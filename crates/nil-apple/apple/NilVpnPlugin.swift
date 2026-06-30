// NilVpnPlugin.swift — the iOS Tauri v2 plugin for NIL VPN. Runs in the CONTAINER-APP process
// (not the packet-tunnel appex), and is the iOS counterpart of the Android `NilVpnPlugin.kt`.
//
// It exposes the same five `nil-vpn` plugin commands the WebView calls
// (prepareVpn / startVpn / statusVpn / stopVpn / openVpnSettings), and drives the REAL attested
// MASQUE tunnel via `NETunnelProviderManager` + the `PacketTunnel` appex
// (`NEPacketTunnelProvider`, see `PacketTunnelProvider.swift`) — never the in-process loopback mock.
//
// Privacy (PD-3): identity NEVER reaches here. `extension_connect` (Rust, app process) already
// redeemed the unlinkable token at the Coordinator; this plugin only receives the attested node
// endpoint + pinned measurement + opaque grant and forwards them to the appex via
// `providerConfiguration`. No account, email, payment, token, or destination crosses into the
// datapath. Nothing identifying is logged (PD-2).
//
// Honest kill-switch (PD-8):
//   * IN-CONNECTION fail-closed — the posture the app CAN set: the protocol's `includeAllNetworks`
//     captures all traffic into the tunnel while connected (the appex also installs the v4+v6
//     default routes and drops IPv6, the engine being IPv4-only). Nothing bypasses the TUN.
//   * PERSISTENT "block when the VPN *process* is down" — this is the OS Always-on / On-Demand
//     system setting. An app CANNOT silently enable it; `openVpnSettings` only deep-links the user
//     there, and the UI must say so. There is deliberately NO `block_without_vpn` argument (an
//     earlier one was hardcoded `true`, never read natively, and implied a control that didn't
//     exist — removed; see `extension.rs` and `DEVICE_VERIFY.md`).

import Foundation
import NetworkExtension
import Tauri
import UIKit
import WebKit

/// The attested start args handed over by `extension_connect` (Rust). Field names are camelCase to
/// match `extension::StartArgs` (`#[serde(rename_all = "camelCase")]`) and are forwarded VERBATIM
/// into the appex's `providerConfiguration`, where `PacketTunnelProvider.swift` reads the same keys.
/// There is no `allowUnattested` field on the real path — its absence means attestation is enforced.
class NilStartArgs: Decodable {
  let nodeHost: String
  let nodePort: Int
  let serverName: String
  let measurementHex: String
  let teeName: String
  let grantHex: String
  let grantNonceHex: String
}

class NilVpnPlugin: Plugin {
  /// The packet-tunnel appex bundle id — a child of the container app id (`com.nilvpn.client`),
  /// matching `PacketTunnel-iOS-Info.plist`'s `CFBundleIdentifier`.
  private static let providerBundleId = "com.nilvpn.client.PacketTunnel"
  /// Settings-facing name of the VPN configuration this plugin manages.
  private static let vpnDescription = "NIL VPN"

  // MARK: - prepareVpn
  // Ensure the VPN configuration exists and OS consent is granted, WITHOUT starting the tunnel — so
  // a token is never redeemed before the user has approved the VPN. iOS has no separate
  // `VpnService.prepare()` (as Android does): the system "VPN Configurations" consent dialog is
  // presented by `saveToPreferences` the first time. We persist a minimal manager (triggering that
  // dialog if needed) and report whether it succeeded.
  @objc public func prepareVpn(_ invoke: Invoke) {
    loadOrCreateManager { manager, error in
      if let error = error {
        invoke.reject("VPN preflight failed: \(error.localizedDescription)")
        return
      }
      guard let manager = manager else {
        invoke.reject("VPN preflight failed: no manager")
        return
      }
      manager.localizedDescription = NilVpnPlugin.vpnDescription
      manager.isEnabled = true
      if manager.protocolConfiguration == nil {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = NilVpnPlugin.providerBundleId
        proto.serverAddress = "NIL"  // display-only placeholder; startVpn sets the real endpoint
        manager.protocolConfiguration = proto
      }
      manager.saveToPreferences { saveError in
        // A save error is, in practice, the user declining the consent dialog — report it as
        // unauthorized (the frontend must not redeem a token) rather than a hard failure.
        invoke.resolve(["authorized": saveError == nil])
      }
    }
  }

  // MARK: - startVpn
  // Configure the manager with the attested args and start the tunnel. Resolves as soon as the start
  // is requested; the tunnel state is asynchronous, so the WebView polls `statusVpn` until "up"
  // (which only happens after the appex passes attestation and applies its network settings).
  @objc public func startVpn(_ invoke: Invoke) {
    let args: NilStartArgs
    do {
      args = try invoke.parseArgs(NilStartArgs.self)
    } catch {
      invoke.reject("invalid startVpn args: \(error.localizedDescription)")
      return
    }
    loadOrCreateManager { manager, error in
      if let error = error {
        invoke.reject("load VPN manager: \(error.localizedDescription)")
        return
      }
      guard let manager = manager else {
        invoke.reject("load VPN manager: none")
        return
      }
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = NilVpnPlugin.providerBundleId
      // `serverAddress` is display-only in Settings — never identity. Use the node host.
      proto.serverAddress = args.nodeHost
      // The keys the appex reads out of `providerConfiguration` (camelCase, matching
      // `PacketTunnelProvider.swift`). `nodePort` fits a u16 but rides as an Int (a JSON number).
      proto.providerConfiguration = [
        "nodeHost": args.nodeHost,
        "nodePort": args.nodePort,
        "serverName": args.serverName,
        "measurementHex": args.measurementHex,
        "teeName": args.teeName,
        "grantHex": args.grantHex,
        "grantNonceHex": args.grantNonceHex,
      ]
      // In-connection fail-closed: route ALL traffic into the tunnel (protocol-level reinforcement of
      // the appex's default routes). The persistent "block when the process is down" guarantee is the
      // OS Always-on setting, which the app cannot set — see `openVpnSettings` (PD-8).
      proto.includeAllNetworks = true
      proto.excludeLocalNetworks = false
      manager.protocolConfiguration = proto
      manager.localizedDescription = NilVpnPlugin.vpnDescription
      manager.isEnabled = true
      // Save → reload (Apple requires a reload to obtain a valid session) → start.
      manager.saveToPreferences { saveError in
        if let saveError = saveError {
          invoke.reject(
            "save VPN preferences (grant the VPN permission, then connect again): \(saveError.localizedDescription)")
          return
        }
        manager.loadFromPreferences { loadError in
          if let loadError = loadError {
            invoke.reject("reload VPN preferences: \(loadError.localizedDescription)")
            return
          }
          do {
            try manager.connection.startVPNTunnel()
            invoke.resolve()
          } catch {
            invoke.reject("start tunnel: \(error.localizedDescription)")
          }
        }
      }
    }
  }

  // MARK: - stopVpn
  // Stop the tunnel. Resolves even if nothing is running (idempotent), mirroring Android.
  @objc public func stopVpn(_ invoke: Invoke) {
    loadOrCreateManager { manager, _ in
      manager?.connection.stopVPNTunnel()
      invoke.resolve()
    }
  }

  // MARK: - statusVpn
  // Map the REAL `NEVPNStatus` to the engine-state vocabulary the WebView expects
  // ("up" | "connecting" | "down"). `.connected` is reported only AFTER the appex calls its
  // `startTunnel` completion handler — which `PacketTunnelProvider.applySettingsAndRead()` does only
  // once attestation has passed — so "up" is a truthful "attested + connected", not optimistic.
  @objc public func statusVpn(_ invoke: Invoke) {
    loadOrCreateManager { manager, _ in
      let state: String
      switch manager?.connection.status {
      case .some(.connected):
        state = "up"
      case .some(.connecting), .some(.reasserting):
        state = "connecting"
      case .some(.disconnecting), .some(.disconnected), .some(.invalid), .none:
        state = "down"
      @unknown default:
        state = "down"
      }
      invoke.resolve(["state": state])
    }
  }

  // MARK: - openVpnSettings
  // Deep-link to OS settings so the user can enable the PERSISTENT kill-switch (Always-on /
  // Connect-On-Demand). iOS has NO public deep-link to Settings ▸ General ▸ VPN (Android has
  // `ACTION_VPN_SETTINGS`), and the private "App-Prefs:" scheme is App-Review-unsafe; the app's own
  // Settings page (`openSettingsURLString`, public + allowed) is the honest target, and the UI must
  // explain that the user enables Always-on there. The app cannot enable it silently (PD-8).
  @objc public func openVpnSettings(_ invoke: Invoke) {
    DispatchQueue.main.async {
      if let url = URL(string: UIApplication.openSettingsURLString) {
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
      }
      invoke.resolve()
    }
  }

  // MARK: - helpers
  /// Load the existing NIL manager (the first `NETunnelProviderManager`) or hand back a fresh one to
  /// configure. NIL manages exactly one VPN configuration.
  private func loadOrCreateManager(_ completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error = error {
        completion(nil, error)
        return
      }
      completion(managers?.first ?? NETunnelProviderManager(), nil)
    }
  }
}

/// Tauri's iOS registration entry point. The Rust side binds this symbol via
/// `tauri::ios_plugin_binding!(init_nil_vpn_plugin)` and hands it to `register_ios_plugin`
/// (see `client/src-tauri/src/lib.rs`). It returns the `Plugin` instance Tauri then manages.
@_cdecl("init_nil_vpn_plugin")
func initNilVpnPlugin() -> Plugin {
  return NilVpnPlugin()
}
