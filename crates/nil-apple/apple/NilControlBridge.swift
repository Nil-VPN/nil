// NilControlBridge — app-side (unprivileged) control plane for NIL VPN on macOS.
//
// This is the macOS analog of the iOS Tauri plugin: it lives in the CONTAINER APP (not the
// system extension). It installs/approves the packet-tunnel System Extension, configures a
// NETunnelProviderManager that points at that SE, and starts/stops the tunnel. The privileged
// datapath lives entirely in the SE (PacketTunnelProvider.swift, which links NilApple.xcframework);
// this file links only NetworkExtension + SystemExtensions and never touches the engine FFI.
//
// BUILD / TEST NOTE: like the iOS Swift, this compiles via the Xcode/app-packaging step, NOT via
// cargo. The Rust side calls the @_cdecl exports below through an `extern "C"` block; the symbols
// only exist once this file is compiled into the app bundle and linked against the system
// frameworks. It cannot be built or run in this environment (no Xcode, no dev-mode Mac, no Apple
// developer account / packet-tunnel-provider entitlement), and is therefore UNTESTED. Treat as
// integration scaffolding.
//
// PRIVACY (NIL SOUL): only the node endpoint + pinned measurement + the per-connection grant cross
// into providerConfiguration. No account/email/payment identity is ever placed here. We NEVER log
// the node address, server name, measurement, grant, or nonce (PD-2/PD-3). UX copy is honest about
// what "block all traffic when VPN is down" can and cannot guarantee (PD-8).

import Foundation
import NetworkExtension
import SystemExtensions
import os.log

// MARK: - Shared contract (must match PacketTunnelProvider.swift, entitlements, Info.plist)

private enum NilContract {
    static let appBundleId       = "com.nilvpn.client"
    static let seBundleId        = "com.nilvpn.client.PacketTunnel"   // child of the app id
    static let appGroup          = "group.com.nilvpn.client"
    static let displayName       = "NIL VPN"
}

// Privacy-safe logger: status/lifecycle breadcrumbs only. Endpoint, measurement and grant are
// NEVER passed here — anything that could identify the user or the node stays out of the log.
private let nilLog = Logger(subsystem: NilContract.appBundleId, category: "control-bridge")

// MARK: - Provider configuration (the contract keys the SE reads)

// Decoded from the JSON C-string handed in by Rust (nil_macos_start_tunnel). Field names are the
// JSON keys; they are re-emitted as the providerConfiguration keys the SE expects. Identity-bearing
// fields are intentionally absent — there is nowhere in this struct to put an account or email.
private struct NilProviderConfig: Decodable {
    var nodeHost: String
    var nodePort: Int
    var serverName: String?
    var measurementHex: String
    var tlsSpkiSha256Hex: String
    var transparencyLogKeyHex: String
    var teeName: String?
    var minTcbSevsnp: NilProviderTcbFloor?
    var allowUnattested: Bool?
    var grantHex: String?
    var grantNonceHex: String?

    // Optional UX/posture toggles (not forwarded to the SE as provider keys — they configure the
    // NETunnelProviderManager / NETunnelProviderProtocol itself).
    var onDemand: Bool?           // install an on-demand "connect on any network" rule
    var includeAllNetworks: Bool? // request OS-enforced full-tunnel ("block when down"); see note

    /// Re-serialize into the [String: Any] providerConfiguration dictionary the SE reads in
    /// `startTunnel`. Only the contract keys; nothing else.
    func toProviderConfiguration() -> [String: Any] {
        var dict: [String: Any] = [
            "nodeHost": nodeHost,
            "nodePort": nodePort,
            "serverName": serverName ?? nodeHost,
            "measurementHex": measurementHex,
            "tlsSpkiSha256Hex": tlsSpkiSha256Hex,
            "transparencyLogKeyHex": transparencyLogKeyHex,
            "teeName": teeName ?? "sev-snp",
            "allowUnattested": allowUnattested ?? false,
        ]
        if let g = grantHex, !g.isEmpty { dict["grantHex"] = g }
        if let n = grantNonceHex, !n.isEmpty { dict["grantNonceHex"] = n }
        if let floor = minTcbSevsnp {
            var encoded: [String: Any] = [
                "bootloader": Int(floor.bootloader),
                "tee": Int(floor.tee),
                "snp": Int(floor.snp),
                "microcode": Int(floor.microcode),
            ]
            if let fmc = floor.fmc { encoded["fmc"] = Int(fmc) }
            dict["minTcbSevsnp"] = encoded
        }
        return dict
    }
}

private struct NilProviderTcbFloor: Decodable {
    var fmc: UInt8?
    var bootloader: UInt8
    var tee: UInt8
    var snp: UInt8
    var microcode: UInt8
}

// MARK: - Tunnel status (mirrors the C ABI return of nil_macos_tunnel_status)

// Stable integer mapping returned across the C ABI. Distinct from the engine's NilStatusCb codes;
// this reflects the OS-level NEVPNStatus of the *manager*, which is what the app UI shows.
@objc enum NilTunnelStatus: Int32 {
    case invalid       = 0   // NEVPNStatus.invalid (no manager loaded yet)
    case disconnected  = 1
    case connecting    = 2
    case connected     = 3
    case reasserting   = 4
    case disconnecting = 5
    case unknown       = -1

    init(_ s: NEVPNStatus) {
        switch s {
        case .invalid:       self = .invalid
        case .disconnected:  self = .disconnected
        case .connecting:    self = .connecting
        case .connected:     self = .connected
        case .reasserting:   self = .reasserting
        case .disconnecting: self = .disconnecting
        @unknown default:    self = .unknown
        }
    }
}

// MARK: - Control bridge

/// App-side controller. A single shared instance owns the SE activation request and the VPN
/// manager so the C ABI can be free functions. All NE/SE work is marshalled to the main queue.
final class NilControlBridge: NSObject {

    static let shared = NilControlBridge()

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    // Holds the activation request delegate alive for the duration of the SE request.
    private var activationInFlight = false

    private override init() {
        super.init()
        observeStatus()
    }

    deinit {
        if let o = statusObserver { NotificationCenter.default.removeObserver(o) }
    }

    // MARK: System Extension activation / approval

    /// Activate (install/approve) the packet-tunnel system extension. The OS may surface a one-time
    /// approval in System Settings > General > Login Items & Extensions; the user must allow it
    /// before the SE can run. Idempotent: re-requesting an already-approved SE completes quickly.
    func activateSystemExtension() {
        guard !activationInFlight else {
            nilLog.info("SE activation already in flight; ignoring duplicate request")
            return
        }
        activationInFlight = true
        nilLog.info("requesting SE activation")
        let req = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: NilContract.seBundleId,
            queue: .main
        )
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    // MARK: Manager load / configure / start / stop

    /// Load the existing NIL manager (if any), else create a fresh one, then run `body`.
    private func loadManager(_ body: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                nilLog.error("loadAllFromPreferences failed: \(error.localizedDescription, privacy: .public)")
                body(nil, error)
                return
            }
            // Reuse our manager if present (matched by the SE bundle id we configure below),
            // otherwise start a clean one. We never key on anything user-identifying.
            let existing = managers?.first { m in
                (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == NilContract.seBundleId
            }
            let mgr = existing ?? NETunnelProviderManager()
            self.manager = mgr
            body(mgr, nil)
        }
    }

    /// Configure the manager from the decoded provider config and start the tunnel.
    /// `fileprivate` because `NilProviderConfig` is file-private (called from the @_cdecl entry below).
    fileprivate func startTunnel(_ cfg: NilProviderConfig) {
        loadManager { mgr, error in
            guard let mgr = mgr else { return }

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = NilContract.seBundleId
            // serverAddress is a non-secret display string the OS shows in Settings. We use the node
            // host so the entry is recognizable; this is the same value already inside the SE config,
            // not new identity. (If you consider the entry host sensitive in your threat model, set
            // a generic placeholder here instead.)
            proto.serverAddress = cfg.nodeHost
            proto.providerConfiguration = cfg.toProviderConfiguration()

            // includeAllNetworks: ask the OS to route *all* traffic through the tunnel, including
            // traffic the system would otherwise exempt. HONEST LIMITATION (PD-8): this is the only
            // lever the app has toward "block all traffic when VPN is down", and it is NOT a hard
            // kill-switch by itself. True block-when-down also depends on the on-demand rule below
            // staying enabled and on the user not disabling the VPN config; the app can request these
            // but the OS/user retain final control. Never imply this guarantees zero leakage.
            if cfg.includeAllNetworks == true {
                proto.includeAllNetworks = true
                proto.excludeLocalNetworks = false
            }

            mgr.protocolConfiguration = proto
            mgr.localizedDescription = NilContract.displayName
            mgr.isEnabled = true

            // Optional on-demand: bring the tunnel up automatically on any network. Combined with
            // includeAllNetworks this approximates always-on; alone it just auto-reconnects.
            if cfg.onDemand == true {
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any
                mgr.onDemandRules = [rule]
                mgr.isOnDemandEnabled = true
            } else {
                mgr.isOnDemandEnabled = false
            }

            mgr.saveToPreferences { saveErr in
                if let saveErr = saveErr {
                    nilLog.error("saveToPreferences failed: \(saveErr.localizedDescription, privacy: .public)")
                    return
                }
                // Reload so the saved configuration is consistent before starting (Apple guidance).
                mgr.loadFromPreferences { loadErr in
                    if let loadErr = loadErr {
                        nilLog.error("reload after save failed: \(loadErr.localizedDescription, privacy: .public)")
                        return
                    }
                    do {
                        try mgr.connection.startVPNTunnel()
                        nilLog.info("startVPNTunnel issued")
                    } catch {
                        nilLog.error("startVPNTunnel threw: \(error.localizedDescription, privacy: .public)")
                    }
                }
            }
        }
    }

    /// Stop the tunnel. Disables the on-demand rule first so the OS does not immediately reconnect.
    func stopTunnel() {
        loadManager { mgr, _ in
            guard let mgr = mgr else { return }
            if mgr.isOnDemandEnabled {
                mgr.isOnDemandEnabled = false
                mgr.saveToPreferences { _ in
                    mgr.connection.stopVPNTunnel()
                    nilLog.info("stopVPNTunnel issued (on-demand disabled)")
                }
            } else {
                mgr.connection.stopVPNTunnel()
                nilLog.info("stopVPNTunnel issued")
            }
        }
    }

    /// Current OS-level status of the loaded manager. Returns `.invalid` when nothing is loaded yet.
    func currentStatus() -> NilTunnelStatus {
        guard let conn = manager?.connection else { return .invalid }
        return NilTunnelStatus(conn.status)
    }

    // MARK: Status observation (NEVPNStatusDidChange)

    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let self else { return }
            // Only adopt notifications from our own connection once we have a manager.
            let status: NEVPNStatus
            if let conn = note.object as? NEVPNConnection {
                status = conn.status
            } else {
                status = self.manager?.connection.status ?? .invalid
            }
            // Status is non-identifying; safe to log at this granularity.
            nilLog.info("VPN status changed: \(NilTunnelStatus(status).rawValue, privacy: .public)")
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension NilControlBridge: OSSystemExtensionRequestDelegate {

    /// The OS is asking the user to approve the extension (System Settings). Not an error — the app
    /// UI should tell the user to allow NIL VPN in Login Items & Extensions.
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        nilLog.info("SE needs user approval (System Settings > Login Items & Extensions)")
    }

    /// A version of the SE is already present. Decide whether to replace it. We always allow
    /// replacing with the same or a newer version, and we also replace an OLDER installed copy with
    /// the one bundled in this app (the app bundle is the source of truth after an update).
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        nilLog.info("SE replace: existing v\(existing.bundleShortVersion, privacy: .public) -> bundled v\(ext.bundleShortVersion, privacy: .public)")
        return .replace
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        activationInFlight = false
        switch result {
        case .completed:
            nilLog.info("SE activation completed")
        case .willCompleteAfterReboot:
            nilLog.info("SE activation will complete after reboot")
        @unknown default:
            nilLog.info("SE activation finished with unknown result \(result.rawValue, privacy: .public)")
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        activationInFlight = false
        nilLog.error("SE activation failed: \(error.localizedDescription, privacy: .public)")
    }
}

// MARK: - C ABI for the Rust side
//
// The Rust engine/host calls these via an `extern "C"` block. Signatures (mirror exactly in Rust):
//
//   // Install/approve the packet-tunnel system extension (may prompt the user in System Settings).
//   // Non-blocking; progress/result is reported via os_log and reflected by nil_macos_tunnel_status.
//   void   nil_macos_activate_se(void);
//
//   // Start the tunnel. `config_json` is a NUL-terminated UTF-8 JSON object with the provider keys:
//   //   { "nodeHost": str, "nodePort": int, "serverName": str?, "measurementHex": str,
//   //     "tlsSpkiSha256Hex": str,
//   //     "transparencyLogKeyHex": str,
//   //     "teeName": str?, "minTcbSevsnp": { "fmc": int?, "bootloader": int,
//   //       "tee": int, "snp": int, "microcode": int }?,
//   //     "allowUnattested": bool?, "grantHex": str?, "grantNonceHex": str?,
//   //     "onDemand": bool?, "includeAllNetworks": bool? }
//   // Returns 0 on accepted (config parsed + start issued asynchronously), -1 on a parse/encoding
//   // error. The pointer is borrowed for the duration of the call only; Rust still owns/frees it.
//   int32_t nil_macos_start_tunnel(const char *config_json);
//
//   // Stop the tunnel (and disable any on-demand rule). Non-blocking.
//   void   nil_macos_stop_tunnel(void);
//
//   // Current OS-level VPN status of the loaded manager:
//   //   0=invalid/none, 1=disconnected, 2=connecting, 3=connected,
//   //   4=reasserting, 5=disconnecting, -1=unknown.
//   int32_t nil_macos_tunnel_status(void);
//
// Matching Rust extern block:
//
//   extern "C" {
//       fn nil_macos_activate_se();
//       fn nil_macos_start_tunnel(config_json: *const std::os::raw::c_char) -> i32;
//       fn nil_macos_stop_tunnel();
//       fn nil_macos_tunnel_status() -> i32;
//   }

@_cdecl("nil_macos_activate_se")
public func nil_macos_activate_se() {
    DispatchQueue.main.async {
        NilControlBridge.shared.activateSystemExtension()
    }
}

@_cdecl("nil_macos_start_tunnel")
public func nil_macos_start_tunnel(_ configJson: UnsafePointer<CChar>) -> Int32 {
    // Copy out of the borrowed C string immediately; do not retain the pointer.
    let json = String(cString: configJson)
    guard let data = json.data(using: .utf8) else {
        nilLog.error("start: config_json was not valid UTF-8")
        return -1
    }
    let cfg: NilProviderConfig
    do {
        cfg = try JSONDecoder().decode(NilProviderConfig.self, from: data)
    } catch {
        // Do NOT log the JSON body — it carries the measurement and grant. Log only that decoding
        // failed (PD-2).
        nilLog.error("start: config_json decode failed")
        return -1
    }
    DispatchQueue.main.async {
        NilControlBridge.shared.startTunnel(cfg)
    }
    return 0
}

@_cdecl("nil_macos_stop_tunnel")
public func nil_macos_stop_tunnel() {
    DispatchQueue.main.async {
        NilControlBridge.shared.stopTunnel()
    }
}

@_cdecl("nil_macos_tunnel_status")
public func nil_macos_tunnel_status() -> Int32 {
    // Status read is cheap and thread-safe enough to answer synchronously from the cached manager.
    NilControlBridge.shared.currentStatus().rawValue
}
