// NIL VPN host/dev wrapper — minimal installer/driver for the System Extension.
//
// Purpose: exercise the one-time SE activation (OSSystemExtensionRequest.activationRequest)
// and then configure + start/stop the tunnel through NETunnelProviderManager so the SE
// integration can be tested without the full Tauri client. Approving the extension is a
// one-time user step in System Settings > General > Login Items & Extensions.
//
// NOTE: integration scaffolding only. Cannot be built or run in this environment (no Xcode,
// no Apple Developer org with the packet-tunnel-provider entitlement, no signing). The
// shipping client is the Tauri app; this wrapper is for SE bring-up.
//
// PRIVACY (NIL SOUL): providerConfiguration carries ONLY the node endpoint + pinned
// measurement + per-connection grant — never identity. Never log node address, token,
// grant, or measurement. The Always-on / "block traffic when VPN is down" behavior is the
// OS includeAllNetworks setting the app can request but cannot silently force — copy must
// stay honest about that. No "100% anonymous" / "untraceable" claims.

import AppKit
import NetworkExtension
import SystemExtensions

private let seBundleID = "com.nilvpn.client.PacketTunnel"

final class SEActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // User must approve once in System Settings > General > Login Items & Extensions.
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { configureAndStartTunnel() }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        // Do not log error details that could include identifying context.
        NSApp.terminate(nil)
    }
}

private let activationDelegate = SEActivationDelegate()

func activateSystemExtension() {
    let req = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: seBundleID,
                                                         queue: .main)
    req.delegate = activationDelegate
    OSSystemExtensionManager.shared.submitRequest(req)
}

func configureAndStartTunnel() {
    NETunnelProviderManager.loadAllFromPreferences { managers, _ in
        let mgr = managers?.first ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = seBundleID
        // serverAddress is a required, non-identifying display field for the OS UI.
        proto.serverAddress = "NIL VPN"
        // Only node endpoint + measurement + grant cross into the SE. No identity.
        // These placeholders are filled by the real client after token redemption.
        proto.providerConfiguration = [
            "nodeHost": "",            // node endpoint (filled at connect time)
            "nodePort": 443,
            "serverName": "",
            "measurementHex": "",      // pinned TEE measurement
            "teeName": "sev-snp",
            "allowUnattested": false,
            "grantHex": "",            // per-connection Privacy Pass grant (redeemed in client)
            "grantNonceHex": "",
        ]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "NIL VPN"
        mgr.isEnabled = true
        mgr.saveToPreferences { _ in
            mgr.loadFromPreferences { _ in
                try? mgr.connection.startVPNTunnel()
            }
        }
    }
}

// Observe status transitions for bring-up visibility (no identifying values logged).
NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { _ in }

let app = NSApplication.shared
activateSystemExtension()
app.run()
