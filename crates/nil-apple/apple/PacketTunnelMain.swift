// macOS System Extension entry point.
//
// Unlike the iOS app extension — which the OS instantiates via the Info.plist
// NSExtensionPrincipalClass and therefore needs no `main` — a macOS NetworkExtension *system
// extension* is a standalone executable and must start the provider machinery itself. Apple's
// documented entry point is `NEProvider.startSystemExtensionMode()`, which reads the bundle's
// `NetworkExtension > NEProviderClasses` map (see PacketTunnel-Info.plist) to instantiate
// `PacketTunnelProvider` when the OS activates the tunnel.
//
// macOS-only: this file is NOT part of the iOS appex target (which uses the principal class).
import Foundation
import NetworkExtension

@main
enum PacketTunnelSystemExtension {
    static func main() {
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }
        dispatchMain()
    }
}
