// Reference NEPacketTunnelProvider for NIL VPN iOS. Drives the C-ABI engine in this crate
// (nil_start / nil_ingest_packets / nil_negotiated_mtu / nil_stop from nil_ios.h, imported via the
// extension's bridging header). The container app redeems the unlinkable token and passes ONLY the
// node endpoint + pinned measurement in providerConfiguration — no identity reaches the extension.
//
// NOTE: this is integration reference code. It cannot run in the Simulator (packet tunnels are
// device-only) and needs the `packet-tunnel-provider` entitlement (Apple org approval) — see
// README. Harden the readPackets pointer lifetimes before shipping.

import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: OpaquePointer?
    private var startCompletion: ((Error?) -> Void)?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let cfg = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let host = (cfg["nodeHost"] as? String) ?? ""
        let port = UInt16((cfg["nodePort"] as? Int) ?? 443)
        let sni = (cfg["serverName"] as? String) ?? host
        let measurement = (cfg["measurementHex"] as? String) ?? ""
        let teeName = (cfg["teeName"] as? String) ?? "sev-snp"
        let allow = (cfg["allowUnattested"] as? Bool) ?? false
        startCompletion = completionHandler

        let writeCb: NilWriteCb = { ctx, pkt, len, af in
            let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx!).takeUnretainedValue()
            let proto = NSNumber(value: af == 30 ? AF_INET6 : AF_INET)
            me.packetFlow.writePackets([Data(bytes: pkt!, count: len)], withProtocols: [proto])
        }
        let statusCb: NilStatusCb = { ctx, state, _ in
            let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx!).takeUnretainedValue()
            if state == 1 { me.applySettingsAndRead() }      // connected
            if state == 2 { me.startCompletion?(NEVPNError(.connectionFailed)); me.startCompletion = nil }
        }

        let ctx = Unmanaged.passUnretained(self).toOpaque()
        host.withCString { hp in sni.withCString { sp in measurement.withCString { mp in teeName.withCString { tp in
            var c = NilConfig(node_host: hp, node_port: port, server_name: sp, measurement_hex: mp, tee_name: tp, allow_unattested: allow)
            tunnel = nil_start(&c, ctx, writeCb, statusCb)
        }}}}
        if tunnel == nil { completionHandler(NEVPNError(.configurationInvalid)); startCompletion = nil }
    }

    private func applySettingsAndRead() {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.74.0.1")
        s.ipv4Settings = NEIPv4Settings(addresses: ["10.74.0.2"], subnetMasks: ["255.255.255.0"])
        s.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        // IPv6 leak fix (Epic 9): the engine is IPv4-only, so capture all IPv6 into the tunnel with a
        // ULA address + a v6 default route. v6 packets entering the engine are dropped, preventing the
        // device's ISP-assigned IPv6 from leaking around the tunnel. (IPv6 is disabled while connected.)
        s.ipv6Settings = NEIPv6Settings(addresses: ["fd00:6e69:6c00::2"], networkPrefixLengths: [64])
        s.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        s.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        let mtu = nil_negotiated_mtu(tunnel)
        s.mtu = NSNumber(value: mtu == 0 ? 1280 : Int(mtu))
        setTunnelNetworkSettings(s) { [weak self] err in
            self?.startCompletion?(err); self?.startCompletion = nil
            if err == nil { self?.readLoop() }
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] datas, _ in
            guard let self, let t = self.tunnel else { return }
            for d in datas {
                d.withUnsafeBytes { raw in
                    var p = raw.bindMemory(to: UInt8.self).baseAddress
                    var len = d.count
                    var af: Int32 = 0
                    nil_ingest_packets(t, &p, &len, &af, 1)   // engine copies synchronously
                }
            }
            self.readLoop()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if let t = tunnel { nil_stop(t); tunnel = nil }
        completionHandler()
    }
}
