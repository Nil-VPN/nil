// Reference NEPacketTunnelProvider for NIL VPN (iOS app extension + macOS system extension — same
// provider). Drives the C-ABI engine in this crate (nil_start / nil_ingest_packets /
// nil_assigned_ipv4 / nil_negotiated_mtu / nil_stop from nil_apple.h, imported via the extension's bridging header). The
// container app redeems the blind-signed bearer token and passes ONLY the node endpoint + pinned measurement
// + the per-connection grant (token + freshness nonce) in providerConfiguration — no identity reaches
// the extension.
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
        let tlsSpkiSha256 = (cfg["tlsSpkiSha256Hex"] as? String) ?? ""
        let transparencyLogKey = (cfg["transparencyLogKeyHex"] as? String) ?? ""
        let teeName = (cfg["teeName"] as? String) ?? "sev-snp"
        let allow = (cfg["allowUnattested"] as? Bool) ?? false
        let floorConfig = cfg["minTcbSevsnp"] as? [String: Any]
        var nativeFloor = NilSevSnpTcbFloor(
            fmc: -1, bootloader: 0, tee: 0, snp: 0, microcode: 0)
        if let floor = floorConfig {
            func component(_ name: String) -> UInt8? {
                guard let value = floor[name] as? Int, (0...255).contains(value) else { return nil }
                return UInt8(value)
            }
            guard let bootloader = component("bootloader"),
                  let tee = component("tee"),
                  let snp = component("snp"),
                  let microcode = component("microcode") else {
                completionHandler(NEVPNError(.configurationInvalid))
                return
            }
            var fmc: Int16 = -1
            if floor.keys.contains("fmc") {
                guard let value = component("fmc") else {
                    completionHandler(NEVPNError(.configurationInvalid))
                    return
                }
                fmc = Int16(value)
            }
            nativeFloor = NilSevSnpTcbFloor(
                fmc: fmc, bootloader: bootloader, tee: tee, snp: snp, microcode: microcode)
        }
        // Per-connection Privacy Pass grant (redeemed in the container app), passed as hex. Empty when
        // unauthenticated; the engine falls back to a fresh random freshness nonce.
        let grantHex = (cfg["grantHex"] as? String) ?? ""
        let grantNonceHex = (cfg["grantNonceHex"] as? String) ?? ""
        startCompletion = completionHandler

        let writeCb: NilWriteCb = { ctx, pkt, len, af in
            let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx!).takeUnretainedValue()
            let proto = NSNumber(value: af == 30 ? AF_INET6 : AF_INET)
            me.packetFlow.writePackets([Data(bytes: pkt!, count: Int(len))], withProtocols: [proto])
        }
        let statusCb: NilStatusCb = { ctx, state, _ in
            let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx!).takeUnretainedValue()
            if state == 1 { me.applySettingsAndRead() }      // connected
            if state == 2 { me.startCompletion?(NEVPNError(.connectionFailed)); me.startCompletion = nil }
        }

        let ctx = Unmanaged.passUnretained(self).toOpaque()
        host.withCString { hp in sni.withCString { sp in measurement.withCString { mp in tlsSpkiSha256.withCString { tsp in transparencyLogKey.withCString { lkp in teeName.withCString { tp in grantHex.withCString { gp in grantNonceHex.withCString { np in
            var c = NilConfig(node_host: hp, node_port: port, server_name: sp, measurement_hex: mp, tls_spki_sha256_hex: tsp, transparency_log_key_hex: lkp, tee_name: tp, allow_unattested: allow, has_min_tcb_sevsnp: floorConfig != nil, min_tcb_sevsnp: nativeFloor, grant_hex: gp, grant_nonce_hex: np)
            tunnel = nil_start(&c, ctx, writeCb, statusCb)
        }}}}}}}}
        if tunnel == nil { completionHandler(NEVPNError(.configurationInvalid)); startCompletion = nil }
    }

    private func applySettingsAndRead() {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.74.0.1")
        let assigned = nil_assigned_ipv4(tunnel)
        let clientAddress = assigned == 0
            ? "10.74.0.2"
            : "\((assigned >> 24) & 0xff).\((assigned >> 16) & 0xff).\((assigned >> 8) & 0xff).\(assigned & 0xff)"
        s.ipv4Settings = NEIPv4Settings(addresses: [clientAddress], subnetMasks: ["255.255.255.0"])
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
                    var len = UInt(d.count)   // FFI lens is *const usize → UInt
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
