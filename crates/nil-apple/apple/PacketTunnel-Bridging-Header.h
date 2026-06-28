// NIL VPN SE bridging header — exposes the nil-apple C FFI (nil_start / nil_ingest_packets
// / nil_negotiated_mtu / nil_stop and the NilConfig/NilWriteCb/NilStatusCb types) to
// PacketTunnelProvider.swift. The header ships inside NilApple.xcframework's Headers/,
// which the cargo build-phase packs from crates/nil-apple/include/nil_apple.h.
//
// Integration scaffolding: cannot be compiled here (no Xcode / xcframework on this host).
#import <nil_apple.h>
