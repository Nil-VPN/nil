package com.nilvpn

/**
 * JNI bridge to `libnil_android.so` (the Rust MASQUE engine in this crate).
 * Method names/signatures must match the `Java_com_nilvpn_NilNative_*` exports in src/lib.rs.
 */
object NilNative {
    init { System.loadLibrary("nil_android") }

    /** Start the tunnel over the VpnService TUN fd. Returns an opaque handle (0 = failure). */
    external fun nativeStart(
        tunFd: Int,
        nodeHost: String,
        nodePort: Int,
        mtu: Int,
        serverName: String,
        measurementHex: String,   // "" when allowUnattested
        allowUnattested: Boolean,
        vpnService: android.net.VpnService,  // engine calls .protect(fd) on this
    ): Long

    external fun nativeStop(handle: Long)
    external fun nativeStatus(handle: Long): String   // JSON {"state":"up|down"}
}
