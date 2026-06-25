package com.nilvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * The `:vpn` process. Configures the TUN via VpnService.Builder (routes/DNS/MTU set here at
 * establish() time — that IS the kill-switch + leak protection on Android), hands the detached fd
 * to the Rust engine (which protect()s its own QUIC socket via the callback), and runs as a
 * foreground service. No account/identity ever reaches this process — only a node endpoint.
 */
class NilVpnService : VpnService() {
    private var handle: Long = 0
    private var pfd: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand flags=$flags startId=$startId hasIntent=${intent != null}")
        val nodeHost = intent?.getStringExtra("nodeHost") ?: run {
            Log.e(TAG, "no nodeHost extra — abort"); return START_NOT_STICKY
        }
        val nodePort = intent.getIntExtra("nodePort", 443)
        val serverName = intent.getStringExtra("serverName") ?: nodeHost
        val measurement = intent.getStringExtra("measurementHex") ?: ""
        val grant = intent.getStringExtra("grantHex") ?: ""
        val grantNonce = intent.getStringExtra("grantNonceHex") ?: ""
        val allowUnattested = intent.getBooleanExtra("allowUnattested", false)
        val teeName = intent.getStringExtra("teeName") ?: "sev-snp"
        // SOUL §3 / PD-2: the node address (host/port/SNI) is a "destination" and MUST NOT reach
        // logcat (readable via adb / READ_LOGS apps / crash reporters) — it would link user→node→time.
        // The grant/nonce are a bearer credential + freshness nonce; log only lengths, never values.
        Log.i(TAG, "extras measLen=${measurement.length} tee=$teeName grantLen=${grant.length} allowUnattested=$allowUnattested")

        try {
            startForeground(NOTIF_ID, notification())
            Log.i(TAG, "startForeground OK")
        } catch (e: Throwable) {
            Log.e(TAG, "startForeground failed", e); stopSelf(); return START_NOT_STICKY
        }

        // Diagnostic: is this app authorized as the VPN? prepare() returns null when authorized,
        // or a consent Intent when not (only an Activity can launch that). This line pinpoints
        // whether a failure is the consent gate vs. the Builder/establish step.
        val consent = VpnService.prepare(this)
        Log.i(TAG, "VpnService.prepare -> ${if (consent == null) "AUTHORIZED(null)" else "NOT-AUTHORIZED(consent needed)"}")

        val tun = try {
            Builder()
                .setSession("NIL VPN")
                .setMtu(MTU)
                .addAddress("10.74.0.2", 24)
                .addRoute("0.0.0.0", 0)        // route all IPv4 through the tunnel (fail-closed)
                // IPv6 leak fix (Epic 9): the Rust engine is IPv4-only, so give the TUN a ULA v6
                // address + a v6 default route. All IPv6 is then captured into the TUN and DROPPED by
                // the engine — preventing the device's ISP-assigned IPv6 from leaking AROUND the
                // tunnel. (Honest tradeoff: IPv6 connectivity is disabled while connected.)
                .addAddress("fd00:6e69:6c00::2", 64)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .setBlocking(true)
                .establish()
        } catch (e: Throwable) {
            Log.e(TAG, "establish() threw", e); null
        }
        if (tun == null) {
            Log.e(TAG, "establish() returned null (not authorized / no consent) — stopping")
            stopSelf(); return START_NOT_STICKY
        }
        Log.i(TAG, "establish() OK")
        pfd = tun

        // detachFd transfers ownership to the Rust engine (it closes it on stop).
        val fd = tun.detachFd()
        Log.i(TAG, "detachFd=$fd — calling nativeStart")
        handle = try {
            NilNative.nativeStart(fd, nodeHost, nodePort, MTU, serverName, measurement, teeName, grant, grantNonce, allowUnattested, this)
        } catch (e: Throwable) {
            Log.e(TAG, "nativeStart threw", e); 0L
        }
        Log.i(TAG, "nativeStart -> handle=$handle")
        if (handle == 0L) {
            Log.e(TAG, "nativeStart failed (handle=0) — stopping")
            stopSelf(); return START_NOT_STICKY
        }
        Log.i(TAG, "TUNNEL UP handle=$handle")
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy handle=$handle")
        if (handle != 0L) { NilNative.nativeStop(handle); handle = 0 }
        pfd?.close(); pfd = null
        super.onDestroy()
    }

    private fun notification(): Notification {
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CHAN, "NIL VPN", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, CHAN)
            .setContentTitle("NIL VPN")
            .setContentText("Connected through an attested node")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "NilVpn"
        private const val NOTIF_ID = 1
        private const val CHAN = "nil_vpn"
        private const val MTU = 1280   // conservative; fits the MASQUE single-hop usable MTU
    }
}
