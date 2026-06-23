package com.nilvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

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
        val nodeHost = intent?.getStringExtra("nodeHost") ?: return START_NOT_STICKY
        val nodePort = intent.getIntExtra("nodePort", 443)
        val serverName = intent.getStringExtra("serverName") ?: nodeHost
        val measurement = intent.getStringExtra("measurementHex") ?: ""
        val allowUnattested = intent.getBooleanExtra("allowUnattested", false)

        startForeground(NOTIF_ID, notification())

        val tun = Builder()
            .setSession("NIL VPN")
            .setMtu(MTU)
            .addAddress("10.74.0.2", 24)
            .addRoute("0.0.0.0", 0)        // route everything through the tunnel (fail-closed)
            .addDnsServer("1.1.1.1")
            .setBlocking(true)
            .establish() ?: run { stopSelf(); return START_NOT_STICKY }
        pfd = tun

        // detachFd transfers ownership to the Rust engine (it closes it on stop).
        handle = NilNative.nativeStart(
            tun.detachFd(), nodeHost, nodePort, MTU, serverName, measurement, allowUnattested, this,
        )
        if (handle == 0L) { stopSelf(); return START_NOT_STICKY }
        return START_STICKY
    }

    override fun onDestroy() {
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
        private const val NOTIF_ID = 1
        private const val CHAN = "nil_vpn"
        private const val MTU = 1280   // conservative; fits the MASQUE single-hop usable MTU
    }
}
