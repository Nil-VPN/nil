package com.nilvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

/**
 * The `:vpn` process. Configures the TUN via VpnService.Builder (routes/DNS/MTU set here at
 * establish() time — that IS the kill-switch + leak protection on Android), hands the detached fd
 * to the Rust engine (which protect()s its own QUIC socket via the callback), and runs as a
 * foreground service. No account/identity ever reaches this process — only a node endpoint.
 *
 * Honest status: the notification + a status file (read by the app process via NilVpnPlugin) reflect
 * the engine's REAL health (Connecting → Connected only after the attestation gate passes; → "lost"
 * when a pump dies). The TUN's full-route capture means a dead tunnel still blackholes (fail-closed),
 * but we never keep claiming "connected" once traffic has stopped flowing.
 */
class NilVpnService : VpnService() {
    private var handle: Long = 0
    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var running = false
    // Set the instant teardown begins. Once true, the poll thread stops writing status, so the
    // authoritative terminal "down" can't be clobbered by a late "dead"/"up" from an in-flight poll.
    @Volatile private var stopping = false
    // Guards teardown() against running twice (ACTION_STOP path → stopSelf → onDestroy both call it).
    @Volatile private var torndown = false
    private var poller: Thread? = null
    private var lastState: String = ""

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Disconnect path. `stopService` does NOT destroy a foreground VpnService (the system binds it
        // while the TUN fd is open), so the app sends an explicit STOP command instead: we tear the
        // tunnel down from inside (closing the fd unbinds the system), drop the foreground state, and
        // stopSelf — which finally triggers onDestroy. Without this, Disconnect left a zombie FGS with
        // a dead tunnel and the status stuck at "dead" (onDestroy never ran to write "down").
        if (intent?.action == ACTION_STOP) {
            Log.i(TAG, "ACTION_STOP — tearing down")
            teardown()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        return onStart(intent, flags, startId)
    }

    private fun onStart(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand flags=$flags startId=$startId hasIntent=${intent != null}")
        val nodeHost = intent?.getStringExtra("nodeHost") ?: run {
            Log.e(TAG, "no nodeHost extra — abort"); writeStatus(DOWN); return START_NOT_STICKY
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
            // Not "Connected" yet — the attestation gate hasn't run. Claiming it here would be the
            // optimistic-status lie this whole channel exists to avoid.
            startForeground(NOTIF_ID, notification("Connecting…"))
            writeStatus(CONNECTING)
            Log.i(TAG, "startForeground OK")
        } catch (e: Throwable) {
            Log.e(TAG, "startForeground failed", e); writeStatus(DOWN); stopSelf(); return START_NOT_STICKY
        }

        // Diagnostic: is this app authorized as the VPN? prepare() returns null when authorized,
        // or a consent Intent when not (only an Activity can launch that). This line pinpoints
        // whether a failure is the consent gate vs. the Builder/establish step.
        val consent = VpnService.prepare(this)
        Log.i(TAG, "VpnService.prepare -> ${if (consent == null) "AUTHORIZED(null)" else "NOT-AUTHORIZED(consent needed)"}")

        // Kill-switch (in-session): capturing the full default route below sends ALL traffic into
        // the TUN, and the Rust engine blackholes the TUN if the tunnel drops — so traffic fails
        // closed while connected, unconditionally (there is no per-connection toggle). setBlocking
        // is the fd's I/O mode, NOT the kill-switch. The PERSISTENT guarantee (block when this VPN
        // process is down) is the OS "Always-on VPN / Block connections without VPN" system setting,
        // which the app can deep-link the user to but cannot enable on its own.
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
            writeStatus(DOWN); stopSelf(); return START_NOT_STICKY
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
            // nativeStart returns 0 on any connect/attestation failure — the gate held, no traffic.
            Log.e(TAG, "nativeStart failed (handle=0) — stopping")
            writeStatus(DOWN); stopSelf(); return START_NOT_STICKY
        }
        Log.i(TAG, "TUNNEL UP handle=$handle")
        // A non-zero handle means the MASQUE handshake + attestation gate passed — only NOW is it
        // honest to report "connected". Then poll the engine's real health and keep it truthful.
        writeStatus(UP); lastState = UP
        updateNotification("Connected through an attested node")
        startPolling()
        return START_STICKY
    }

    /**
     * Poll the engine's REAL health and reflect it honestly. A dead tunnel (a pump exited:
     * hang/transport drop/TUN error) keeps the full-route TUN held so traffic stays blackholed
     * (fail-closed), but we stop claiming "connected" — DEAD is surfaced to the app (status file)
     * and the notification, instead of an optimistic lie. The app decides whether to reconnect.
     */
    private fun startPolling() {
        running = true
        poller = Thread {
            while (running) {
                val state = engineState()
                if (!stopping && state != lastState) {
                    lastState = state
                    writeStatus(state)
                    when (state) {
                        DEAD -> updateNotification("Connection lost — traffic is blocked")
                        UP -> updateNotification("Connected through an attested node")
                    }
                }
                try { Thread.sleep(POLL_MS) } catch (e: InterruptedException) { break }
            }
        }.apply { isDaemon = true; name = "nil-vpn-status"; start() }
    }

    /** Parse the engine's nativeStatus JSON (`{"state":"up|dead|down"}`) into a bare state word. */
    private fun engineState(): String {
        val h = handle
        if (h == 0L) return DOWN
        return try {
            val json = NilNative.nativeStatus(h)
            STATE_RE.find(json)?.groupValues?.get(1) ?: DEAD
        } catch (e: Throwable) {
            Log.e(TAG, "nativeStatus threw", e); DEAD
        }
    }

    /**
     * Atomically publish the tunnel state to the app (WebView) process. Both processes share this
     * app's private `filesDir`, so a temp-write + rename is a simple, dependency-free cross-process
     * channel — no bound service / AIDL. NilVpnPlugin.statusVPN reads it. Carries only a state word,
     * never any node/identity data (PD-2).
     */
    private fun writeStatus(state: String) {
        try {
            val tmp = File(filesDir, "$STATUS_FILE.tmp")
            tmp.writeText(state)
            if (!tmp.renameTo(File(filesDir, STATUS_FILE))) {
                File(filesDir, STATUS_FILE).writeText(state) // fallback if rename is unavailable
            }
        } catch (e: Throwable) {
            Log.e(TAG, "writeStatus failed", e)
        }
    }

    /**
     * Idempotent teardown — safe to call from ACTION_STOP, onRevoke, and onDestroy. Stops the poller
     * and JOINs it before freeing the engine (nativeStatus borrows the engine pointer, so nativeStop
     * must not free it under an in-flight poll — use-after-free). Writes the terminal "down" AFTER the
     * join (nothing overwrites it) and BEFORE the potentially-slow nativeStop (rt.block_on(down())),
     * so the status is correct even if the process is killed mid-teardown.
     */
    private fun teardown() {
        if (torndown) return
        torndown = true
        stopping = true
        running = false
        poller?.interrupt()
        try { poller?.join(1000) } catch (e: InterruptedException) { /* ignore */ }
        poller = null
        writeStatus(DOWN)
        if (handle != 0L) {
            try { NilNative.nativeStop(handle) } catch (e: Throwable) { Log.e(TAG, "nativeStop failed", e) }
            handle = 0
        }
        try { pfd?.close() } catch (e: Throwable) { /* ignore */ }
        pfd = null
    }

    override fun onRevoke() {
        // The OS revoked the VPN (user disabled it in Settings, or another VPN took over).
        Log.i(TAG, "onRevoke — tearing down")
        teardown()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy handle=$handle")
        teardown()
        super.onDestroy()
    }

    private fun ensureChannel() {
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CHAN, "NIL VPN", NotificationManager.IMPORTANCE_LOW))
    }

    private fun notification(text: String): Notification {
        ensureChannel()
        return Notification.Builder(this, CHAN)
            .setContentTitle("NIL VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
        } catch (e: Throwable) {
            Log.e(TAG, "updateNotification failed", e)
        }
    }

    companion object {
        private const val TAG = "NilVpn"
        private const val NOTIF_ID = 1
        private const val CHAN = "nil_vpn"
        private const val MTU = 1280   // conservative; fits the MASQUE single-hop usable MTU
        private const val POLL_MS = 2000L
        private val STATE_RE = Regex("\"state\"\\s*:\\s*\"(\\w+)\"")
        /** Status file in the app's private filesDir — the app↔:vpn status channel. */
        const val STATUS_FILE = "nil_vpn_status"
        const val CONNECTING = "connecting"
        const val UP = "up"
        const val DEAD = "dead"
        const val DOWN = "down"
        /** Intent action the app sends (via startService) to cleanly stop the foreground VpnService. */
        const val ACTION_STOP = "com.nilvpn.action.STOP"
    }
}
