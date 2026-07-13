package com.nilvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException

/**
 * Private Rust-to-native bridge for the `:vpn` service. Rust retains the Tauri PluginHandle and the
 * WebView has no plugin ACL, so bearer start arguments never cross JavaScript. The app process
 * redeems the blind-signed token and passes only the resulting node policy + grant here.
 */
@TauriPlugin
class NilVpnPlugin(private val activity: Activity) : Plugin(activity) {

    @Command
    fun startVpn(invoke: Invoke) {
        // OS consent: returns an Intent the first time; null once granted.
        VpnService.prepare(activity)?.let {
            activity.startActivityForResult(it, VPN_CONSENT)
            invoke.reject("VPN permission required; approve the system dialog and start again")
            return
        }
        val a = invoke.parseArgs(StartArgs::class.java)
        if (!a.reservationId.matches(Regex("[0-9a-f]{64}"))) {
            invoke.reject("invalid reservation id")
            return
        }
        val i = Intent(activity, NilVpnService::class.java).apply {
            putExtra("nodeHost", a.nodeHost)
            putExtra("nodePort", a.nodePort)
            putExtra("serverName", a.serverName ?: a.nodeHost)
            putExtra("measurementHex", a.measurementHex ?: "")
            putExtra("tlsSpkiSha256Hex", a.tlsSpkiSha256Hex ?: "")
            putExtra("transparencyLogKeyHex", a.transparencyLogKeyHex ?: "")
            putExtra("teeName", a.teeName ?: "sev-snp")
            val minTcb = a.minTcbSevsnp
            putExtra("minTcbPresent", minTcb != null)
            putExtra("minTcbFmc", minTcb?.fmc ?: -1)
            putExtra("minTcbBootloader", minTcb?.bootloader ?: 0)
            putExtra("minTcbTee", minTcb?.tee ?: 0)
            putExtra("minTcbSnp", minTcb?.snp ?: 0)
            putExtra("minTcbMicrocode", minTcb?.microcode ?: 0)
            // Coordinator grant for this hop (redeemed in the app process); "" if the path carries none.
            putExtra("grantHex", a.grantHex ?: "")
            putExtra("grantNonceHex", a.grantNonceHex ?: "")
            putExtra("reservationId", a.reservationId)
            putExtra("allowUnattested", a.allowUnattested)
        }
        // Publish "connecting" synchronously BEFORE dispatching the service, so a status poll can't
        // read a stale "down"/"up" from a previous session in the gap before the service writes.
        try {
            File(activity.filesDir, NilVpnService.STATUS_FILE)
                .writeText("${NilVpnService.CONNECTING}|${a.reservationId}|${SystemClock.elapsedRealtime()}")
        } catch (_: Throwable) { /* best-effort; the service writes it again on start */ }
        activity.startForegroundService(i)
        invoke.resolve()
    }

    /**
     * Preflight the OS VPN consent WITHOUT starting anything, so the app can obtain permission
     * BEFORE it redeems a single-use token. `{authorized:true}` means prepare() returned null
     * (already granted) — the caller may redeem + startVPN. `{authorized:false}` means consent was
     * required: we launch the system dialog and the caller must NOT redeem (it would burn a token on
     * a permission the user may still deny); the user approves, then taps Connect again.
     */
    @Command
    fun prepareVpn(invoke: Invoke) {
        val consent = VpnService.prepare(activity)
        if (consent == null) {
            invoke.resolve(JSObject().apply { put("authorized", true) })
        } else {
            activity.startActivityForResult(consent, VPN_CONSENT)
            invoke.resolve(JSObject().apply { put("authorized", false) })
        }
    }

    /**
     * Deep-link to the OS VPN settings so the user can turn on "Always-on VPN" + "Block connections
     * without VPN" — the PERSISTENT kill-switch. The app CANNOT enable this itself (PD-8 honesty);
     * all it can do is take the user there. Falls back to app details if the VPN settings screen is
     * unavailable on this device/OEM.
     */
    @Command
    fun openVpnSettings(invoke: Invoke) {
        try {
            activity.startActivity(
                Intent(android.provider.Settings.ACTION_VPN_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } catch (e: Throwable) {
            activity.startActivity(
                Intent(android.provider.Settings.ACTION_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
        invoke.resolve()
    }

    @Command
    fun stopVpn(invoke: Invoke) {
        // stopService does NOT destroy a foreground VpnService (the system binds it while the TUN fd
        // is open), so deliver an explicit STOP command instead — the service tears the tunnel down
        // from inside (closing the fd unbinds the system) and stopSelf()s. startService just routes
        // the action to the already-running service's onStartCommand.
        activity.startService(Intent(activity, NilVpnService::class.java).setAction(NilVpnService.ACTION_STOP))
        invoke.resolve()
    }

    /**
     * Report the `:vpn` service's fresh tunnel state to the private Rust plugin handle:
     * `{state: connecting|up|dead|down, reservationId?: ...}`.
     * The service (a separate process) writes its health to a file in this app's shared `filesDir`;
     * we read it here. This lets the UI report "connected" only after the attestation gate actually
     * passes (state==up), and surface a dropped/stale tunnel (dead) instead of an optimistic lie.
     * Defaults to "down" when no status has been published. The random local reservation id binds
     * completion but carries no node, token, account, payment, or identity data.
     */
    @Command
    fun statusVpn(invoke: Invoke) {
        val raw = try {
            File(activity.filesDir, NilVpnService.STATUS_FILE).readText().trim()
        } catch (e: Throwable) {
            ""
        }
        val fields = raw.split('|', limit = 4)
        val recordedState = fields.getOrNull(0)?.ifEmpty { NilVpnService.DOWN }
            ?: NilVpnService.DOWN
        val reservationId = fields.getOrNull(1)?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
        val writtenAt = fields.getOrNull(2)?.toLongOrNull()
        val recordedIncarnation = fields.getOrNull(3)
            ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
        val now = SystemClock.elapsedRealtime()
        val fresh = writtenAt != null && writtenAt <= now && now - writtenAt <= STATUS_MAX_AGE_MS
        val liveIncarnation = liveVpnServiceIncarnation()
        val sameLiveService = liveIncarnation != null && liveIncarnation == recordedIncarnation
        val recognized = recordedState in setOf(
            NilVpnService.CONNECTING,
            NilVpnService.UP,
            NilVpnService.DEAD,
            NilVpnService.DOWN,
        )
        // An old `up` record proves nothing after the service/process has died. Return `dead` so
        // Rust keeps the pending pass and tears down/retries instead of acknowledging a ghost VPN.
        val state = when {
            !recognized -> NilVpnService.DOWN
            recordedState == NilVpnService.DOWN -> NilVpnService.DOWN
            !fresh -> NilVpnService.DEAD
            // The app publishes a short connecting transition immediately before dispatching the
            // service. It never authorizes token completion, so it may precede lease acquisition.
            recordedState == NilVpnService.CONNECTING -> NilVpnService.CONNECTING
            sameLiveService -> recordedState
            else -> NilVpnService.DEAD
        }
        invoke.resolve(JSObject().apply {
            put("state", state)
            if (fresh && reservationId != null && (sameLiveService || state == NilVpnService.CONNECTING)) {
                put("reservationId", reservationId)
            }
        })
    }

    /**
     * Test the separate `:vpn` process's exclusive lease without trusting ActivityManager caches.
     * Linux releases this lock immediately on process death. The random value stored under that
     * lock binds a status record to the exact process incarnation that wrote it.
     */
    private fun liveVpnServiceIncarnation(): String? {
        var leaseFile: RandomAccessFile? = null
        return try {
            leaseFile = RandomAccessFile(File(activity.filesDir, NilVpnService.STATUS_LEASE_FILE), "rw")
            val candidate = leaseFile.channel.tryLock()
            if (candidate == null) {
                leaseFile.seek(0)
                leaseFile.readLine()?.trim()?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
            } else {
                candidate.release()
                null
            }
        } catch (_: OverlappingFileLockException) {
            try {
                leaseFile?.seek(0)
                leaseFile?.readLine()?.trim()?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
            } catch (_: Throwable) {
                null
            }
        } catch (_: Throwable) {
            null
        } finally {
            try { leaseFile?.close() } catch (_: Throwable) { /* fail-closed result already chosen */ }
        }
    }

    companion object {
        private const val VPN_CONSENT = 0x1107
        // Longer than the frontend's 20-second connection deadline, but short enough that an app
        // restart cannot mistake a long-dead service for a live tunnel.
        private const val STATUS_MAX_AGE_MS = 30_000L
    }

    class StartArgs {
        lateinit var reservationId: String
        lateinit var nodeHost: String
        var nodePort: Int = 443
        var serverName: String? = null
        var measurementHex: String? = null
        var tlsSpkiSha256Hex: String? = null
        var transparencyLogKeyHex: String? = null
        var teeName: String? = null
        var minTcbSevsnp: SevSnpTcbFloor? = null
        var grantHex: String? = null
        var grantNonceHex: String? = null
        var allowUnattested: Boolean = false
    }

    class SevSnpTcbFloor {
        var fmc: Int? = null
        var bootloader: Int = 0
        var tee: Int = 0
        var snp: Int = 0
        var microcode: Int = 0
    }
}
