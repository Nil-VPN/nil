package com.nilvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

/**
 * Tauri plugin bridging the WebView (app process) to the `:vpn` service. The app process redeems
 * the unlinkable token at the Coordinator and passes ONLY the resulting node endpoint + pinned
 * measurement here — no identity crosses into `:vpn`. `startVPN` triggers the OS VPN-consent
 * dialog (VpnService.prepare) the first time, then starts the foreground service.
 */
@TauriPlugin
class NilVpnPlugin(private val activity: Activity) : Plugin(activity) {

    @Command
    fun startVPN(invoke: Invoke) {
        // OS consent: returns an Intent the first time; null once granted.
        VpnService.prepare(activity)?.let {
            activity.startActivityForResult(it, VPN_CONSENT)
            invoke.reject("VPN permission required; approve the system dialog and start again")
            return
        }
        val a = invoke.parseArgs(StartArgs::class.java)
        val i = Intent(activity, NilVpnService::class.java).apply {
            putExtra("nodeHost", a.nodeHost)
            putExtra("nodePort", a.nodePort)
            putExtra("serverName", a.serverName ?: a.nodeHost)
            putExtra("measurementHex", a.measurementHex ?: "")
            putExtra("teeName", a.teeName ?: "sev-snp")
            // Coordinator grant for this hop (redeemed in the app process); "" if the path carries none.
            putExtra("grantHex", a.grantHex ?: "")
            putExtra("grantNonceHex", a.grantNonceHex ?: "")
            putExtra("allowUnattested", a.allowUnattested)
        }
        // Publish "connecting" synchronously BEFORE dispatching the service, so a status poll can't
        // read a stale "down"/"up" from a previous session in the gap before the service writes.
        try {
            File(activity.filesDir, NilVpnService.STATUS_FILE).writeText(NilVpnService.CONNECTING)
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
    fun prepareVPN(invoke: Invoke) {
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
    fun stopVPN(invoke: Invoke) {
        activity.stopService(Intent(activity, NilVpnService::class.java))
        invoke.resolve()
    }

    /**
     * Report the `:vpn` service's REAL tunnel state to the WebView: `{state: connecting|up|dead|down}`.
     * The service (a separate process) writes its health to a file in this app's shared `filesDir`;
     * we read it here. This lets the UI report "connected" only after the attestation gate actually
     * passes (state==up), and surface a dropped tunnel (dead) instead of an optimistic lie. Defaults
     * to "down" when no status has been published yet. Carries only a state word — no node/identity.
     */
    @Command
    fun statusVPN(invoke: Invoke) {
        val state = try {
            File(activity.filesDir, NilVpnService.STATUS_FILE).readText().trim().ifEmpty { "down" }
        } catch (e: Throwable) {
            "down"
        }
        invoke.resolve(JSObject().apply { put("state", state) })
    }

    companion object { private const val VPN_CONSENT = 0x1107 }

    class StartArgs {
        lateinit var nodeHost: String
        var nodePort: Int = 443
        var serverName: String? = null
        var measurementHex: String? = null
        var teeName: String? = null
        var grantHex: String? = null
        var grantNonceHex: String? = null
        var allowUnattested: Boolean = false
    }
}
