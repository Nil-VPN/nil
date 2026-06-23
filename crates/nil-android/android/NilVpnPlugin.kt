package com.nilvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

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
            putExtra("allowUnattested", a.allowUnattested)
        }
        activity.startForegroundService(i)
        invoke.resolve()
    }

    @Command
    fun stopVPN(invoke: Invoke) {
        activity.stopService(Intent(activity, NilVpnService::class.java))
        invoke.resolve()
    }

    companion object { private const val VPN_CONSENT = 0x1107 }

    class StartArgs {
        lateinit var nodeHost: String
        var nodePort: Int = 443
        var serverName: String? = null
        var measurementHex: String? = null
        var teeName: String? = null
        var allowUnattested: Boolean = false
    }
}
