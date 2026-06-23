package com.nilvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log

/**
 * Thin, invisible launcher that performs the Android VPN consent handshake before starting
 * NilVpnService. VpnService.prepare() returns a consent Intent the first time an app wants to be
 * the system VPN; only an Activity can launch it. We launch it, wait for RESULT_OK, then start the
 * foreground service. This is the production-correct entry point (the app's Connect action routes
 * here) and the headless e2e harness drives it too (auto-approving the system dialog). It forwards
 * only a node endpoint — never any account/identity.
 */
class VpnConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val consent = VpnService.prepare(this)
        if (consent != null) {
            Log.i(TAG, "consent required — launching system VPN dialog")
            startActivityForResult(consent, REQ)
        } else {
            Log.i(TAG, "already authorized (prepare==null) — starting service")
            startServiceAndFinish()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.i(TAG, "consent result requestCode=$requestCode resultCode=$resultCode (OK=$RESULT_OK)")
        if (requestCode == REQ && resultCode == RESULT_OK) {
            startServiceAndFinish()
        } else {
            Log.e(TAG, "consent denied — not starting the tunnel")
            finish()
        }
    }

    private fun startServiceAndFinish() {
        val svc = Intent(this, NilVpnService::class.java).apply {
            putExtra("nodeHost", intent.getStringExtra("nodeHost"))
            putExtra("nodePort", intent.getIntExtra("nodePort", 443))
            putExtra("serverName", intent.getStringExtra("serverName"))
            putExtra("measurementHex", intent.getStringExtra("measurementHex"))
            putExtra("teeName", intent.getStringExtra("teeName"))
            // Forward the Coordinator grant so the consent-flow entry point starts the SAME attested,
            // granted tunnel as the plugin path (never an ungranted one).
            putExtra("grantHex", intent.getStringExtra("grantHex"))
            putExtra("grantNonceHex", intent.getStringExtra("grantNonceHex"))
            putExtra("allowUnattested", intent.getBooleanExtra("allowUnattested", false))
        }
        startForegroundService(svc)
        Log.i(TAG, "startForegroundService(NilVpnService) dispatched")
        finish()
    }

    companion object {
        private const val TAG = "NilVpn"
        private const val REQ = 0x4E494C   // "NIL"
    }
}
