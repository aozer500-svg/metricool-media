package app.netzwaechter

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Startet den Schutz nach dem Neustart, sofern der VPN-Zugriff schon einmal erteilt wurde. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val wanted = context.getSharedPreferences("settings", Context.MODE_PRIVATE).getBoolean("guard_enabled", false)
        if (wanted && VpnService.prepare(context) == null) GuardVpnService.start(context)
    }
}
