package app.netzwaechter

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat

class AppFinding(val pkg: String, val label: String, val score: Int, val reasons: List<String>)

/**
 * Sucht nach installierten Apps mit typischen Spyware-/Stalkerware-Merkmalen:
 * Bedienungshilfen, Geraeteadmin, Benachrichtigungszugriff, Bildschirmaufnahme-Berechtigung,
 * SMS/Anrufe, kein Startsymbol, Installation ausserhalb des Play Stores.
 * Ein Treffer ist ein Hinweis, kein Beweis - viele legitime Apps (z.B. Passwortmanager) haben solche Rechte.
 */
object AppScanner {
    fun scan(ctx: Context): List<AppFinding> {
        val pm = ctx.packageManager
        val accessibility = enabledAccessibilityPackages(ctx)
        val admins = (ctx.getSystemService(DevicePolicyManager::class.java).activeAdmins ?: emptyList()).map { it.packageName }.toSet()
        val listeners = NotificationManagerCompat.getEnabledListenerPackages(ctx)
        val out = ArrayList<AppFinding>()

        for (pi in installedPackages(pm)) {
            val ai = pi.applicationInfo ?: continue
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem || pi.packageName == ctx.packageName) continue
            val perms = pi.requestedPermissions?.toSet() ?: emptySet()
            var score = 0
            val why = ArrayList<String>()
            fun add(points: Int, text: String) { score += points; why += text }

            if (pi.packageName in accessibility) add(3, "Bedienungshilfen-Dienst aktiv (kann Bildschirminhalt und Eingaben lesen)")
            if (pi.packageName in admins) add(3, "Geräteadministrator (schwer zu deinstallieren)")
            if (pi.packageName in listeners) add(2, "Darf alle Benachrichtigungen mitlesen")
            if ("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION" in perms) add(2, "Darf Bildschirm aufnehmen/übertragen")
            if ("android.permission.SYSTEM_ALERT_WINDOW" in perms) add(1, "Darf über anderen Apps einblenden")
            if ("android.permission.READ_SMS" in perms || "android.permission.RECEIVE_SMS" in perms) add(1, "Liest SMS")
            if ("android.permission.READ_CALL_LOG" in perms) add(1, "Liest Anrufliste")
            if ("android.permission.RECORD_AUDIO" in perms && "android.permission.ACCESS_FINE_LOCATION" in perms &&
                "android.permission.READ_CONTACTS" in perms) add(1, "Mikrofon + Standort + Kontakte")
            if ("android.permission.REQUEST_INSTALL_PACKAGES" in perms) add(1, "Darf weitere Apps installieren")
            if (pm.getLaunchIntentForPackage(pi.packageName) == null) add(3, "Kein Startsymbol (versteckte App)")
            if (installer(pm, pi.packageName) != "com.android.vending") add(1, "Nicht aus dem Play Store installiert")

            if (score >= 4) {
                out += AppFinding(pi.packageName, pm.getApplicationLabel(ai).toString(), score, why)
            }
        }
        return out.sortedByDescending { it.score }
    }

    @Suppress("DEPRECATION")
    private fun installedPackages(pm: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

    @Suppress("DEPRECATION")
    private fun installer(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName else pm.getInstallerPackageName(pkg)
    } catch (_: Exception) { null }

    private fun enabledAccessibilityPackages(ctx: Context): Set<String> {
        val s = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return emptySet()
        return s.split(':').filter { it.contains('/') }.map { it.substringBefore('/') }.toSet()
    }
}
