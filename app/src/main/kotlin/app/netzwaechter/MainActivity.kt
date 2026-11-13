package app.netzwaechter

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import app.netzwaechter.core.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private companion object { const val REQ_VPN = 1; const val REQ_NOTIF = 2 }

    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var usageBtn: Button
    private lateinit var alertsBox: LinearLayout
    private lateinit var appsBox: LinearLayout
    private lateinit var logView: TextView
    private val listener: () -> Unit = { runOnUiThread { refresh() } }
    private lateinit var volume: VolumeMonitor

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AlertCenter.init(this)
        volume = VolumeMonitor(this)
        buildUi()
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
    }

    override fun onResume() {
        super.onResume()
        AlertCenter.addListener(listener)
        refresh()
    }

    override fun onPause() {
        AlertCenter.removeListener(listener)
        super.onPause()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun text(s: String, size: Float = 14f, bold: Boolean = false, color: Int = Color.parseColor("#222222")) =
        TextView(this).apply {
            text = s; textSize = size; setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(4), 0, dp(4))
        }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(24), dp(16), dp(16))
        }
        root.addView(text("Netzwächter", 26f, true))
        status = text("", 16f, true)
        root.addView(status)

        toggle = Button(this).apply { setOnClickListener { onToggle() } }
        root.addView(toggle)
        usageBtn = Button(this).apply {
            text = "Datenmengen-Überwachung erlauben (Nutzungszugriff)"
            setOnClickListener { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }
        }
        root.addView(usageBtn)
        root.addView(Button(this).apply {
            text = "Systemeinstellung: Dauerhaftes VPN"
            setOnClickListener { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
        })

        root.addView(text("Warnungen", 18f, true))
        alertsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(alertsBox)
        root.addView(Button(this).apply { text = "Warnungen löschen"; setOnClickListener { AlertCenter.clear() } })

        root.addView(text("Verdächtige Apps", 18f, true))
        appsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(appsBox)
        root.addView(Button(this).apply { text = "Installierte Apps prüfen"; setOnClickListener { scanApps() } })

        root.addView(text("DNS-Protokoll (letzte Anfragen)", 18f, true))
        logView = text("", 12f).apply { typeface = Typeface.MONOSPACE }
        root.addView(logView)

        root.addView(text(
            "Hinweis: Der Netzwächter sieht, welche App welche Domain anfragt und wie viel Daten sie sendet. " +
                "Verschlüsselte Inhalte (z. B. ein Screenshot) kann er nicht lesen, nur auffälliges Verhalten melden. " +
                "Apps mit eigenem DNS (DNS-over-HTTPS) oder fest eingebauten IP-Adressen umgehen die DNS-Prüfung.",
            12f, color = Color.GRAY))
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun onToggle() {
        val prefs = getSharedPreferences("settings", Context.MODE_PRIVATE)
        if (GuardVpnService.running) {
            prefs.edit().putBoolean("guard_enabled", false).apply()
            GuardVpnService.stop(this)
            toggle.postDelayed({ refresh() }, 500)
        } else {
            val i = VpnService.prepare(this)
            if (i != null) startActivityForResult(i, REQ_VPN) else startGuard()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startGuard()
    }

    private fun startGuard() {
        getSharedPreferences("settings", Context.MODE_PRIVATE).edit().putBoolean("guard_enabled", true).apply()
        GuardVpnService.start(this)
        toggle.postDelayed({ refresh() }, 800)
    }

    private fun scanApps() {
        appsBox.removeAllViews()
        appsBox.addView(text("Prüfe …"))
        Thread {
            val found = AppScanner.scan(this)
            runOnUiThread {
                appsBox.removeAllViews()
                if (found.isEmpty()) appsBox.addView(text("Keine auffälligen Apps gefunden.", color = Color.parseColor("#2E7D32")))
                for (f in found) {
                    val color = if (f.score >= 6) Color.parseColor("#C62828") else Color.parseColor("#EF6C00")
                    appsBox.addView(text("${f.label}  (Risiko ${f.score})", 15f, true, color))
                    appsBox.addView(text(f.pkg + "\n• " + f.reasons.joinToString("\n• "), 12f))
                    appsBox.addView(Button(this).apply {
                        text = "App-Info öffnen"
                        setOnClickListener {
                            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                                .setData(android.net.Uri.parse("package:${f.pkg}")))
                        }
                    })
                }
            }
        }.start()
    }

    private fun refresh() {
        val on = GuardVpnService.running
        status.text = if (on) "● Schutz aktiv" else "○ Schutz aus"
        status.setTextColor(if (on) Color.parseColor("#2E7D32") else Color.parseColor("#C62828"))
        toggle.text = if (on) "Schutz beenden" else "Schutz starten"
        usageBtn.visibility = if (volume.hasAccess()) View.GONE else View.VISIBLE

        alertsBox.removeAllViews()
        val alerts = AlertCenter.snapshotAlerts()
        if (alerts.isEmpty()) alertsBox.addView(text("Keine Warnungen.", color = Color.GRAY))
        val fmt = SimpleDateFormat("dd.MM. HH:mm", Locale.GERMANY)
        for (a in alerts.take(30)) {
            val c = when (a.severity) {
                Severity.HIGH -> Color.parseColor("#C62828")
                Severity.MEDIUM -> Color.parseColor("#EF6C00")
                Severity.LOW -> Color.GRAY
            }
            alertsBox.addView(text("${fmt.format(Date(a.timeMs))}  ${a.title}", 15f, true, c))
            alertsBox.addView(text(a.detail, 12f))
        }
        logView.text = AlertCenter.snapshotLog().take(60).joinToString("\n")
    }
}
