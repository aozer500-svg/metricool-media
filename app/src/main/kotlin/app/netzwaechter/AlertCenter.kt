package app.netzwaechter

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.SharedPreferences
import androidx.core.app.NotificationCompat
import app.netzwaechter.core.Alert
import app.netzwaechter.core.Kind
import app.netzwaechter.core.Severity
import org.json.JSONArray
import org.json.JSONObject

/** Zentrale Ablage fuer Warnungen und DNS-Protokoll. Warnungen bleiben gespeichert (letzte 200). */
object AlertCenter {
    private const val CHANNEL = "alerts"
    private const val MAX_ALERTS = 200
    private const val MAX_LOG = 150

    private lateinit var appCtx: Context
    private lateinit var prefs: SharedPreferences
    private val alerts = ArrayDeque<Alert>()
    private val log = ArrayDeque<String>()
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    private var notifId = 1000
    private var initialized = false

    @Synchronized
    fun init(context: Context) {
        if (initialized) return
        appCtx = context.applicationContext
        prefs = appCtx.getSharedPreferences("alerts", Context.MODE_PRIVATE)
        load()
        val nm = appCtx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Sicherheitswarnungen", NotificationManager.IMPORTANCE_HIGH))
        initialized = true
    }

    fun addListener(l: () -> Unit) { listeners += l }
    fun removeListener(l: () -> Unit) { listeners -= l }

    @Synchronized fun snapshotAlerts(): List<Alert> = alerts.toList()
    @Synchronized fun snapshotLog(): List<String> = log.toList()

    fun raise(a: Alert) {
        synchronized(this) {
            alerts.addFirst(a)
            while (alerts.size > MAX_ALERTS) alerts.removeLast()
            save()
        }
        if (a.severity != Severity.LOW) notify(a)
        listeners.forEach { it() }
    }

    fun logDns(time: Long, pkg: String, domain: String, note: String = "") {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.GERMANY).format(java.util.Date(time))
        synchronized(this) {
            log.addFirst("$t  ${shortPkg(pkg)}  $domain$note")
            while (log.size > MAX_LOG) log.removeLast()
        }
        listeners.forEach { it() }
    }

    @Synchronized
    fun clear() { alerts.clear(); save(); listeners.forEach { it() } }

    private fun shortPkg(p: String) = if (p.length > 28) "…" + p.takeLast(27) else p

    private fun notify(a: Alert) {
        val nm = appCtx.getSystemService(NotificationManager::class.java)
        val open = android.app.PendingIntent.getActivity(
            appCtx, 0, android.content.Intent(appCtx, MainActivity::class.java),
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(appCtx, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(a.title)
            .setContentText(a.detail)
            .setStyle(NotificationCompat.BigTextStyle().bigText(a.detail))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try { nm.notify(notifId++, n) } catch (_: SecurityException) { /* Benachrichtigungen nicht erlaubt */ }
    }

    private fun save() {
        val arr = JSONArray()
        alerts.forEach {
            arr.put(JSONObject().put("t", it.timeMs).put("s", it.severity.name).put("k", it.kind.name)
                .put("p", it.pkg).put("ti", it.title).put("d", it.detail))
        }
        prefs.edit().putString("list", arr.toString()).apply()
    }

    private fun load() {
        try {
            val arr = JSONArray(prefs.getString("list", "[]"))
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                alerts.addLast(Alert(o.getLong("t"), Severity.valueOf(o.getString("s")), Kind.valueOf(o.getString("k")),
                    o.getString("p"), o.getString("ti"), o.getString("d")))
            }
        } catch (_: Exception) { alerts.clear() }
    }
}
