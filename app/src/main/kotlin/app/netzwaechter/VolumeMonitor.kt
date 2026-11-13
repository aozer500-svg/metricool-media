package app.netzwaechter

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import app.netzwaechter.core.VolumeSample

/**
 * Misst pro App, wie viel seit der letzten Messung gesendet wurde (NetworkStatsManager).
 * Braucht den "Nutzungszugriff". Die Messung ist grob (Android fasst Daten in Zeitfenstern zusammen),
 * reicht aber, um auffaellige Uploads zu erkennen.
 */
class VolumeMonitor(private val ctx: Context) {
    private val nsm = ctx.getSystemService(NetworkStatsManager::class.java)
    private val pm = ctx.packageManager
    private var last: Map<Int, LongArray>? = null // uid -> [tx, rx] seit Boot

    fun hasAccess(): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    /** Liefert die Differenz seit dem letzten Aufruf. Beim ersten Aufruf nur Basiswerte merken. */
    fun sample(): List<VolumeSample> {
        if (!hasAccess()) return emptyList()
        val now = System.currentTimeMillis()
        val bootTime = now - SystemClock.elapsedRealtime()
        val totals = HashMap<Int, LongArray>()
        for (type in intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            try {
                val stats = nsm.querySummary(type, null, bootTime, now + 60_000)
                val b = NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(b)
                    val t = totals.getOrPut(b.uid) { LongArray(2) }
                    t[0] += b.txBytes; t[1] += b.rxBytes
                }
                stats.close()
            } catch (_: Exception) { /* z.B. Mobilfunk nicht vorhanden */ }
        }
        val prev = last
        last = totals
        if (prev == null) return emptyList()

        val screenOn = ctx.getSystemService(PowerManager::class.java).isInteractive
        val out = ArrayList<VolumeSample>()
        for ((uid, t) in totals) {
            if (uid == Process.myUid() || uid < Process.FIRST_APPLICATION_UID) continue
            val p = prev[uid] ?: continue
            val tx = t[0] - p[0]; val rx = t[1] - p[1]
            if (tx <= 0) continue
            val pkg = pm.getPackagesForUid(uid)?.firstOrNull() ?: "uid:$uid"
            out += VolumeSample(uid, pkg, tx, maxOf(rx, 0), screenOn)
        }
        return out
    }
}
