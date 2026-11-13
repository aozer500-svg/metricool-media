package app.netzwaechter.core

import kotlin.math.sqrt

class AnalyzerConfig(
    val cooldownMs: Long = 30 * 60_000L,
    val tunnelWindowMs: Long = 5 * 60_000L,
    val tunnelMinDistinct: Int = 30,
    val tunnelMinAvgLabel: Int = 20,
    val beaconMinHits: Int = 8,
    val beaconMinIntervalMs: Long = 5_000L,
    val beaconMaxIntervalMs: Long = 30 * 60_000L,
    val beaconMaxJitter: Double = 0.10,
)

/** Wertet DNS-Anfragen pro App aus. Nicht thread-sicher nach aussen, aber intern synchronisiert. */
class TrafficAnalyzer(
    private val rules: RuleSet,
    private val cfg: AnalyzerConfig = AnalyzerConfig(),
    private val ignoredPkgs: Set<String> = emptySet(),
) {
    private val lastAlert = HashMap<String, Long>()
    private val tunnelSeen = HashMap<String, ArrayDeque<Pair<Long, String>>>()
    private val beaconTimes = HashMap<String, ArrayDeque<Long>>()

    @Synchronized
    fun onDns(e: DnsEvent): DnsVerdict {
        val out = ArrayList<Alert>()
        var block = false
        val domain = e.domain

        rules.match(domain)?.let { r ->
            if (e.pkg !in r.expectedPkgs) {
                if (r.block) block = true
                if (shouldAlert("${r.kind}|${e.pkg}|${r.suffix}", e.timeMs)) {
                    out += Alert(
                        e.timeMs, r.severity, r.kind, e.pkg,
                        "${r.kind.label}: ${r.suffix}",
                        "${e.pkg} hat $domain aufgeloest. ${r.reason}." + if (r.block) " Anfrage wurde blockiert." else "",
                    )
                }
            }
        }

        if (e.pkg !in ignoredPkgs) {
            if (DomainHeuristics.looksGenerated(domain) &&
                shouldAlert("GEN|${e.pkg}|${DomainHeuristics.baseDomain(domain)}", e.timeMs)
            ) {
                out += Alert(
                    e.timeMs, Severity.MEDIUM, Kind.GENERATED_DOMAIN, e.pkg,
                    "Zufaellig aussehende Domain",
                    "${e.pkg} fragt $domain ab. Malware erzeugt solche Namen automatisch, um Servern auszuweichen.",
                )
            }
            checkTunnel(e)?.let { out += it }
            checkBeacon(e)?.let { out += it }
        }
        return DnsVerdict(out, block)
    }

    private fun checkTunnel(e: DnsEvent): Alert? {
        val base = DomainHeuristics.baseDomain(e.domain)
        val sub = DomainHeuristics.subdomainPart(e.domain)
        val oversized = DomainHeuristics.hasOversizedLabel(e.domain)
        val key = "${e.pkg}|$base"
        val q = tunnelSeen.getOrPut(key) { ArrayDeque() }
        if (sub.isNotEmpty()) q.addLast(e.timeMs to sub)
        while (q.isNotEmpty() && e.timeMs - q.first().first > cfg.tunnelWindowMs) q.removeFirst()
        val distinct = q.map { it.second }.toSet()
        val avgLen = if (distinct.isEmpty()) 0.0 else distinct.sumOf { it.length }.toDouble() / distinct.size
        val tunnel = distinct.size >= cfg.tunnelMinDistinct && avgLen >= cfg.tunnelMinAvgLabel
        if (!tunnel && !oversized) return null
        if (!shouldAlert("TUN|${e.pkg}|$base", e.timeMs)) return null
        return Alert(
            e.timeMs, if (tunnel) Severity.HIGH else Severity.MEDIUM, Kind.DNS_TUNNEL, e.pkg,
            "Moeglicher DNS-Tunnel zu $base",
            if (tunnel) "${e.pkg} schickte ${distinct.size} verschiedene lange Subdomains zu $base in 5 Minuten - so lassen sich Daten ueber DNS herausschmuggeln."
            else "${e.pkg} fragte einen ungewoehnlich langen Domainnamen ab: ${e.domain.take(80)}",
        )
    }

    private fun checkBeacon(e: DnsEvent): Alert? {
        if (e.qtype != DnsCodec.TYPE_A && e.qtype != DnsCodec.TYPE_AAAA) return null
        val key = "${e.pkg}|${e.domain}"
        val q = beaconTimes.getOrPut(key) { ArrayDeque() }
        if (q.isNotEmpty() && e.timeMs - q.last() < 1000) return null // doppelte A/AAAA-Anfragen zusammenfassen
        q.addLast(e.timeMs)
        while (q.size > 12) q.removeFirst()
        if (q.size < cfg.beaconMinHits) return null
        val intervals = q.zipWithNext { a, b -> (b - a).toDouble() }
        val mean = intervals.average()
        if (mean < cfg.beaconMinIntervalMs || mean > cfg.beaconMaxIntervalMs) return null
        val sd = sqrt(intervals.sumOf { (it - mean) * (it - mean) } / intervals.size)
        if (sd / mean > cfg.beaconMaxJitter) return null
        if (!shouldAlert("BEA|$key", e.timeMs)) return null
        return Alert(
            e.timeMs, Severity.LOW, Kind.BEACON, e.pkg,
            "Regelmaessige Verbindung zu ${e.domain}",
            "${e.pkg} meldet sich etwa alle ${(mean / 1000).toLong()} Sekunden sehr gleichmaessig bei ${e.domain}. Das kann harmlos sein (Push, Sync) oder ein Malware-Beacon.",
        )
    }

    private fun shouldAlert(key: String, now: Long): Boolean {
        val last = lastAlert[key]
        if (last != null && now - last < cfg.cooldownMs) return false
        lastAlert[key] = now
        return true
    }
}

/** Upload-Menge einer App seit der letzten Messung. */
class VolumeSample(
    val uid: Int,
    val pkg: String,
    val txBytes: Long,
    val rxBytes: Long,
    val screenOn: Boolean,
)

class VolumeConfig(
    val screenOffTxBytes: Long = 5L * 1024 * 1024,
    val largeTxBytes: Long = 100L * 1024 * 1024,
    val skewedMinTxBytes: Long = 10L * 1024 * 1024,
    val skewedRatio: Double = 3.0,
    val cooldownMs: Long = 60 * 60_000L,
)

class VolumeAnalyzer(
    private val cfg: VolumeConfig = VolumeConfig(),
    private val ignoredPkgs: Set<String> = emptySet(),
) {
    private val lastAlert = HashMap<String, Long>()

    @Synchronized
    fun analyze(samples: List<VolumeSample>, nowMs: Long): List<Alert> {
        val out = ArrayList<Alert>()
        for (s in samples) {
            if (s.pkg in ignoredPkgs || s.txBytes <= 0) continue
            val kind: Kind
            val severity: Severity
            val text: String
            when {
                !s.screenOn && s.txBytes >= cfg.screenOffTxBytes -> {
                    kind = Kind.UPLOAD_SCREEN_OFF; severity = Severity.MEDIUM
                    text = "${s.pkg} hat bei ausgeschaltetem Bildschirm ${mb(s.txBytes)} gesendet."
                }
                s.txBytes >= cfg.largeTxBytes -> {
                    kind = Kind.UPLOAD_LARGE; severity = Severity.MEDIUM
                    text = "${s.pkg} hat seit der letzten Pruefung ${mb(s.txBytes)} gesendet."
                }
                s.txBytes >= cfg.skewedMinTxBytes && s.txBytes > cfg.skewedRatio * (s.rxBytes + 1) -> {
                    kind = Kind.UPLOAD_SKEWED; severity = Severity.MEDIUM
                    text = "${s.pkg} sendet ${mb(s.txBytes)} und empfaengt nur ${mb(s.rxBytes)} - ungewoehnlich viel Upload."
                }
                else -> continue
            }
            val key = "${kind}|${s.pkg}"
            val last = lastAlert[key]
            if (last != null && nowMs - last < cfg.cooldownMs) continue
            lastAlert[key] = nowMs
            out += Alert(nowMs, severity, kind, s.pkg, kind.label, text + " Cloud-Backup/Foto-Sync ist normal, unbekannte Apps nicht.")
        }
        return out
    }

    private fun mb(b: Long) = "%.1f MB".format(java.util.Locale.ROOT, b / 1048576.0)
}
