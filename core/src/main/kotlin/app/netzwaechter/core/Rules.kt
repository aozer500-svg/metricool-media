package app.netzwaechter.core

/**
 * @param block true = Anfrage wird mit NXDOMAIN beantwortet
 * @param expectedPkgs Apps, bei denen dieser Dienst normal ist (z.B. Telegram bei api.telegram.org)
 */
class Rule(
    val suffix: String,
    val severity: Severity,
    val kind: Kind,
    val reason: String,
    val block: Boolean = false,
    val expectedPkgs: Set<String> = emptySet(),
)

class RuleSet(rules: Collection<Rule> = emptyList()) {
    private val map = HashMap<String, Rule>().apply { rules.forEach { put(it.suffix.lowercase(), it) } }

    val size get() = map.size

    /** Sucht Regel fuer die Domain oder eine ihrer Eltern-Domains ("x.evil.com" trifft "evil.com"). */
    fun match(domain: String): Rule? {
        val labels = domain.lowercase().trim('.').split('.')
        for (i in labels.indices) {
            map[labels.subList(i, labels.size).joinToString(".")]?.let { return it }
        }
        return null
    }

    operator fun plus(other: RuleSet): RuleSet = RuleSet(map.values + other.map.values)

    companion object {
        /**
         * Liest eine Blockliste: eine Domain pro Zeile oder Hosts-Format ("0.0.0.0 evil.com").
         * '#' beginnt einen Kommentar.
         */
        fun parseBlocklist(text: String, reason: String = "Auf Blockliste"): RuleSet {
            val rules = ArrayList<Rule>()
            for (raw in text.lineSequence()) {
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) continue
                val parts = line.split(Regex("\\s+"))
                val host = if (parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1")) parts[1] else parts[0]
                if (host == "localhost" || !host.contains('.')) continue
                rules += Rule(host.lowercase(), Severity.HIGH, Kind.BLOCKLIST, reason, block = true)
            }
            return RuleSet(rules)
        }
    }
}

/** Beobachtungsliste: Dienste, die gerne zum Abfliessen von Daten missbraucht werden. Kein Blocken. */
object DefaultRules {
    fun watchlist(): RuleSet = RuleSet(
        listOf(
            Rule("api.telegram.org", Severity.MEDIUM, Kind.WATCHLIST,
                "Telegram-Bot-API: wird von Stealern/Stalkerware zum Senden von Daten genutzt",
                expectedPkgs = setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram")),
            Rule("pastebin.com", Severity.LOW, Kind.WATCHLIST, "Paste-Dienst, wird fuer Daten-Ablage und Befehle missbraucht",
                expectedPkgs = setOf("com.android.chrome", "org.mozilla.firefox")),
            Rule("transfer.sh", Severity.MEDIUM, Kind.WATCHLIST, "Anonymer Datei-Upload"),
            Rule("ngrok.io", Severity.MEDIUM, Kind.WATCHLIST, "Tunnel-Dienst (Fernzugriff auf Geraete)"),
            Rule("ngrok-free.app", Severity.MEDIUM, Kind.WATCHLIST, "Tunnel-Dienst (Fernzugriff auf Geraete)"),
            Rule("trycloudflare.com", Severity.MEDIUM, Kind.WATCHLIST, "Anonymer Tunnel-Dienst"),
            Rule("duckdns.org", Severity.LOW, Kind.WATCHLIST, "Dynamisches DNS, oft fuer C2-Server genutzt"),
            Rule("ddns.net", Severity.LOW, Kind.WATCHLIST, "Dynamisches DNS, oft fuer C2-Server genutzt"),
            Rule("hopto.org", Severity.LOW, Kind.WATCHLIST, "Dynamisches DNS, oft fuer C2-Server genutzt"),
            Rule("zapto.org", Severity.LOW, Kind.WATCHLIST, "Dynamisches DNS, oft fuer C2-Server genutzt"),
        ),
    )
}
