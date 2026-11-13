package app.netzwaechter.core

import kotlin.math.ln

object DomainHeuristics {
    private val SECOND_LEVEL = setOf("co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go")

    /** "a.b.example.co.uk" -> "example.co.uk" */
    fun baseDomain(host: String): String {
        val labels = host.trim('.').split('.')
        if (labels.size <= 2) return labels.joinToString(".")
        val last = labels[labels.size - 1]
        val prev = labels[labels.size - 2]
        val take = if (last.length == 2 && prev in SECOND_LEVEL) 3 else 2
        return labels.takeLast(take).joinToString(".")
    }

    /** Teil vor dem Base-Domain-Suffix, z.B. "a.b" bei "a.b.example.com". */
    fun subdomainPart(host: String): String {
        val base = baseDomain(host)
        val h = host.trim('.')
        return if (h.length > base.length) h.removeSuffix(base).trimEnd('.') else ""
    }

    /** Name vor der TLD, z.B. "example" bei "www.example.com". */
    fun secondLevelLabel(host: String): String {
        val base = baseDomain(host).split('.')
        return if (base.size >= 2) base[0] else host
    }

    fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = s.groupingBy { it }.eachCount()
        return -counts.values.sumOf { c ->
            val p = c.toDouble() / s.length
            p * (ln(p) / ln(2.0))
        }
    }

    /** Sieht der Domainname maschinell erzeugt aus (typisch fuer DGA-Malware)? */
    fun looksGenerated(host: String): Boolean {
        val label = secondLevelLabel(host)
        if (label.length < 10) return false
        val letters = label.count { it.isLetter() }
        val digits = label.count { it.isDigit() }
        val vowels = label.count { it in "aeiouy" }
        val vowelRatio = vowels.toDouble() / label.length
        val digitRatio = digits.toDouble() / label.length
        val entropy = shannonEntropy(label)
        return entropy >= 3.3 && letters > 0 && (vowelRatio < 0.25 || digitRatio >= 0.3)
    }

    fun hasOversizedLabel(host: String, limit: Int = 50) = host.split('.').any { it.length >= limit }
}
