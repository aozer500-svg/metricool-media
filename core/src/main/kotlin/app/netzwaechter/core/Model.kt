package app.netzwaechter.core

enum class Severity { LOW, MEDIUM, HIGH }

enum class Kind(val label: String) {
    BLOCKLIST("Bekannte Schad-Domain"),
    WATCHLIST("Verdaechtiger Dienst"),
    GENERATED_DOMAIN("Zufaellige Domain"),
    DNS_TUNNEL("Moeglicher DNS-Tunnel"),
    BEACON("Regelmaessiges Signal"),
    UPLOAD_SCREEN_OFF("Upload bei ausgeschaltetem Bildschirm"),
    UPLOAD_LARGE("Grosser Upload"),
    UPLOAD_SKEWED("Auffaellig viel Upload"),
    APP_RISK("Riskante App"),
}

class Alert(
    val timeMs: Long,
    val severity: Severity,
    val kind: Kind,
    val pkg: String,
    val title: String,
    val detail: String,
)

class DnsEvent(
    val timeMs: Long,
    val uid: Int,
    val pkg: String,
    val domain: String,
    val qtype: Int,
)

class DnsVerdict(val alerts: List<Alert>, val block: Boolean)
