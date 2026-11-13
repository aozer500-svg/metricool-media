package app.netzwaechter.core

import kotlin.test.*

private fun dnsQuery(name: String, qtype: Int = 1, id: Int = 0x1234): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    out.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
    for (l in name.split('.')) { out.write(l.length); out.write(l.toByteArray()) }
    out.write(0)
    out.write(byteArrayOf((qtype shr 8).toByte(), qtype.toByte(), 0, 1))
    return out.toByteArray()
}

class PacketTest {
    private val a = byteArrayOf(10, 77, 0, 2)
    private val b = byteArrayOf(10, 77, 0, 1)

    @Test fun roundTrip() {
        val q = dnsQuery("example.com")
        val raw = PacketCodec.buildIpv4Udp(a, b, 40000, 53, q)
        val p = assertNotNull(PacketCodec.parseIpv4Udp(raw, raw.size))
        assertEquals(40000, p.srcPort); assertEquals(53, p.dstPort)
        assertContentEquals(a, p.srcAddr); assertContentEquals(b, p.dstAddr)
        assertContentEquals(q, p.payload)
    }

    @Test fun ipHeaderChecksumIsValid() {
        val raw = PacketCodec.buildIpv4Udp(a, b, 1, 53, dnsQuery("a.de"))
        assertEquals(0, PacketCodec.checksum(raw, 0, 20, 0)) // Summe inkl. Pruefsumme muss 0 ergeben
    }

    @Test fun rejectsNonUdpAndShort() {
        val raw = PacketCodec.buildIpv4Udp(a, b, 1, 53, dnsQuery("a.de"))
        raw[9] = 6 // TCP
        assertNull(PacketCodec.parseIpv4Udp(raw, raw.size))
        assertNull(PacketCodec.parseIpv4Udp(ByteArray(10), 10))
    }

    @Test fun dnsQuestion() {
        val q = assertNotNull(DnsCodec.parseQuestion(dnsQuery("WWW.Example.COM", DnsCodec.TYPE_TXT)))
        assertEquals("www.example.com", q.name)
        assertEquals(DnsCodec.TYPE_TXT, q.qtype)
        assertEquals(0x1234, q.id)
    }

    @Test fun nxdomain() {
        val raw = dnsQuery("evil.example")
        val q = assertNotNull(DnsCodec.parseQuestion(raw))
        val r = DnsCodec.buildNxdomain(raw, q)
        assertEquals(0x80, r[2].toInt() and 0x80) // QR
        assertEquals(3, r[3].toInt() and 0x0F) // NXDOMAIN
        assertEquals(0x1234, ((r[0].toInt() and 0xFF) shl 8) or (r[1].toInt() and 0xFF))
        assertNull(DnsCodec.parseQuestion(r)) // ist jetzt eine Antwort
    }

    @Test fun garbageIsRejected() {
        assertNull(DnsCodec.parseQuestion(ByteArray(40) { 0xFF.toByte() }))
        assertNull(DnsCodec.parseQuestion(ByteArray(5)))
    }
}

class HeuristicsTest {
    @Test fun baseDomain() {
        assertEquals("example.com", DomainHeuristics.baseDomain("a.b.example.com"))
        assertEquals("example.co.uk", DomainHeuristics.baseDomain("x.example.co.uk"))
        assertEquals("example.de", DomainHeuristics.baseDomain("example.de"))
        assertEquals("a.b", DomainHeuristics.subdomainPart("a.b.example.com"))
    }

    @Test fun generatedDomains() {
        assertTrue(DomainHeuristics.looksGenerated("xkqzjvbnrtplwqc.com"))
        assertTrue(DomainHeuristics.looksGenerated("a8f3k29x7d1q0z5m.net"))
        for (ok in listOf("google.com", "microsoftonline.com", "cloudflare.com", "googleusercontent.com",
            "d1a2b3c4e5f6a7.cloudfront.net", "akamaiedge.net", "amazonaws.com", "instagram.com", "whatsapp.net"))
            assertFalse(DomainHeuristics.looksGenerated(ok), ok)
    }
}

class RulesTest {
    @Test fun parentMatching() {
        val rs = RuleSet.parseBlocklist("# Kommentar\n0.0.0.0 evil.com\nbad.example.org # inline\nlocalhost\n")
        assertEquals(2, rs.size)
        assertNotNull(rs.match("evil.com"))
        assertNotNull(rs.match("deep.sub.evil.com"))
        assertNotNull(rs.match("BAD.example.org"))
        assertNull(rs.match("notevil.com"))
        assertNull(rs.match("example.org"))
    }
}

class AnalyzerTest {
    private fun ev(t: Long, d: String, pkg: String = "com.x", q: Int = 1) = DnsEvent(t, 10001, pkg, d, q)

    @Test fun blocklistBlocksAndAlerts() {
        val an = TrafficAnalyzer(RuleSet.parseBlocklist("evil.com"))
        val v = an.onDns(ev(0, "c2.evil.com"))
        assertTrue(v.block)
        assertEquals(Kind.BLOCKLIST, v.alerts.single().kind)
        assertEquals(Severity.HIGH, v.alerts.single().severity)
        // Cooldown: kein zweiter Alarm, aber weiterhin blocken
        val v2 = an.onDns(ev(1000, "c2.evil.com"))
        assertTrue(v2.block); assertTrue(v2.alerts.isEmpty())
    }

    @Test fun watchlistRespectsExpectedApp() {
        val an = TrafficAnalyzer(DefaultRules.watchlist())
        assertTrue(an.onDns(ev(0, "api.telegram.org", pkg = "org.telegram.messenger")).alerts.isEmpty())
        val v = an.onDns(ev(0, "api.telegram.org", pkg = "com.fake.flashlight"))
        assertFalse(v.block)
        assertEquals(Kind.WATCHLIST, v.alerts.single().kind)
    }

    @Test fun dnsTunnelDetected() {
        val an = TrafficAnalyzer(RuleSet())
        val all = (0 until 40).flatMap { i ->
            an.onDns(ev(i * 1000L, "${"a1b2c3d4e5f6g7h8i9j0".repeat(1)}$i.t.tunnel-example.com", q = DnsCodec.TYPE_TXT)).alerts
        }
        assertTrue(all.any { it.kind == Kind.DNS_TUNNEL && it.severity == Severity.HIGH })
    }

    @Test fun normalBrowsingIsQuiet() {
        val an = TrafficAnalyzer(DefaultRules.watchlist())
        val domains = listOf("www.google.com", "i.ytimg.com", "fonts.gstatic.com", "graph.facebook.com",
            "api.spotify.com", "mtalk.google.com", "clients4.google.com", "play.googleapis.com")
        val alerts = domains.flatMapIndexed { i, d -> an.onDns(ev(i * 1000L, d)).alerts }
        assertTrue(alerts.isEmpty(), alerts.joinToString { it.title })
    }

    @Test fun beaconDetected() {
        val an = TrafficAnalyzer(RuleSet())
        val alerts = (0 until 10).flatMap { i -> an.onDns(ev(i * 60_000L + (i % 2) * 200, "ping.beacon-example.com")).alerts }
        assertTrue(alerts.any { it.kind == Kind.BEACON })
    }

    @Test fun irregularTrafficIsNoBeacon() {
        val an = TrafficAnalyzer(RuleSet())
        val times = listOf(0L, 7_000, 90_000, 100_000, 400_000, 410_000, 900_000, 1_000_000, 1_500_000, 1_501_000)
        assertTrue(times.flatMap { an.onDns(ev(it, "sync.example.com")).alerts }.none { it.kind == Kind.BEACON })
    }

    @Test fun uploadScreenOff() {
        val va = VolumeAnalyzer()
        val mb = 1024L * 1024
        val a = va.analyze(listOf(
            VolumeSample(1, "com.sus", 8 * mb, 100_000, screenOn = false),
            VolumeSample(2, "com.video", 8 * mb, 90 * mb, screenOn = true),
            VolumeSample(3, "com.quiet", 100_000, 100_000, screenOn = false),
            VolumeSample(4, "com.skew", 12 * mb, mb, screenOn = true),
        ), 0)
        assertEquals(setOf("com.sus", "com.skew"), a.map { it.pkg }.toSet())
        assertEquals(Kind.UPLOAD_SCREEN_OFF, a.first { it.pkg == "com.sus" }.kind)
        assertEquals(Kind.UPLOAD_SKEWED, a.first { it.pkg == "com.skew" }.kind)
    }
}
