package app.netzwaechter.core

/** Ein UDP-Datagramm aus einem IPv4-Paket. */
class UdpPacket(
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
)

object PacketCodec {
    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    /** Liest ein IPv4/UDP-Paket aus dem TUN-Puffer. Liefert null bei allem anderen. */
    fun parseIpv4Udp(buf: ByteArray, len: Int): UdpPacket? {
        if (len < 28 || len > buf.size) return null
        if (((buf[0].toInt() and 0xF0) shr 4) != 4) return null
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return null
        if ((buf[9].toInt() and 0xFF) != 17) return null // nur UDP
        if ((u16(buf, 6) and 0x3FFF) != 0) return null // fragmentiert: ignorieren
        val end = minOf(len, u16(buf, 2))
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        val payloadEnd = minOf(end, ihl + u16(buf, ihl + 4))
        if (payloadEnd < ihl + 8) return null
        return UdpPacket(
            srcAddr = buf.copyOfRange(12, 16),
            dstAddr = buf.copyOfRange(16, 20),
            srcPort = srcPort,
            dstPort = dstPort,
            payload = buf.copyOfRange(ihl + 8, payloadEnd),
        )
    }

    /** Baut ein vollstaendiges IPv4/UDP-Paket (mit korrekten Pruefsummen). */
    fun buildIpv4Udp(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        require(src.size == 4 && dst.size == 4)
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        require(total <= 65535)
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[6] = 0x40 // Don't Fragment
        p[8] = 64 // TTL
        p[9] = 17
        src.copyInto(p, 12); dst.copyInto(p, 16)
        val ipSum = checksum(p, 0, 20, 0)
        p[10] = (ipSum shr 8).toByte(); p[11] = ipSum.toByte()

        p[20] = (srcPort shr 8).toByte(); p[21] = srcPort.toByte()
        p[22] = (dstPort shr 8).toByte(); p[23] = dstPort.toByte()
        p[24] = (udpLen shr 8).toByte(); p[25] = udpLen.toByte()
        payload.copyInto(p, 28)
        // UDP-Pruefsumme ueber Pseudo-Header + UDP
        var pseudo = 0
        for (i in 0 until 4 step 2) {
            pseudo += u16(src, i) + u16(dst, i)
        }
        pseudo += 17 + udpLen
        var udpSum = checksum(p, 20, udpLen, pseudo)
        if (udpSum == 0) udpSum = 0xFFFF
        p[26] = (udpSum shr 8).toByte(); p[27] = udpSum.toByte()
        return p
    }

    internal fun checksum(b: ByteArray, off: Int, len: Int, initial: Int): Int {
        var sum = initial.toLong()
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += u16(b, i); i += 2
        }
        if (i < end) sum += (b[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}

class DnsQuestion(val id: Int, val name: String, val qtype: Int, val questionEnd: Int)

object DnsCodec {
    const val TYPE_A = 1
    const val TYPE_NULL = 10
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28

    /** Liest die erste Frage einer DNS-Anfrage. Null, wenn es keine gueltige Anfrage ist. */
    fun parseQuestion(p: ByteArray): DnsQuestion? {
        if (p.size < 17) return null
        if ((p[2].toInt() and 0x80) != 0) return null // das ist eine Antwort
        val qd = ((p[4].toInt() and 0xFF) shl 8) or (p[5].toInt() and 0xFF)
        if (qd < 1) return null
        var pos = 12
        val sb = StringBuilder()
        while (true) {
            if (pos >= p.size) return null
            val l = p[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if (l and 0xC0 != 0) return null // Kompression in der Frage unueblich
            if (pos + 1 + l > p.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until l) sb.append((p[pos + 1 + i].toInt() and 0xFF).toChar())
            pos += 1 + l
            if (sb.length > 255) return null
        }
        if (pos + 4 > p.size) return null
        val qtype = ((p[pos].toInt() and 0xFF) shl 8) or (p[pos + 1].toInt() and 0xFF)
        val id = ((p[0].toInt() and 0xFF) shl 8) or (p[1].toInt() and 0xFF)
        return DnsQuestion(id, sb.toString().lowercase(), qtype, pos + 4)
    }

    /** Antwort "Domain existiert nicht" - so wird eine Domain blockiert. */
    fun buildNxdomain(query: ByteArray, q: DnsQuestion): ByteArray {
        val r = query.copyOf(q.questionEnd)
        r[2] = (0x80 or (query[2].toInt() and 0x79)).toByte() // QR=1, Opcode+RD uebernehmen
        r[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
        r[6] = 0; r[7] = 0; r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0
        r[4] = 0; r[5] = 1
        return r
    }
}
