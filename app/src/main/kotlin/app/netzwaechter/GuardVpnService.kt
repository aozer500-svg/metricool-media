package app.netzwaechter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import app.netzwaechter.core.DefaultRules
import app.netzwaechter.core.DnsCodec
import app.netzwaechter.core.DnsEvent
import app.netzwaechter.core.PacketCodec
import app.netzwaechter.core.TrafficAnalyzer
import app.netzwaechter.core.UdpPacket
import app.netzwaechter.core.VolumeAnalyzer
import app.netzwaechter.core.RuleSet
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/**
 * Lokaler "DNS-Waechter": Der VPN-Tunnel faengt NUR DNS-Anfragen ab (Route nur auf die Fake-DNS-Adresse).
 * Der restliche Datenverkehr laeuft unveraendert am Tunnel vorbei, nichts verlaesst das Handy ueber
 * Dritte. Jede Anfrage wird der anfragenden App zugeordnet, geprueft und an den normalen DNS-Server
 * des Netzwerks weitergereicht (oder bei Blocklist-Treffern mit NXDOMAIN beantwortet).
 */
class GuardVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "app.netzwaechter.STOP"
        private const val NOTIF_ID = 1
        private const val CHANNEL = "guard"
        private const val TUN_ADDR = "10.77.0.2"
        private const val DNS_ADDR = "10.77.0.1"
        private const val VOLUME_INTERVAL_MS = 5 * 60_000L

        @Volatile var running = false
            private set

        fun start(ctx: Context) {
            androidx.core.content.ContextCompat.startForegroundService(ctx, Intent(ctx, GuardVpnService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, GuardVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private val pool = Executors.newFixedThreadPool(4)
    private val outLock = Any()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var cm: ConnectivityManager
    private lateinit var analyzer: TrafficAnalyzer
    private lateinit var volumeAnalyzer: VolumeAnalyzer
    private lateinit var volumeMonitor: VolumeMonitor

    @Volatile private var underlying: Network? = null
    @Volatile private var upstream: List<InetAddress> = defaultUpstream()

    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            val dns = lp.dnsServers.filterIsInstance<Inet4Address>().filter { it.hostAddress != DNS_ADDR }
            underlying = network
            if (dns.isNotEmpty()) upstream = dns
        }
        override fun onLost(network: Network) {
            if (underlying == network) underlying = null
        }
    }

    private val volumeTick = object : Runnable {
        override fun run() {
            if (!running) return
            pool.execute {
                try {
                    val now = System.currentTimeMillis()
                    volumeAnalyzer.analyze(volumeMonitor.sample(), now).forEach(AlertCenter::raise)
                } catch (_: Exception) { }
            }
            main.postDelayed(this, VOLUME_INTERVAL_MS)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopGuard()
            return START_NOT_STICKY
        }
        AlertCenter.init(this)
        enterForeground()
        startGuard()
        return START_STICKY
    }

    override fun onRevoke() {
        // Der Nutzer hat den VPN-Zugriff entzogen oder eine andere VPN-App gestartet.
        stopGuard()
    }

    override fun onDestroy() {
        stopGuard()
        pool.shutdownNow()
        super.onDestroy()
    }

    private fun enterForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Netzwächter aktiv", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Netzwächter überwacht den Datenverkehr")
            .setContentText("DNS-Anfragen und Upload-Mengen werden geprüft")
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun startGuard() {
        if (running) return
        cm = getSystemService(ConnectivityManager::class.java)
        analyzer = TrafficAnalyzer(DefaultRules.watchlist() + loadBlocklist(), ignoredPkgs = setOf(packageName))
        volumeAnalyzer = VolumeAnalyzer(ignoredPkgs = setOf(packageName))
        volumeMonitor = VolumeMonitor(this)

        // DNS-Server des echten Netzwerks merken, bevor der Tunnel aktiv ist
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(req, netCallback)

        val fd = Builder()
            .setSession("Netzwächter")
            .setMtu(1500)
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32) // nur DNS durch den Tunnel
            .setBlocking(true)
            .establish()
        if (fd == null) {
            stopGuard()
            return
        }
        tun = fd
        running = true
        reader = Thread({ readLoop(fd) }, "guard-reader").also { it.start() }
        main.postDelayed(volumeTick, 30_000L)
        AlertCenter.logDns(System.currentTimeMillis(), packageName, "— Schutz gestartet —")
    }

    private fun stopGuard() {
        val wasRunning = running
        running = false
        main.removeCallbacks(volumeTick)
        try { cm.unregisterNetworkCallback(netCallback) } catch (_: Exception) { }
        try { tun?.close() } catch (_: Exception) { }
        tun = null
        reader = null
        if (wasRunning) AlertCenter.logDns(System.currentTimeMillis(), packageName, "— Schutz beendet —")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun loadBlocklist(): RuleSet {
        // Eigene Blockliste: Datei "blocklist.txt" im App-Speicher (Hosts-Format oder eine Domain pro Zeile)
        return try {
            val f = java.io.File(filesDir, "blocklist.txt")
            if (f.exists()) RuleSet.parseBlocklist(f.readText()) else RuleSet()
        } catch (_: Exception) { RuleSet() }
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (running) {
                val n = input.read(buf)
                if (n <= 0) continue
                val pkt = PacketCodec.parseIpv4Udp(buf, n) ?: continue
                if (pkt.dstPort != 53) continue
                pool.execute { handleQuery(pkt, output) }
            }
        } catch (_: Exception) {
            // Tunnel wurde geschlossen
        }
    }

    private fun handleQuery(pkt: UdpPacket, output: FileOutputStream) {
        val q = DnsCodec.parseQuestion(pkt.payload)
        var response: ByteArray? = null
        if (q != null) {
            val uid = ownerUid(pkt)
            val pkg = packageManager.getPackagesForUid(uid)?.firstOrNull() ?: "uid:$uid"
            val now = System.currentTimeMillis()
            val verdict = analyzer.onDns(DnsEvent(now, uid, pkg, q.name, q.qtype))
            verdict.alerts.forEach(AlertCenter::raise)
            AlertCenter.logDns(now, pkg, q.name, if (verdict.block) "  [blockiert]" else "")
            if (verdict.block) response = DnsCodec.buildNxdomain(pkt.payload, q)
        }
        if (response == null) response = forward(pkt.payload)
        if (response == null) return
        val out = PacketCodec.buildIpv4Udp(pkt.dstAddr, pkt.srcAddr, pkt.dstPort, pkt.srcPort, response)
        try {
            synchronized(outLock) { output.write(out) }
        } catch (_: Exception) { }
    }

    private fun ownerUid(p: UdpPacket): Int = try {
        cm.getConnectionOwnerUid(
            OsConstants.IPPROTO_UDP,
            InetSocketAddress(InetAddress.getByAddress(p.srcAddr), p.srcPort),
            InetSocketAddress(InetAddress.getByAddress(p.dstAddr), p.dstPort),
        )
    } catch (_: Exception) { Process.INVALID_UID }

    private fun forward(query: ByteArray): ByteArray? {
        for (server in upstream) {
            try {
                DatagramSocket().use { s ->
                    protect(s) // an der VPN vorbei, sonst Endlosschleife
                    underlying?.bindSocket(s)
                    s.soTimeout = 3000
                    s.connect(InetSocketAddress(server, 53))
                    s.send(DatagramPacket(query, query.size))
                    val rb = ByteArray(4096)
                    val rp = DatagramPacket(rb, rb.size)
                    s.receive(rp)
                    return rb.copyOf(rp.length)
                }
            } catch (_: Exception) { /* naechsten Server versuchen */ }
        }
        return null
    }

    private fun defaultUpstream(): List<InetAddress> =
        listOf("9.9.9.9", "1.1.1.1").map { InetAddress.getByName(it) }
}
