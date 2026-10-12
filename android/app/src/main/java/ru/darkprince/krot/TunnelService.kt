package ru.darkprince.krot

import android.app.*
import android.content.*
import android.content.pm.ServiceInfo
import android.net.*
import android.os.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Live {
    @Volatile var running = false
    @Volatile var connected = false
    @Volatile var tunnel: Tunnel? = null
    private val lines = ArrayDeque<String>()
    @Synchronized fun log(message: String) {
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date())
        lines.addLast("$stamp  $message"); while (lines.size > 200) lines.removeFirst()
    }
    @Synchronized fun logs(): String = lines.joinToString("\n")
}

class TunnelService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private val running = AtomicBoolean(false)
    private lateinit var connectivity: ConnectivityManager
    private var wake: PowerManager.WakeLock? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var signature = ""
    private var cfg: Config? = null
    private fun enqueue(task: () -> Unit) {
        if (!running.get()) return
        try { executor.execute { if (running.get()) task() } } catch (_: RejectedExecutionException) { }
    }
    private fun notice(): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, TunnelService::class.java).setAction("STOP"), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "krot").setContentTitle("Крот · DNS-туннель")
            .setContentText(if (Live.connected) "SOCKS 127.0.0.1:${cfg?.socksPort ?: 1080}" else "Подключение к серверу…")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done).setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Остановить", stop).build()).build()
    }
    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("krot", "Соединение Крот", NotificationManager.IMPORTANCE_LOW))
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") { stopSelf(); return START_NOT_STICKY }
        cfg = Config.load(this)
        try { cfg!!.validate() } catch (e: Exception) { Live.log(e.message ?: "Ошибка настроек"); stopSelf(); return START_NOT_STICKY }
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notice(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, notice())
        if (!running.compareAndSet(false, true)) return START_STICKY
        Live.running = true
        wake = getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "krot:tunnel").also { it.acquire() }
        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { reconnect(network) }
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) { reconnect(network) }
            override fun onLost(network: Network) { enqueue {
                if (connectivity.activeNetwork != network && signature.startsWith("${network.networkHandle}/")) {
                    signature = ""; Live.tunnel?.close(); Live.tunnel = null; Live.connected = false; Live.log("Сеть потеряна; ожидаю подключение")
                }
            } }
        }
        connectivity.registerDefaultNetworkCallback(callback!!)
        connectivity.activeNetwork?.let { reconnect(it) }
        return START_STICKY
    }
    private fun reconnect(network: Network) {
        if (!running.get()) return
        enqueue {
            if (!running.get() || network != connectivity.activeNetwork) return@enqueue
            val config = cfg ?: return@enqueue
            val properties = connectivity.getLinkProperties(network) ?: return@enqueue
            val addresses = if (config.nameserver.isEmpty()) properties.dnsServers else listOf(InetAddress.getByName(config.nameserver))
            if (addresses.isEmpty()) { Live.log("В сети нет DNS; задайте IP вручную"); return@enqueue }
            val token = "${network.networkHandle}/${addresses.map { it.hostAddress }}"
            if (token == signature && Live.tunnel != null) return@enqueue
            signature = token
            Live.tunnel?.close(); Live.tunnel = null
            // Try the system resolvers in order; never inject public DNS defaults.
            for (address in addresses) {
                if (!running.get()) return@enqueue
                val candidate = Tunnel(config, InetSocketAddress(address, 53), { network.bindSocket(it) }, Live::log, {
                    Live.connected = it
                    if (running.get()) getSystemService(NotificationManager::class.java).notify(1, notice())
                })
                Live.tunnel = candidate
                try {
                    candidate.start()
                    if (!running.get()) candidate.close()
                    return@enqueue
                } catch (e: Exception) { Live.log(e.message ?: "Ошибка соединения"); candidate.close(); Live.tunnel = null }
            }
            if (running.get()) { Live.log("Подключиться не удалось; исправьте настройки и запустите снова"); Handler(Looper.getMainLooper()).post { stopSelf() } }
        }
    }
    override fun onDestroy() {
        running.set(false); Live.running = false; Live.connected = false
        callback?.let { connectivity.unregisterNetworkCallback(it) }; callback = null
        Live.tunnel?.close(); Live.tunnel = null; executor.shutdownNow()
        wake?.let { if (it.isHeld) it.release() }; wake = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        Live.log("Остановлено")
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}
