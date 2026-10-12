package ru.darkprince.krot

import java.io.DataInputStream
import java.io.IOException
import java.net.*
import java.nio.ByteBuffer
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import java.security.SecureRandom
import kotlin.math.max

class Tunnel(
    private val cfg: Config,
    private val resolver: InetSocketAddress,
    private val bindDns: (DatagramSocket) -> Unit = {},
    private val log: (String) -> Unit = {},
    private val status: (Boolean) -> Unit = {}
) : AutoCloseable {
    private val crypto = CryptoSession(cfg.password, cfg.domain)
    private val alive = AtomicBoolean(true)
    private val semaphore = Semaphore(cfg.pipeline, true)
    private val uploads = Executors.newFixedThreadPool(cfg.pipeline)
    private val heartbeat = Executors.newSingleThreadScheduledExecutor()
    private val dnsSockets = ConcurrentHashMap.newKeySet<DatagramSocket>()
    private val clients = ConcurrentHashMap.newKeySet<Socket>()
    private val nextStream = AtomicInteger(0)
    private val random = SecureRandom()
    private var listener: ServerSocket? = null
    val queries = AtomicLong(0); val tx = AtomicLong(0); val rx = AtomicLong(0)
    val active = AtomicInteger(0); val inFlight = AtomicInteger(0); val peakInFlight = AtomicInteger(0)
    private val lastTraffic = AtomicLong(System.nanoTime())
    @Volatile var rtt = 500.0
    @Volatile private var lastSuccess = System.nanoTime()
    private val lastStallLog = AtomicLong(0)
    @Volatile private var loggedChunk = 0

    private fun thread(name: String, block: () -> Unit): Thread = Thread(block, name).also { it.isDaemon = true; it.start() }
    fun start(helloAttempts: Int = RpcRetryPolicy.ATTEMPTS) {
        try {
            val hello = rpc(Frame(Wire.PING), helloAttempts)
            require(hello.type == Wire.PONG && hello.stream == 0) { "Неверное приветствие" }
            val server = ServerSocket().also { listener = it }
            server.reuseAddress = true
            server.bind(InetSocketAddress(if (cfg.lan) "0.0.0.0" else "127.0.0.1", cfg.socksPort), 32)
            status(true)
            log("DNS ${resolver.address.hostAddress}:53 · SOCKS ${server.localSocketAddress}")
            heartbeat.scheduleWithFixedDelay({
                if (!alive.get()) return@scheduleWithFixedDelay
                try { rpc(Frame(Wire.PING)); status(true) }
                catch (_: Exception) { if ((System.nanoTime() - lastSuccess) / 1e9 > 15) status(false) }
            }, 1500, 1500, TimeUnit.MILLISECONDS)
            thread("krot-accept") {
                while (alive.get()) {
                    try {
                        val socket = server.accept()
                        if (clients.size >= 32) { socket.close(); continue }
                        clients.add(socket)
                        thread("krot-socks") { serve(socket) }
                    } catch (_: IOException) { break }
                }
            }
        } catch (e: Exception) { close(); throw e }
    }

    private class ServerRejected(stream: Int) : IOException("Сервер отклонил поток $stream")

    private fun rpc(frame: Frame, attempts: Int = RpcRetryPolicy.ATTEMPTS): Frame {
        require(attempts in 1..RpcRetryPolicy.ATTEMPTS)
        check(alive.get())
        semaphore.acquire()
        val flight = inFlight.incrementAndGet()
        peakInFlight.updateAndGet { max(it, flight) }
        val initialRtt = rtt // concurrent successful polls must not reset this RPC's backoff
        var lastError: IOException? = null
        try {
            repeat(attempts) { attempt ->
                check(alive.get())
                val name = crypto.name(frame) // fresh nonce, including retransmissions
                val id = random.nextInt(65536)
                val packet = Dns.query(id, name, cfg.recordType)
                DatagramSocket().use { socket ->
                    dnsSockets.add(socket)
                    try {
                        bindDns(socket); socket.connect(resolver)
                        val start = System.nanoTime()
                        val timeout = RpcRetryPolicy.timeoutMs(initialRtt, frame.type, attempt)
                        val deadline = start + TimeUnit.MILLISECONDS.toNanos(timeout)
                        socket.send(DatagramPacket(packet, packet.size)); queries.incrementAndGet()
                        while (alive.get()) {
                            val left = deadline - System.nanoTime(); if (left <= 0) break
                            socket.soTimeout = max(1, TimeUnit.NANOSECONDS.toMillis(left).toInt())
                            val reply = DatagramPacket(ByteArray(2048), 2048)
                            try { socket.receive(reply) } catch (_: SocketTimeoutException) { break } catch (_: PortUnreachableException) { break }
                            val response = try {
                                crypto.open(Dns.answer(reply.data.copyOf(reply.length), id, name, cfg.recordType))
                            } catch (_: Exception) { continue }
                            if (response.stream != frame.stream) continue
                            if (response.type == Wire.ERROR) throw ServerRejected(frame.stream)
                            if (frame.type == Wire.POLL) {
                                if (response.type !in listOf(Wire.DATA, Wire.PONG, Wire.CLOSE)) continue
                                if (response.type != Wire.CLOSE && response.seq != frame.seq) continue
                            } else if (frame.type == Wire.PING) {
                                if (response.type != Wire.PONG) continue
                            } else if (response.type != Wire.ACK || response.seq != frame.seq) continue
                            val sample = (System.nanoTime() - start) / 1e6
                            // A POLL may be held by the server (long poll): it is not a network RTT sample.
                            if (frame.type != Wire.POLL) synchronized(this) { rtt = rtt * 0.8 + sample * 0.2 }
                            lastSuccess = System.nanoTime()
                            return response
                        }
                    } catch (e: ServerRejected) {
                        throw e // an authenticated rejection is not packet loss
                    } catch (e: IOException) {
                        if (!alive.get()) throw e
                        lastError = e // retry transient UDP send/receive/bind failures as well
                    } finally { dnsSockets.remove(socket) }
                }
                if (attempt == attempts - 1) throw IOException(
                    "DNS ${resolver.address.hostAddress}: нет ответа после $attempts попыток; проверьте делегацию, пароль и резолвер", lastError)
                Thread.sleep(50L * (attempt + 1))
            }
            error("unreachable")
        } finally { inFlight.decrementAndGet(); semaphore.release() }
    }

    /**
     * A block whose seven attempts all timed out keeps its TCP stream while the tunnel
     * itself still answers (heartbeat or other lanes succeeded meanwhile), up to
     * [STREAM_STALL_MS]. Retrying DATA/POLL/FIN with the same seq is idempotent on the server.
     */
    private fun streamRpc(frame: Frame, transfer: Transfer): Frame {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(STREAM_STALL_MS)
        while (true) {
            val started = System.nanoTime()
            try { return rpc(frame) } catch (e: ServerRejected) { throw e } catch (e: IOException) {
                if (!alive.get() || transfer.done.get() || lastSuccess - started <= 0 || System.nanoTime() - deadline > 0) throw e
                val now = System.nanoTime(); val logged = lastStallLog.get()
                if ((logged == 0L || now - logged > TimeUnit.SECONDS.toNanos(5)) && lastStallLog.compareAndSet(logged, now))
                    log("Поток ${frame.stream}: DNS-таймаут, туннель жив — поток сохранён, повторяю")
            }
        }
    }

    private fun serve(socket: Socket) {
        var stream = 0
        var state: Transfer? = null
        val jobs = ArrayDeque<Future<*>>()
        try {
            socket.tcpNoDelay = true; socket.soTimeout = 15000
            val input = DataInputStream(socket.getInputStream()); val output = socket.getOutputStream()
            if (input.readUnsignedByte() != 5) return
            val count = input.readUnsignedByte(); if (count == 0) return
            val methods = ByteArray(count).also { input.readFully(it) }
            if (!methods.contains(0.toByte())) { output.write(byteArrayOf(5, -1)); return }
            output.write(byteArrayOf(5, 0)); output.flush()
            if (input.readUnsignedByte() != 5) return
            val command = input.readUnsignedByte(); if (input.readUnsignedByte() != 0) return
            val host = when (input.readUnsignedByte()) {
                1 -> InetAddress.getByAddress(ByteArray(4).also { input.readFully(it) }).hostAddress!!
                3 -> {
                    val n = input.readUnsignedByte(); require(n > 0)
                    String(ByteArray(n).also { input.readFully(it) }, Charsets.US_ASCII)
                }
                4 -> InetAddress.getByAddress(ByteArray(16).also { input.readFully(it) }).hostAddress!!
                else -> { socksReply(output, 8); return }
            }
            val port = input.readUnsignedShort()
            if (command != 1) { socksReply(output, 7); return }
            require(port > 0)
            val hostname = host.toByteArray(Charsets.US_ASCII)
            val openData = ByteBuffer.allocate(hostname.size + 5).put(hostname.size.toByte()).put(hostname).putShort(port.toShort()).putShort(cfg.maxResponse.toShort()).array()
            stream = nextStream.incrementAndGet(); check(stream > 0)
            val commit = if (openData.size <= crypto.maxUp()) openData else {
                val parts = openData.toList().chunked(crypto.maxUp()).map { it.toByteArray() }
                require(parts.size <= 4) { "Адрес слишком длинный для этой зоны DNS" }
                for ((index, part) in parts.withIndex()) rpc(Frame(Wire.OPEN_PART, stream, index.toLong(), parts.size.toLong(), part))
                byteArrayOf()
            }
            val opened = rpc(Frame(Wire.OPEN, stream, data = commit))
            require(opened.data.size == 2)
            val chunk = ByteBuffer.wrap(opened.data).short.toInt() and 65535
            require(chunk in 100..cfg.maxResponse)
            if (chunk != loggedChunk) { loggedChunk = chunk; log("Chunk $chunk Б (запрошено ${cfg.maxResponse})") }
            val transfer = Transfer(stream, socket, output, chunk); state = transfer
            active.incrementAndGet()
            socksReply(output, 0); socket.soTimeout = 0
            // Every stream may use the whole pipeline; the global semaphore shares it and idle lanes park.
            repeat(cfg.pipeline) { lane -> thread("krot-poll-$stream-$lane") { transfer.poll(lane) } }
            var seq = 0L
            val buffer = ByteArray(crypto.maxUp())
            while (alive.get() && !transfer.done.get()) {
                val n = input.read(buffer); if (n < 0) break
                if (n == 0) continue
                val part = buffer.copyOf(n); val index = seq++
                jobs.add(uploads.submit {
                    transfer.lastActive = System.nanoTime() // a reply is likely to follow
                    streamRpc(Frame(Wire.DATA, transfer.stream, index, transfer.downAck.get(), part), transfer)
                    tx.addAndGet(part.size.toLong()); lastTraffic.set(System.nanoTime())
                })
                // Bound retained uploads and the distance ahead of a missing block.
                if (jobs.size >= cfg.pipeline) jobs.removeFirst().get()
            }
            while (jobs.isNotEmpty()) jobs.removeFirst().get()
            if (!transfer.done.get() && alive.get()) {
                streamRpc(Frame(Wire.FIN, stream, seq, transfer.downAck.get()), transfer)
                synchronized(transfer.monitor) {
                    while (!transfer.done.get() && alive.get()) transfer.monitor.wait(1000)
                }
            }
        } catch (e: Exception) {
            if (alive.get()) {
                log("Поток закрыт: ${e.cause?.message ?: e.message}")
                if (state == null) try { socksReply(socket.getOutputStream(), 1) } catch (_: Exception) { }
            }
        } finally {
            jobs.forEach { it.cancel(true) }
            state?.finish()
            if (state != null) active.decrementAndGet()
            clients.remove(socket); try { socket.close() } catch (_: Exception) { }
            if (stream != 0 && alive.get()) {
                try { rpc(Frame(Wire.CLOSE, stream, ack = state?.downAck?.get() ?: 0)) } catch (_: Exception) { }
            }
        }
    }

    private fun socksReply(out: java.io.OutputStream, code: Int) {
        out.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
    }

    private inner class Transfer(val stream: Int, val socket: Socket, val out: java.io.OutputStream, val chunk: Int) {
        val monitor = Object(); val done = AtomicBoolean(false)
        val downAck = AtomicLong(0)
        private val pending = sortedMapOf<Long, ByteArray>(); private val polling = HashSet<Long>(); private var eof: Long? = null
        @Volatile private var lastData = 0L // no downstream yet: only lane 0 polls
        @Volatile var lastActive = System.nanoTime()
        fun finish() {
            if (done.compareAndSet(false, true)) {
                try { socket.close() } catch (_: Exception) { }
                synchronized(monitor) { monitor.notifyAll() }
            }
        }
        /** Lowest block neither received nor being polled, inside the window. Caller holds [monitor]. */
        private fun claim(): Long? {
            var seq = downAck.get()
            while (seq in pending || seq in polling) seq++
            if (seq >= downAck.get() + WINDOW || eof?.let { seq >= it } == true) return null
            polling.add(seq); return seq
        }
        fun poll(lane: Int) {
            try {
                while (alive.get() && !done.get()) {
                    val requested = synchronized(monitor) {
                        // Extra lanes run only while downstream data flows; lane 0 keeps watch via long poll.
                        val parked = lane > 0 && System.nanoTime() - lastData > LANE_IDLE_NS
                        val seq = if (parked) null else claim()
                        if (seq == null && !done.get()) monitor.wait(if (parked) 1000 else 50)
                        seq
                    } ?: continue
                    val response = try { streamRpc(Frame(Wire.POLL, stream, requested, downAck.get()), this) }
                        catch (e: Exception) { synchronized(monitor) { polling.remove(requested) }; throw e }
                    synchronized(monitor) {
                        polling.remove(requested)
                        if (done.get()) return
                        when (response.type) {
                            Wire.DATA -> {
                                require(response.seq == requested && response.data.isNotEmpty() && response.data.size <= chunk)
                                if (response.seq >= downAck.get()) pending[response.seq] = response.data
                                require(pending.size <= WINDOW)
                                while (true) {
                                    val data = pending.remove(downAck.get()) ?: break
                                    out.write(data); out.flush(); rx.addAndGet(data.size.toLong()); lastTraffic.set(System.nanoTime()); downAck.incrementAndGet()
                                }
                                lastData = System.nanoTime(); lastActive = lastData
                                monitor.notifyAll() // wake parked lanes
                            }
                            Wire.CLOSE -> { require(response.seq >= downAck.get()); eof = response.seq }
                        }
                        if (eof == downAck.get()) { finish(); return }
                    }
                    // The server already held an empty POLL; back off only on a stream idle for 3s.
                    if (response.type != Wire.DATA) Thread.sleep(if (System.nanoTime() - lastActive > TimeUnit.SECONDS.toNanos(3)) 1500 else 90)
                }
            } catch (e: Exception) {
                if (!done.get() && alive.get()) log("Поток $stream: ${e.message}")
                finish()
            }
        }
    }

    companion object {
        const val STREAM_STALL_MS = 60_000L
        private const val WINDOW = 64 // blocks, as on the server
        private val LANE_IDLE_NS = TimeUnit.SECONDS.toNanos(1)
    }

    override fun close() {
        if (!alive.compareAndSet(true, false)) return
        heartbeat.shutdownNow(); uploads.shutdownNow()
        try { listener?.close() } catch (_: Exception) { }
        dnsSockets.forEach { it.close() }; clients.forEach { try { it.close() } catch (_: Exception) { } }
        status(false)
    }
}
