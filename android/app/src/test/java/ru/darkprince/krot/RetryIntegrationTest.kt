package ru.darkprince.krot

import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.io.File
import java.net.*
import java.nio.ByteBuffer
import java.util.Random
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Deterministic loss on the real Kotlin -> DNS -> Python -> TCP path. */
class RetryIntegrationTest {
    private val password = "test-password-only-32-characters!"
    private val domain = "tunnel.example.ru"

    private inner class LossProxy(val upstream: InetSocketAddress, val drops: Int, val delayMs: Long, val delayAllMs: Long = 0) : AutoCloseable {
        val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val hits = AtomicInteger(0)
        val names = CopyOnWriteArrayList<String>()
        private val polls = ConcurrentHashMap<Int, AtomicInteger>()
        val peakPolls = ConcurrentHashMap<Int, Int>()
        private val running = AtomicBoolean(true)
        private val forwards = ConcurrentHashMap.newKeySet<DatagramSocket>()
        private val workers = Executors.newCachedThreadPool()
        init {
            workers.submit {
                while (running.get()) {
                    val request = DatagramPacket(ByteArray(1232), 1232)
                    try { socket.receive(request) } catch (_: SocketException) { break }
                    val raw = request.data.copyOf(request.length)
                    val target = request.socketAddress
                    val name = name(raw)
                    val f = decode(name)
                    val selected = f.type == Wire.DATA && f.stream == 1 && f.seq == 0L
                    val attempt = if (selected) hits.incrementAndGet() else 0
                    if (selected) names.add(name)
                    if (selected && attempt <= drops) continue
                    val poll = if (f.type == Wire.POLL) polls.computeIfAbsent(f.stream) { AtomicInteger() } else null
                    poll?.incrementAndGet()?.let { n -> peakPolls.merge(f.stream, n, ::maxOf) }
                    workers.submit {
                        val forward = DatagramSocket(); forwards.add(forward)
                        try {
                            forward.soTimeout = 5000
                            forward.send(DatagramPacket(raw, raw.size, upstream))
                            val response = DatagramPacket(ByteArray(1232), 1232)
                            forward.receive(response)
                            if (selected && delayMs > 0) Thread.sleep(delayMs)
                            if (delayAllMs > 0) Thread.sleep(delayAllMs)
                            if (running.get()) socket.send(DatagramPacket(response.data, response.length, target))
                        } catch (_: Exception) {
                            // shutdown interrupts sleep and closes all forwarding sockets
                        } finally { poll?.decrementAndGet(); forwards.remove(forward); forward.close() }
                    }
                }
            }
        }
        private fun name(raw: ByteArray): String {
            var p = 12; val parts = mutableListOf<String>()
            while (true) {
                val n = raw[p++].toInt() and 255; if (n == 0) break
                parts.add(String(raw, p, n, Charsets.US_ASCII)); p += n
            }
            return parts.joinToString(".")
        }
        private fun unb32(s: String): ByteArray {
            val result = java.io.ByteArrayOutputStream(); var bits = 0; var buffer = 0
            for (c in s.lowercase()) {
                val n = "abcdefghijklmnopqrstuvwxyz234567".indexOf(c); require(n >= 0)
                buffer = (buffer shl 5) or n; bits += 5
                if (bits >= 8) { bits -= 8; result.write((buffer ushr bits) and 255) }
            }
            return result.toByteArray()
        }
        private fun decode(name: String): Frame {
            val labels = name.split('.').dropLast(domain.split('.').size)
            val meta = unb32(labels.last())
            val master = Wire.hkdf(password.toByteArray(), "krot-v1".toByteArray(), domain.toByteArray())
            val sub = Wire.hkdf(master, meta.copyOfRange(0, 8), byteArrayOf())
            val key = Wire.hkdf(sub, "krot-v1".toByteArray(), "up".toByteArray())
            val cipher = unb32(labels.dropLast(1).joinToString(""))
            return Frame.decode(Wire.crypt(key, meta.copyOfRange(8, 20), cipher, "up", false))
        }
        override fun close() {
            running.set(false); socket.close(); forwards.forEach { it.close() }; workers.shutdownNow()
        }
    }

    private fun transfer(drops: Int, delayMs: Long, minimumAttempts: Int, stalls: Boolean = false) {
        val udpPort = DatagramSocket(0).use { it.localPort }
        val socksPort = ServerSocket(0).use { it.localPort }
        val echo = ServerSocket(0)
        val workers = Executors.newCachedThreadPool()
        val echoJob = workers.submit {
            echo.accept().use { s ->
                val buffer = ByteArray(1024)
                while (true) {
                    val n = s.getInputStream().read(buffer); if (n < 0) break
                    s.getOutputStream().write(buffer, 0, n); s.getOutputStream().flush()
                }
            }
        }
        val server = File("../../server/krot.py").canonicalFile
        val process = ProcessBuilder("python3", server.path, "--domain", domain, "--port", "$udpPort", "--bind", "127.0.0.1", "--allow-private")
            .apply { environment()["KROT_PASSWORD"] = password; redirectErrorStream(true); redirectOutput(File.createTempFile("krot-retry", ".log")) }.start()
        val proxy = LossProxy(InetSocketAddress("127.0.0.1", udpPort), drops, delayMs)
        val logs = CopyOnWriteArrayList<String>()
        val tunnel = Tunnel(Config(domain, password, pipeline = 12, socksPort = socksPort), InetSocketAddress("127.0.0.1", proxy.socket.localPort), log = { logs.add(it) })
        try {
            tunnel.start(); tunnel.rtt = 20.0
            Socket("127.0.0.1", socksPort).use { s ->
                s.soTimeout = 30000
                val out = s.getOutputStream(); val input = DataInputStream(s.getInputStream())
                out.write(byteArrayOf(5, 1, 0)); assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
                out.write(ByteBuffer.allocate(10).put(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1)).putShort(echo.localPort.toShort()).array())
                val reply = ByteArray(10).also { input.readFully(it) }; assertEquals(0, reply[1].toInt())
                val bytes = ByteArray(8192).also { Random(123).nextBytes(it) }
                val sent = workers.submit { out.write(bytes); out.flush(); s.shutdownOutput() }
                assertArrayEquals("TCP must survive DNS retries without duplicate bytes", bytes, input.readNBytes(bytes.size))
                assertEquals(-1, input.read())
                sent.get(30, TimeUnit.SECONDS)
                assertTrue("Not enough retransmissions", proxy.hits.get() >= minimumAttempts)
                assertEquals("Retries reused a cached QNAME", proxy.names.size, proxy.names.toSet().size)
                assertEquals("Stall path: $logs", stalls, logs.any { "поток сохранён" in it })
                assertTrue("Negotiated chunk is logged: $logs", logs.any { it.startsWith("Chunk ") })
            }
            echoJob.get(30, TimeUnit.SECONDS)
        } finally {
            tunnel.close(); proxy.close(); echo.close(); workers.shutdownNow(); process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS)
        }
    }
    private fun socks(port: Int, target: Int): Socket {
        val s = Socket("127.0.0.1", port); s.soTimeout = 30000
        val out = s.getOutputStream(); val input = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 0)); assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
        out.write(ByteBuffer.allocate(10).put(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1)).putShort(target.toShort()).array())
        assertEquals(0, ByteArray(10).also { input.readFully(it) }[1].toInt())
        return s
    }

    /** A download next to idle connections (as Telegram keeps them) gets the whole pipeline. */
    @Test fun busyStreamUsesWholePipelineBesideIdleStreams() {
        val udpPort = DatagramSocket(0).use { it.localPort }
        val socksPort = ServerSocket(0).use { it.localPort }
        val bytes = ByteArray(65536).also { Random(7).nextBytes(it) }
        val origin = ServerSocket(0)
        val workers = Executors.newCachedThreadPool()
        workers.submit {
            while (true) {
                val s = try { origin.accept() } catch (_: SocketException) { break }
                // Connections 1-3 stay silent; the fourth downloads.
                workers.submit { s.use { if (s.getInputStream().read() == 'G'.code) { s.getOutputStream().write(bytes); s.getOutputStream().flush() } else s.getInputStream().read() } }
            }
        }
        val server = File("../../server/krot.py").canonicalFile
        val process = ProcessBuilder("python3", server.path, "--domain", domain, "--port", "$udpPort", "--bind", "127.0.0.1", "--allow-private")
            .apply { environment()["KROT_PASSWORD"] = password; redirectErrorStream(true); redirectOutput(File.createTempFile("krot-lanes", ".log")) }.start()
        val proxy = LossProxy(InetSocketAddress("127.0.0.1", udpPort), drops = 0, delayMs = 0, delayAllMs = 30)
        val tunnel = Tunnel(Config(domain, password, pipeline = 12, socksPort = socksPort), InetSocketAddress("127.0.0.1", proxy.socket.localPort))
        val idle = mutableListOf<Socket>()
        try {
            tunnel.start()
            repeat(3) { idle.add(socks(socksPort, origin.localPort)) }
            socks(socksPort, origin.localPort).use { s ->
                s.getOutputStream().write('G'.code); s.getOutputStream().flush()
                assertArrayEquals(bytes, DataInputStream(s.getInputStream()).readNBytes(bytes.size))
            }
            // Before: lanes = pipeline / active streams = 3 for the downloading stream 4.
            assertTrue("Peak POLLs per stream: ${proxy.peakPolls}", (proxy.peakPolls[4] ?: 0) >= 8)
        } finally {
            idle.forEach { it.close() }
            tunnel.close(); proxy.close(); origin.close(); workers.shutdownNow(); process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS)
        }
    }

    @Test fun twoLossesAndSlowRepliesDoNotCloseStream() = transfer(drops = 2, delayMs = 800, minimumAttempts = 4)
    @Test fun seventhAttemptStillDeliversExactlyOnce() = transfer(drops = 6, delayMs = 0, minimumAttempts = 7)
    // All seven attempts are lost while heartbeats still succeed: the block is retried, the stream stays open.
    @Test fun exhaustedAttemptsKeepStreamWhileTunnelAnswers() = transfer(drops = 9, delayMs = 0, minimumAttempts = 10, stalls = true)
}
