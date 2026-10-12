package ru.darkprince.krot

import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.net.*
import java.nio.ByteBuffer
import java.io.File
import java.util.Random
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Real Kotlin SOCKS engine -> UDP DNS -> Python -> TCP echo (no Android mocks). */
class EndToEndTest {
    @Test fun socksAcrossAllRecordTypes() {
        for (type in listOf(16, 10, 1)) {
            val udpPort = DatagramSocket(0).use { it.localPort }
            val socksPort = ServerSocket(0).use { it.localPort }
            val echo = ServerSocket(0)
            val workers = Executors.newCachedThreadPool()
            val echoJob = workers.submit {
                echo.accept().use { socket ->
                    val input = socket.getInputStream(); val output = socket.getOutputStream()
                    val buf = ByteArray(2048)
                    while (true) { val n = input.read(buf); if (n < 0) break; output.write(buf, 0, n); output.flush() }
                }
            }
            val server = File("../../server/krot.py").canonicalFile
            assertTrue("Missing server: $server", server.exists())
            val process = ProcessBuilder("python3", server.path, "--domain", "tunnel.example.ru", "--port", "$udpPort", "--bind", "127.0.0.1", "--allow-private")
                .apply { environment()["KROT_PASSWORD"] = "test-password-only-32-characters!"; redirectErrorStream(true); redirectOutput(File.createTempFile("krot-server", ".log")) }.start()
            val tunnel = Tunnel(Config("tunnel.example.ru", "test-password-only-32-characters!", recordType = type, pipeline = 12, socksPort = socksPort), InetSocketAddress("127.0.0.1", udpPort))
            try {
                tunnel.start()
                Socket("127.0.0.1", socksPort).use { socket ->
                    socket.soTimeout = 30000
                    val out = socket.getOutputStream(); val input = DataInputStream(socket.getInputStream())
                    out.write(byteArrayOf(5, 1, 0)); assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
                    val host = "127.0.0.1".toByteArray()
                    out.write(ByteBuffer.allocate(7 + host.size).put(byteArrayOf(5, 1, 0, 3, host.size.toByte())).put(host).putShort(echo.localPort.toShort()).array())
                    val reply = ByteArray(10).also { input.readFully(it) }; assertEquals(0, reply[1].toInt())
                    val bytes = ByteArray(32768).also { Random(42).nextBytes(it) }
                    val sent = workers.submit { out.write(bytes); out.flush(); socket.shutdownOutput() }
                    val result = input.readNBytes(bytes.size)
                    assertArrayEquals("Record type $type", bytes, result)
                    assertEquals(-1, input.read())
                    sent.get(30, TimeUnit.SECONDS)
                    assertEquals(bytes.size.toLong(), tunnel.rx.get())
                    assertTrue(tunnel.queries.get() > 10)
                    assertTrue("DNS pipeline was sequential", tunnel.peakInFlight.get() >= 8)
                }
                echoJob.get(30, TimeUnit.SECONDS)
            } finally {
                tunnel.close(); process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS); echo.close(); workers.shutdownNow()
            }
        }
    }
}
