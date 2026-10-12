package ru.darkprince.krot

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

object Wire {
    const val OPEN = 1; const val DATA = 2; const val CLOSE = 3; const val POLL = 4
    const val PING = 5; const val PONG = 6; const val ACK = 7; const val ERROR = 8; const val FIN = 9; const val OPEN_PART = 10
    const val HEADER = 23
    fun hkdf(key: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(key, salt, info))
        return ByteArray(32).also { generator.generateBytes(it, 0, it.size) }
    }
    fun b32(raw: ByteArray): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        var buffer = 0; var bits = 0
        val out = StringBuilder()
        for (byte in raw) {
            buffer = (buffer shl 8) or (byte.toInt() and 255); bits += 8
            while (bits >= 5) { bits -= 5; out.append(alphabet[(buffer ushr bits) and 31]) }
        }
        if (bits > 0) out.append(alphabet[(buffer shl (5 - bits)) and 31])
        return out.toString()
    }
    fun crypt(key: ByteArray, nonce: ByteArray, data: ByteArray, direction: String, encrypt: Boolean): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(encrypt, AEADParameters(KeyParameter(key), 128, nonce, "krot-v1-$direction".toByteArray()))
        val out = ByteArray(cipher.getOutputSize(data.size))
        val n = cipher.processBytes(data, 0, data.size, out, 0)
        return out.copyOf(n + cipher.doFinal(out, n))
    }
}

data class Frame(val type: Int, val stream: Int = 0, val seq: Long = 0, val ack: Long = 0, val data: ByteArray = byteArrayOf()) {
    fun encode(): ByteArray = ByteBuffer.allocate(Wire.HEADER + data.size).put(type.toByte()).putInt(stream).putLong(seq).putLong(ack).putShort(data.size.toShort()).put(data).array()
    companion object {
        fun decode(raw: ByteArray): Frame {
            require(raw.size >= Wire.HEADER)
            val b = ByteBuffer.wrap(raw)
            val type = b.get().toInt() and 255; val stream = b.int; val seq = b.long; val ack = b.long
            val length = b.short.toInt() and 65535
            require(type in 1..10 && seq >= 0 && ack >= 0 && b.remaining() == length)
            return Frame(type, stream, seq, ack, ByteArray(length).also { b.get(it) })
        }
    }
}

class CryptoSession(password: String, val domain: String) {
    private val random = SecureRandom()
    val session = ByteArray(8).also(random::nextBytes)
    private val prefix = ByteArray(4).also(random::nextBytes)
    private val counter = AtomicLong(0)
    private val master = Wire.hkdf(password.toByteArray(Charsets.UTF_8), "krot-v1".toByteArray(), domain.toByteArray())
    private val sub = Wire.hkdf(master, session, byteArrayOf())
    private val up = Wire.hkdf(sub, "krot-v1".toByteArray(), "up".toByteArray())
    private val down = Wire.hkdf(sub, "krot-v1".toByteArray(), "down".toByteArray())
    fun name(frame: Frame): String {
        val n = counter.incrementAndGet(); check(n > 0)
        val nonce = ByteBuffer.allocate(12).put(prefix).putLong(n).array()
        val cipher = Wire.crypt(up, nonce, frame.encode(), "up", true)
        val name = Wire.b32(cipher).chunked(63).joinToString(".") + "." + Wire.b32(session + nonce) + "." + domain
        require(name.length + 2 <= 255) { "Имя DNS слишком длинное" }
        return name
    }
    fun maxUp(): Int {
        for (size in 180 downTo 1) {
            val chars = ((Wire.HEADER + size + 16) * 8 + 4) / 5
            if (chars + (chars + 62) / 63 + 33 + domain.length + 2 <= 255) return size
        }
        error("Домен слишком длинный")
    }
    fun open(raw: ByteArray): Frame {
        require(raw.size >= 28 + Wire.HEADER)
        return Frame.decode(Wire.crypt(down, raw.copyOfRange(0, 12), raw.copyOfRange(12, raw.size), "down", false))
    }
}
