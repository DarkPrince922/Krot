package ru.darkprince.krot

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class ProtocolTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun pythonCompatibleVector() {
        val master = Wire.hkdf("test-password-only-32-characters!".toByteArray(), "krot-v1".toByteArray(), "tunnel.example.ru".toByteArray())
        assertArrayEquals(hex("d35250e88be330c90aba0f5052b3024452f7aaf252acb9744cbbe68feec30f2c"), master)
        val sub = Wire.hkdf(master, ByteArray(8) { it.toByte() }, byteArrayOf())
        val up = Wire.hkdf(sub, "krot-v1".toByteArray(), "up".toByteArray())
        assertArrayEquals(hex("cd6962586a0f3514f18be2806461fef4d048922fd93b01866a4280844e796360"), up)
        val plain = Frame(Wire.DATA, 7, 9, 3, "hello".toByteArray()).encode()
        val encrypted = Wire.crypt(up, ByteArray(12) { it.toByte() }, plain, "up", true)
        assertArrayEquals(hex("cf0a6f827e860f0a565ee44c8fb083f6eb9e11bf7d343435eaf4e2bd355b2cc5a4d69565b8ff7cfa54194a7d"), encrypted)
        assertArrayEquals(plain, Wire.crypt(up, ByteArray(12) { it.toByte() }, encrypted, "up", false))
        try { Wire.crypt(up, ByteArray(12), encrypted, "down", false); fail("wrong direction authenticated") } catch (_: org.bouncycastle.crypto.InvalidCipherTextException) { }
    }
    @Test fun nameBudgetAndUniqueness() {
        assertEquals("mzxw6", Wire.b32("foo".toByteArray()))
        for (domain in listOf("tunnel.example.ru", "tunnel." + "x".repeat(60) + ".example.ru")) {
            val c = CryptoSession("secret-password-at-least-16", domain)
            val f = Frame(Wire.DATA, 1, data = ByteArray(c.maxUp()))
            val a = c.name(f); val b = c.name(f)
            assertNotEquals(a, b); assertTrue(a.length + 2 <= 255)
            assertTrue(a.split('.').all { it.length <= 63 })
            try { c.name(f.copy(data = ByteArray(c.maxUp() + 1))); fail("oversized QNAME") } catch (_: IllegalArgumentException) { }
            val query = Dns.query(42, a, 16)
            assertArrayEquals(hex("00002904d0000000000000"), query.takeLast(11).toByteArray())
        }
    }
    @Test fun malformedDoesNotDecode() {
        val c = CryptoSession("secret-password-at-least-16", "tunnel.example.ru")
        repeat(512) { size ->
            val raw = ByteArray(size) { (it * 37).toByte() }
            try { Dns.answer(raw, 12, "x.tunnel.example.ru", 16); fail("foreign reply accepted") } catch (_: IllegalArgumentException) { }
        }
        try { Frame.decode(ByteArray(1)); fail("short frame") } catch (_: IllegalArgumentException) { }
        val f = Frame(Wire.DATA, 1, data = byteArrayOf(3)).encode()
        try { Frame.decode(f + 1.toByte()); fail("trailing bytes") } catch (_: IllegalArgumentException) { }
    }
}
