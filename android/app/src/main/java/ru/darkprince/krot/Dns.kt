package ru.darkprince.krot

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.util.Base64

object Dns {
    private fun labels(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        name.split('.').forEach { val b = it.toByteArray(Charsets.US_ASCII); require(b.size in 1..63); out.write(b.size); out.write(b) }
        out.write(0); require(out.size() <= 255)
        return out.toByteArray()
    }
    fun query(id: Int, name: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream(); val d = DataOutputStream(out)
        d.writeShort(id); d.writeShort(0x0100); d.writeShort(1); d.writeShort(0); d.writeShort(0); d.writeShort(1)
        d.write(labels(name)); d.writeShort(type); d.writeShort(1)
        d.writeByte(0); d.writeShort(41); d.writeShort(1232); d.writeInt(0); d.writeShort(0)
        return out.toByteArray()
    }
    private class Reader(val raw: ByteArray) {
        var pos = 0
        fun byte(): Int { require(pos < raw.size); return raw[pos++].toInt() and 255 }
        fun short(): Int = (byte() shl 8) or byte()
        fun skip(n: Int) { require(n >= 0 && pos + n <= raw.size); pos += n }
        fun name(): String {
            val pieces = mutableListOf<String>(); var cursor = pos; var end = -1; var steps = 0; var wireSize = 1
            while (true) {
                require(cursor < raw.size && ++steps <= 128)
                val n = raw[cursor++].toInt() and 255
                if (n == 0) { if (end < 0) end = cursor; break }
                if (n and 0xc0 == 0xc0) {
                    require(cursor < raw.size)
                    val target = ((n and 63) shl 8) or (raw[cursor++].toInt() and 255)
                    require(target < cursor - 2) // reject forward pointers and cycles
                    if (end < 0) end = cursor
                    cursor = target
                } else {
                    require(n <= 63 && cursor + n <= raw.size)
                    wireSize += n + 1; require(wireSize <= 255)
                    pieces.add(String(raw, cursor, n, Charsets.US_ASCII)); cursor += n
                }
            }
            pos = end
            return pieces.joinToString(".")
        }
    }
    fun answer(raw: ByteArray, id: Int, name: String, type: Int): ByteArray {
        require(raw.size in 12..1232)
        val r = Reader(raw)
        require(r.short() == id)
        val flags = r.short()
        require(flags and 0x8000 != 0 && flags and 0x020f == 0 && flags and 0x7800 == 0)
        require(r.short() == 1)
        val count = r.short(); val authority = r.short(); val additional = r.short()
        require(count in 1..256 && authority + additional <= 256)
        require(r.name().equals(name, true) && r.short() == type && r.short() == 1)
        val fragments = sortedMapOf<Int, ByteArray>(); var payload: ByteArray? = null
        repeat(count) {
            val owner = r.name(); val rt = r.short(); val cls = r.short(); r.skip(4); val len = r.short()
            val begin = r.pos; r.skip(len)
            if (owner.equals(name, true) && rt == type && cls == 1) {
                when (type) {
                    16 -> {
                        require(payload == null)
                        var p = begin; val txt = ByteArrayOutputStream()
                        while (p < begin + len) { val n = raw[p++].toInt() and 255; require(p + n <= begin + len); txt.write(raw, p, n); p += n }
                        payload = Base64.getUrlDecoder().decode(txt.toByteArray())
                    }
                    10 -> { require(payload == null); payload = raw.copyOfRange(begin, begin + len) }
                    1 -> { require(len == 4); val index = raw[begin].toInt() and 255; require(!fragments.containsKey(index)); fragments[index] = raw.copyOfRange(begin + 1, begin + 4) }
                }
            }
        }
        if (type == 1) {
            require(fragments.isNotEmpty() && fragments.keys.toList() == (0 until fragments.size).toList())
            val joined = ByteArrayOutputStream().also { out -> fragments.values.forEach { out.write(it) } }.toByteArray()
            require(joined.size >= 2)
            val len = ByteBuffer.wrap(joined).short.toInt() and 65535
            require(len >= 51 && len <= joined.size - 2 && joined.size - 2 - len < 3)
            payload = joined.copyOfRange(2, len + 2)
        }
        return payload ?: error("Нет данных DNS")
    }
}
