package ru.darkprince.krot

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class Config(val domain: String, val password: String, val nameserver: String = "", val recordType: Int = 16,
                  val pipeline: Int = 12, val maxResponse: Int = 900, val socksPort: Int = 1080, val lan: Boolean = false) {
    fun validate() {
        require(domain.startsWith("tunnel.") && domain.length <= 90 && domain.split('.').all { it.matches(Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) }) { "Введите зону tunnel.example.ru (до 90 символов)" }
        require(password.length >= 16) { "Пароль: минимум 16 символов" }
        if (nameserver.isNotEmpty()) {
            val ipv4 = nameserver.split('.')
            val numeric = if (':' in nameserver) nameserver.matches(Regex("[0-9a-fA-F:.%]+")) && runCatching { java.net.InetAddress.getByName(nameserver) }.isSuccess
                else ipv4.size == 4 && ipv4.all { part -> part.isNotEmpty() && part.all(Char::isDigit) && (part.toIntOrNull() ?: -1) in 0..255 }
            require(numeric) { "Nameserver должен быть корректным IP, не именем" }
        }
        require(recordType in listOf(1, 10, 16) && pipeline in 8..16 && maxResponse in 100..1100 && socksPort in 1024..65535) { "Проверьте числовые настройки" }
    }
    fun save(context: Context) {
        validate()
        context.getSharedPreferences("krot", 0).edit().putString("domain", domain).putString("secret", SecretStore.encrypt(password))
            .putString("nameserver", nameserver).putInt("type", recordType).putInt("pipeline", pipeline)
            .putInt("size", maxResponse).putInt("port", socksPort).putBoolean("lan", lan).apply()
    }
    companion object {
        fun load(context: Context): Config {
            val p = context.getSharedPreferences("krot", 0)
            val secret = try { SecretStore.decrypt(p.getString("secret", "")!!) } catch (_: Exception) { "" }
            return Config(p.getString("domain", "tunnel.example.ru")!!, secret, p.getString("nameserver", "")!!,
                p.getInt("type", 16), p.getInt("pipeline", 12), p.getInt("size", 900), p.getInt("port", 1080), p.getBoolean("lan", false))
        }
    }
}

private object SecretStore {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return (store.getKey("krot-password", null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("krot-password", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun encrypt(text: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key())
        return Base64.getEncoder().encodeToString(c.iv + c.doFinal(text.toByteArray(Charsets.UTF_8)))
    }
    fun decrypt(text: String): String {
        if (text.isEmpty()) return ""
        val raw = Base64.getDecoder().decode(text); require(raw.size >= 28)
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        return String(c.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8)
    }
}
