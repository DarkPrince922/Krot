package ru.darkprince.krot

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.math.max
import kotlin.math.pow

object ResolverPolicy {
    /** Preserve the operator's addresses and their order within each family. */
    fun systemCandidates(addresses: List<InetAddress>): List<InetAddress> {
        val unique = addresses.distinctBy { it.hostAddress }
        return unique.filterIsInstance<Inet4Address>() + unique.filterIsInstance<Inet6Address>()
    }
    fun helloAttempts(automatic: Boolean, address: InetAddress): Int =
        if (automatic && address is Inet6Address) 2 else RpcRetryPolicy.ATTEMPTS
}

object RpcRetryPolicy {
    const val ATTEMPTS = 7
    const val MAX_TIMEOUT_MS = 8000L
    fun timeoutMs(rttMs: Double, type: Int, attempt: Int): Long {
        require(attempt in 0 until ATTEMPTS)
        val sample = if (rttMs.isFinite() && rttMs >= 0) rttMs else 500.0
        val first = max(if (type == Wire.OPEN) 2500.0 else 300.0, 1.5 * sample)
        return (first * 1.5.pow(attempt)).coerceAtMost(MAX_TIMEOUT_MS.toDouble()).toLong()
    }
}
