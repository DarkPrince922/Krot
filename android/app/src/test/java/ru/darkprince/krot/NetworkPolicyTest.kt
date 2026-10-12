package ru.darkprince.krot

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class NetworkPolicyTest {
    @Test fun ipv4FirstWithoutInjectingForeignResolvers() {
        val v6 = InetAddress.getByName("2a00:1fa1:ee00:ff::1")
        val v4 = InetAddress.getByName("212.188.31.154")
        val otherV4 = InetAddress.getByName("192.0.2.53")
        assertEquals(listOf(v4, otherV4, v6), ResolverPolicy.systemCandidates(listOf(v6, v4, v6, otherV4)))
        assertTrue(ResolverPolicy.systemCandidates(emptyList()).isEmpty())
        assertEquals(listOf(v6), ResolverPolicy.systemCandidates(listOf(v6)))
        assertEquals(2, ResolverPolicy.helloAttempts(true, v6))
        assertEquals(7, ResolverPolicy.helloAttempts(false, v6))
        assertEquals(7, ResolverPolicy.helloAttempts(true, v4))
    }
    @Test fun retriesGrowDespiteFastParallelTrafficAndHaveABound() {
        assertEquals(7, RpcRetryPolicy.ATTEMPTS)
        val waits = (0 until 7).map { RpcRetryPolicy.timeoutMs(20.0, Wire.DATA, it) }
        assertEquals(listOf(300L, 450L, 675L, 1012L, 1518L, 2278L, 3417L), waits)
        assertEquals(2500L, RpcRetryPolicy.timeoutMs(20.0, Wire.OPEN, 0))
        assertEquals(8000L, RpcRetryPolicy.timeoutMs(5000.0, Wire.DATA, 6))
        assertEquals(8000L, RpcRetryPolicy.timeoutMs(20.0, Wire.OPEN, 6))
        assertEquals(750L, RpcRetryPolicy.timeoutMs(Double.NaN, Wire.DATA, 0))
    }
}
