package com.openminis.app.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.InetAddress
import java.net.UnknownHostException

class AndroidActiveNetworkDnsTest {
    @Test fun preferActiveNetwork() {
        val expected = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val dns = AndroidActiveNetworkDns({ listOf(expected) }, { error("system should not be used") })
        assertEquals(listOf(expected), dns.lookup("auth.openai.com"))
    }

    @Test fun useSystemDnsWhenActiveNetworkFails() {
        val expected = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val dns = AndroidActiveNetworkDns(
            { throw UnknownHostException("active network unavailable") },
            { listOf(expected) },
        )
        assertEquals(listOf(expected), dns.lookup("auth.openai.com"))
    }

    @Test fun reportErrorWhenBothResolversFail() {
        val dns = AndroidActiveNetworkDns(
            { throw UnknownHostException("active network unavailable") },
            { throw UnknownHostException("system resolver unavailable") },
        )
        val failure = assertThrows(UnknownHostException::class.java) { dns.lookup("auth.openai.com") }
        assertEquals(1, failure.suppressed.size)
    }
}
