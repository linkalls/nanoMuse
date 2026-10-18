package com.openminis.app.auth

import okhttp3.Dns
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Prefer Android's currently active network DNS (including VPN/private DNS)
 * over Java's process-global resolver, which can use a stale or unrelated
 * network after returning from a browser-based login. Keep system DNS as a
 * fallback; do NOT bypass user DNS/privacy policies via public DNS services.
 *
 * The injected resolvers make this testable with no real network requests.
 */
internal class AndroidActiveNetworkDns(
    private val activeNetworkLookup: (String) -> List<InetAddress>?,
    private val systemLookup: (String) -> List<InetAddress> = Dns.SYSTEM::lookup,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        var activeError: UnknownHostException? = null
        try {
            activeNetworkLookup(hostname)?.takeIf { it.isNotEmpty() }?.let { return it }
        } catch (e: UnknownHostException) {
            activeError = e
        } catch (_: SecurityException) {
            // Network access might be restricted by device policy; try system.
        }
        try {
            return systemLookup(hostname)
        } catch (e: UnknownHostException) {
            activeError?.let { e.addSuppressed(it) }
            throw e
        }
    }
}
