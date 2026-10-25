package com.github.kr328.clash.common.capture

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Calendar
import java.util.Date

class CaptureRequestTest {
    private val now: Date = Calendar.getInstance().apply {
        clear()
        set(2026, Calendar.OCTOBER, 25, 13, 4, 5)
    }.time

    private fun parse(vararg extras: Pair<String, String>): CaptureCommand {
        val map = extras.toMap()
        return CaptureRequest.parse({ map[it] }, now)
    }

    @Test
    fun startWithSinglePackage() {
        assertEquals(
            CaptureCommand.Start(listOf("com.a"), "x.pcap"),
            parse("action" to "start", "app_filter" to "com.a", "pcap_name" to "x.pcap"),
        )
    }

    @Test
    fun startSplitsAndDedupsPackages() {
        val cmd = parse("action" to "start", "app_filter" to " com.a, ,com.b,com.a ", "pcap_name" to "x.pcap")
        assertEquals(listOf("com.a", "com.b"), (cmd as CaptureCommand.Start).packages)
    }

    @Test
    fun defaultPcapName() {
        val cmd = parse("action" to "start", "app_filter" to "com.a")
        assertEquals("capture_20261025_130405.pcap", (cmd as CaptureCommand.Start).pcapName)
    }

    @Test
    fun explicitPcapFileModeAccepted() {
        val cmd = parse("action" to "start", "app_filter" to "com.a", "pcap_dump_mode" to "pcap_file")
        assertEquals(listOf("com.a"), (cmd as CaptureCommand.Start).packages)
    }

    @Test
    fun stopIgnoresOtherExtras() {
        assertEquals(CaptureCommand.Stop, parse("action" to "stop"))
    }

    @Test(expected = CaptureRequestException::class)
    fun missingAppFilter() {
        parse("action" to "start")
    }

    @Test(expected = CaptureRequestException::class)
    fun blankAppFilter() {
        parse("action" to "start", "app_filter" to " , ")
    }

    @Test(expected = CaptureRequestException::class)
    fun unsupportedDumpMode() {
        parse("action" to "start", "app_filter" to "com.a", "pcap_dump_mode" to "http_server")
    }

    @Test(expected = CaptureRequestException::class)
    fun unknownAction() {
        parse("action" to "pause")
    }

    @Test(expected = CaptureRequestException::class)
    fun missingAction() {
        parse("app_filter" to "com.a")
    }

    @Test(expected = CaptureRequestException::class)
    fun pcapNameWithSlash() {
        parse("action" to "start", "app_filter" to "com.a", "pcap_name" to "a/b.pcap")
    }

    @Test(expected = CaptureRequestException::class)
    fun pcapNameStartingWithDot() {
        parse("action" to "start", "app_filter" to "com.a", "pcap_name" to "..pcap")
    }

    @Test
    fun socksExtrasIgnored() {
        assertEquals(
            CaptureCommand.Start(listOf("com.a"), "x.pcap"),
            parse(
                "action" to "start", "app_filter" to "com.a", "pcap_name" to "x.pcap",
                "socks5_enabled" to "true", "socks5_proxy_host" to "127.0.0.1",
            ),
        )
    }
}
