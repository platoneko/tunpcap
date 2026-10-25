package com.github.kr328.clash.common.capture

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** logcat tag for every capture start/stop/reject line; host tooling greps for it. */
const val CAPTURE_LOG_TAG = "TunPcap"

sealed interface CaptureCommand {
    data class Start(val packages: List<String>, val pcapName: String) : CaptureCommand
    object Stop : CaptureCommand
}

class CaptureRequestException(message: String) : Exception(message)

/**
 * Parses the PCAPdroid CaptureCtrl-style extras accepted by TunPcap.
 * Extras PCAPdroid supports but TunPcap does not need (socks5_*, full_payload, ...)
 * are ignored: the egress comes from the Clash config and payloads are always full.
 */
object CaptureRequest {
    fun parse(getString: (String) -> String?, now: Date): CaptureCommand {
        return when (val action = getString("action")) {
            "start" -> parseStart(getString, now)
            "stop" -> CaptureCommand.Stop
            else -> throw CaptureRequestException("unknown action: $action")
        }
    }

    private fun parseStart(getString: (String) -> String?, now: Date): CaptureCommand.Start {
        val packages = getString("app_filter").orEmpty()
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        if (packages.isEmpty())
            throw CaptureRequestException("app_filter is required")

        val dumpMode = getString("pcap_dump_mode")
        if (dumpMode != null && dumpMode != "pcap_file")
            throw CaptureRequestException("unsupported pcap_dump_mode: $dumpMode")

        val name = getString("pcap_name")
            ?: "capture_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(now)}.pcap"
        if (name.contains('/') || name.startsWith('.'))
            throw CaptureRequestException("invalid pcap_name: $name")

        return CaptureCommand.Start(packages, name)
    }
}
