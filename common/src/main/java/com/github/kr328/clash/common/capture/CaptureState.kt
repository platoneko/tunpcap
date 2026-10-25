package com.github.kr328.clash.common.capture

import com.github.kr328.clash.common.store.Store
import com.github.kr328.clash.common.store.StoreProvider

data class CaptureSession(val packages: Set<String>, val pcapName: String)

/**
 * Capture handoff between CaptureCtrl (app process) and TunService (:background),
 * over the shared multi-process preferences.
 *
 * A capture starts only from an explicit request that TunService consumes once;
 * every other TunService start (UI, tile, boot, external control) clears leftovers
 * of a killed capture instead of silently becoming one.
 */
class CaptureState(provider: StoreProvider) {
    private val store = Store(provider)

    private var requested by store.boolean(key = "capture_requested", defaultValue = false)
    private var packages by store.stringSet(key = "capture_packages", defaultValue = emptySet())
    private var pcapName by store.string(key = "capture_pcap_name", defaultValue = "")

    /** A capture session is running (set by [take], cleared by [clear]). */
    var active by store.boolean(key = "capture_active", defaultValue = false)
        private set

    fun request(session: CaptureSession) {
        packages = session.packages
        pcapName = session.pcapName
        // Flag last, so a reader never sees a request with stale details.
        requested = true
    }

    /** The request waiting for TunService, e.g. while the VPN consent dialog is up. */
    fun pending(): CaptureSession? = if (requested) CaptureSession(packages, pcapName) else null

    /** Called once per TunService start: the session to capture, or null for a normal start. */
    fun take(): CaptureSession? {
        if (!requested) {
            clear()
            return null
        }
        requested = false
        active = true
        return CaptureSession(packages, pcapName)
    }

    fun clear() {
        requested = false
        active = false
        packages = emptySet()
        pcapName = ""
    }
}
