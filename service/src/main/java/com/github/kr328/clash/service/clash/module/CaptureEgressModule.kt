package com.github.kr328.clash.service.clash.module

import android.app.Service
import android.util.Log
import com.github.kr328.clash.common.capture.CAPTURE_LOG_TAG
import com.github.kr328.clash.common.constants.Intents
import com.github.kr328.clash.core.Clash
import com.github.kr328.clash.core.model.ProxySort
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel

/**
 * Capture mode forces global mode, so every packet of the captured apps leaves
 * through whatever GLOBAL selects. Refuse to run when that is not a proxy.
 */
class CaptureEgressModule(service: Service) : Module<CaptureEgressModule.Rejected>(service) {
    data class Rejected(val message: String)

    /** Completes once a loaded profile passed the check; TunService opens the VPN only then. */
    val ready = CompletableDeferred<Unit>()

    // Registered at construction, i.e. before ConfigurationModule exists, so the
    // first PROFILE_LOADED broadcast cannot be missed.
    private val loaded = receiveBroadcast(capacity = Channel.CONFLATED) {
        addAction(Intents.ACTION_PROFILE_LOADED)
    }

    override suspend fun run() {
        while (true) {
            loaded.receive()

            val now = runCatching { Clash.queryGroup(GLOBAL_GROUP, ProxySort.Default).now }
                .getOrDefault("")
            if (now.isEmpty() || now.uppercase() in NON_PROXY_OUTBOUNDS) {
                val message = "rejected: GLOBAL selects ${now.ifEmpty { "<none>" }}"
                Log.e(CAPTURE_LOG_TAG, message)
                return enqueueEvent(Rejected(message))
            }

            Log.i(CAPTURE_LOG_TAG, "egress GLOBAL=$now mode=${Clash.queryTunnelState().mode}")
            ready.complete(Unit)
        }
    }

    companion object {
        private const val GLOBAL_GROUP = "GLOBAL"
        private val NON_PROXY_OUTBOUNDS = setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE")
    }
}
