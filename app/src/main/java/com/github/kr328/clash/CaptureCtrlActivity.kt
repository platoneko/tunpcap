package com.github.kr328.clash

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import com.github.kr328.clash.common.capture.CAPTURE_LOG_TAG
import com.github.kr328.clash.common.capture.CaptureCommand
import com.github.kr328.clash.common.capture.CaptureRequest
import com.github.kr328.clash.common.capture.CaptureRequestException
import com.github.kr328.clash.common.compat.startForegroundServiceCompat
import com.github.kr328.clash.common.util.intent
import com.github.kr328.clash.remote.StatusClient
import com.github.kr328.clash.service.TunService
import com.github.kr328.clash.service.capture.PcapOutput
import com.github.kr328.clash.service.store.ServiceStore
import com.github.kr328.clash.util.stopClashService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.Date

/**
 * adb-only capture control, PCAPdroid CaptureCtrl style:
 *   am start -n <pkg>/.CaptureCtrl --es action start --es app_filter <pkgs> [--es pcap_name x.pcap]
 *   am start -n <pkg>/.CaptureCtrl --es action stop
 * Reached through the exported <pkg>.CaptureCtrl alias guarded by android.permission.DUMP,
 * which adb shell holds and ordinary apps cannot obtain. Every outcome is one logcat line.
 */
class CaptureCtrlActivity : Activity(), CoroutineScope by MainScope() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        overridePendingTransition(0, 0)

        val command = try {
            CaptureRequest.parse(intent::getStringExtra, Date())
        } catch (e: CaptureRequestException) {
            Log.e(CAPTURE_LOG_TAG, "rejected: ${e.message}")
            return finish()
        }

        when (command) {
            CaptureCommand.Stop -> {
                stop()
                finish()
            }
            is CaptureCommand.Start -> launch {
                // Stay open only while the system VPN consent dialog is up.
                if (!start(command)) finish()
            }
        }
    }

    private fun stop() {
        if (ServiceStore(this).captureActive) {
            stopClashService()
            Log.i(CAPTURE_LOG_TAG, "stop requested")
        } else {
            Log.i(CAPTURE_LOG_TAG, "stop: not capturing")
        }
    }

    /** Returns true when waiting for the VPN consent result. */
    private suspend fun start(command: CaptureCommand.Start): Boolean {
        val store = ServiceStore(this)

        command.packages.firstOrNull { !isInstalled(it) }?.let {
            return reject("package not installed: $it")
        }

        val running = isClashRunning()
        if (store.captureActive) {
            if (running)
                return reject("already capturing")
            // Left over by a killed process; TunService never got to clear it.
            store.clearCapture()
        }

        val file = PcapOutput.file(command.pcapName)
        if (file.exists())
            return reject("file exists: $file")

        if (running) {
            stopClashService()
            if (!waitStopped())
                return reject("could not stop running proxy")
        }

        store.captureActive = true
        store.capturePackages = command.packages.toSet()
        store.capturePcapName = command.pcapName

        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_CONSENT)
            return true
        }

        launchCapture()
        return false
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN_CONSENT)
            return

        if (resultCode == RESULT_OK) {
            launchCapture()
        } else {
            ServiceStore(this).clearCapture()
            Log.e(CAPTURE_LOG_TAG, "rejected: vpn consent denied")
        }
        finish()
    }

    private fun launchCapture() {
        startForegroundServiceCompat(TunService::class.intent)
        Log.i(CAPTURE_LOG_TAG, "start requested")
    }

    private fun reject(message: String): Boolean {
        Log.e(CAPTURE_LOG_TAG, "rejected: $message")
        return false
    }

    private fun isInstalled(packageName: String): Boolean = try {
        packageManager.getPackageInfo(packageName, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    private fun isClashRunning(): Boolean = StatusClient(this).currentProfile() != null

    private suspend fun waitStopped(): Boolean {
        repeat(STOP_POLLS) {
            if (!isClashRunning()) return true
            delay(STOP_POLL_MS)
        }
        return !isClashRunning()
    }

    override fun finish() {
        super.finish()
        @Suppress("DEPRECATION")
        overridePendingTransition(0, 0)
    }

    companion object {
        private const val REQUEST_VPN_CONSENT = 1
        private const val STOP_POLL_MS = 200L
        private const val STOP_POLLS = 25 // 5 s
    }
}
