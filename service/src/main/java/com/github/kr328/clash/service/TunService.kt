package com.github.kr328.clash.service

import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.github.kr328.clash.common.capture.CAPTURE_LOG_TAG
import com.github.kr328.clash.common.capture.CaptureSession
import com.github.kr328.clash.common.compat.pendingIntentFlags
import com.github.kr328.clash.common.constants.Components
import com.github.kr328.clash.common.log.Log
import com.github.kr328.clash.core.Clash
import com.github.kr328.clash.core.model.ConfigurationOverride
import com.github.kr328.clash.core.model.TunnelState
import com.github.kr328.clash.service.capture.PcapOutput
import com.github.kr328.clash.service.clash.clashRuntime
import com.github.kr328.clash.service.clash.module.*
import com.github.kr328.clash.service.model.AccessControlMode
import com.github.kr328.clash.service.store.ServiceStore
import com.github.kr328.clash.service.util.cancelAndJoinBlocking
import com.github.kr328.clash.service.util.parseCIDR
import com.github.kr328.clash.service.util.sendClashStarted
import com.github.kr328.clash.service.util.sendClashStopped
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select

class TunService : VpnService(), CoroutineScope by CoroutineScope(Dispatchers.Default) {
    private val self: TunService
        get() = this

    private var reason: String? = null

    // Set once the capture's .part file exists; onDestroy publishes it after the flush.
    @Volatile
    private var capturePcapName: String? = null

    private val runtime = clashRuntime {
        val store = ServiceStore(self)

        // Only an explicit CaptureCtrl request makes this start a capture; any
        // other start also clears leftovers of a killed capture.
        val capture = store.capture.take()

        // Capture: global mode via the session override, which the runtime clears
        // on start and on exit, so the user's own mode comes back after stop.
        // Must be patched before ConfigurationModule loads the profile.
        val egress = if (capture != null) {
            Clash.patchOverride(
                Clash.OverrideSlot.Session,
                ConfigurationOverride(mode = TunnelState.Mode.Global)
            )
            install(CaptureEgressModule(self))
        } else null

        val close = install(CloseModule(self))
        val tun = install(TunModule(self))
        val config = install(ConfigurationModule(self))
        val network = install(NetworkObserveModule(self))

        if (store.dynamicNotification)
            install(DynamicNotificationModule(self))
        else
            install(StaticNotificationModule(self))

        install(AppListCacheModule(self))
        install(TimeZoneModule(self))
        install(SuspendModule(self))

        try {
            // Capture: no VPN until the profile is loaded and GLOBAL verified. Until
            // then the core runs an empty rule-mode config that sends everything
            // DIRECT, which would leak the captured apps' first connections.
            if (egress != null) {
                val proceed = select<Boolean> {
                    close.onEvent { false }
                    config.onEvent {
                        reason = it.message

                        false
                    }
                    egress.onEvent {
                        reason = it.message

                        false
                    }
                    egress.ready.onAwait { true }
                }

                if (!proceed) return@clashRuntime
            }

            tun.open(capture)

            while (isActive) {
                val quit = select<Boolean> {
                    close.onEvent {
                        true
                    }
                    config.onEvent {
                        reason = it.message

                        true
                    }
                    egress?.onEvent {
                        reason = it.message

                        true
                    }
                    network.onEvent { n ->
                        if (Build.VERSION.SDK_INT in 22..28) @TargetApi(22) {
                            setUnderlyingNetworks(n?.let { arrayOf(it) })
                        }

                        false
                    }
                }

                if (quit) break
            }
        } catch (e: Exception) {
            Log.e("Create clash runtime: ${e.message}", e)

            reason = e.message
        } finally {
            withContext(NonCancellable) {
                tun.close()

                stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()

        if (StatusProvider.serviceRunning)
            return stopSelf()

        StatusProvider.serviceRunning = true

        StaticNotificationModule.createNotificationChannel(this)
        StaticNotificationModule.notifyLoadingNotification(this)

        runtime.launch()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        sendClashStarted()

        return super.onStartCommand(intent, flags, startId)
    }

    override fun onDestroy() {
        // Also the path for VpnService.onRevoke (its default calls stopSelf):
        // stopping the tun flushes and closes the pcap, only then is it published.
        TunModule.requestStop()

        capturePcapName?.let { name ->
            try {
                PcapOutput.files.finish(name)
                android.util.Log.i(CAPTURE_LOG_TAG, "stopped file=${PcapOutput.files.final(name)}: ${reason ?: "requested"}")
            } catch (e: Exception) {
                android.util.Log.e(CAPTURE_LOG_TAG, "stopped, but ${e.message}")
            }
        }
        ServiceStore(this).capture.let { capture ->
            if (capture.active) capture.clear()
        }

        StatusProvider.serviceRunning = false

        sendClashStopped(reason)

        cancelAndJoinBlocking()

        Log.i("TunService destroyed: ${reason ?: "successfully"}")

        super.onDestroy()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)

        runtime.requestGc()
    }

    private fun TunModule.open(capture: CaptureSession?) {
        val store = ServiceStore(self)

        if (capture != null)
            return openCapture(capture, store)

        val device = with(Builder()) {
            // Interface address
            addAddress(TUN_GATEWAY, TUN_SUBNET_PREFIX)
            if (store.allowIpv6) {
                addAddress(TUN_GATEWAY6, TUN_SUBNET_PREFIX6)
            }

            // Route
            if (store.bypassPrivateNetwork) {
                resources.getStringArray(R.array.bypass_private_route).map(::parseCIDR).forEach {
                    addRoute(it.ip, it.prefix)
                }
                if (store.allowIpv6) {
                    resources.getStringArray(R.array.bypass_private_route6).map(::parseCIDR).forEach {
                        addRoute(it.ip, it.prefix)
                    }
                }

                // Route of virtual DNS
                addRoute(TUN_DNS, 32)
                if (store.allowIpv6) {
                    addRoute(TUN_DNS6, 128)
                }
            } else {
                addRoute(NET_ANY, 0)
                if (store.allowIpv6) {
                    addRoute(NET_ANY6, 0)
                }
            }

            // Access Control
            when (store.accessControlMode) {
                AccessControlMode.AcceptAll -> Unit
                AccessControlMode.AcceptSelected -> {
                    (store.accessControlPackages + packageName).forEach {
                        runCatching { addAllowedApplication(it) }
                    }
                }
                AccessControlMode.DenySelected -> {
                    (store.accessControlPackages - packageName).forEach {
                        runCatching { addDisallowedApplication(it) }
                    }
                }
            }

            // Blocking
            setBlocking(false)

            // Mtu
            setMtu(TUN_MTU)

            // Session Name
            setSession("Clash")

            // Virtual Dns Server
            addDnsServer(TUN_DNS)
            if (store.allowIpv6) {
                addDnsServer(TUN_DNS6)
            }

            // Open MainActivity
            setConfigureIntent(
                PendingIntent.getActivity(
                    self,
                    R.id.nf_vpn_status,
                    Intent().setComponent(Components.MAIN_ACTIVITY),
                    pendingIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
                )
            )

            // Metered
            if (Build.VERSION.SDK_INT >= 29) {
                setMetered(false)
            }

            // System Proxy
            if (Build.VERSION.SDK_INT >= 29 && store.systemProxy) {
                listenHttp()?.let {
                    setHttpProxy(
                        ProxyInfo.buildDirectProxy(
                            it.address.hostAddress,
                            it.port,
                            HTTP_PROXY_BLACK_LIST + if (store.bypassPrivateNetwork) HTTP_PROXY_LOCAL_LIST else emptyList()
                        )
                    )
                }
            }

            if (store.allowBypass) {
                allowBypass()
            }

            TunModule.TunDevice(
                fd = establish()?.detachFd()
                    ?: throw NullPointerException("Establish VPN rejected by system"),
                stack = store.tunStackMode,
                gateway = "$TUN_GATEWAY/$TUN_SUBNET_PREFIX" + if (store.allowIpv6) ",$TUN_GATEWAY6/$TUN_SUBNET_PREFIX6" else "",
                portal = TUN_PORTAL + if (store.allowIpv6) ",$TUN_PORTAL6" else "",
                dns = if (store.dnsHijacking) NET_ANY else (TUN_DNS + if (store.allowIpv6) ",$TUN_DNS6" else ""),
            )
        }

        attach(device)
    }

    // Capture mode ignores the user's network settings on purpose: anything that
    // lets the captured apps' traffic skip the TUN (system HTTP proxy, allowBypass,
    // bypassed private routes) would leave holes in the pcap and change the egress.
    // No IPv6 address or route: Android then blocks IPv6 for these apps, so they
    // fall back to IPv4 instead of leaking around the VPN.
    private fun TunModule.openCapture(capture: CaptureSession, store: ServiceStore) {
        val packages = capture.packages
        val name = capture.pcapName

        try {
            // Without any allowed app Android would route the whole device into the VPN.
            require(packages.isNotEmpty()) { "no apps to capture" }

            val vpnFd = with(Builder()) {
                addAddress(TUN_GATEWAY, TUN_SUBNET_PREFIX)
                addRoute(NET_ANY, 0)
                packages.forEach { addAllowedApplication(it) }
                setBlocking(false)
                setMtu(TUN_MTU)
                setSession(CAPTURE_SESSION)
                addDnsServer(TUN_DNS)
                setConfigureIntent(
                    PendingIntent.getActivity(
                        self,
                        R.id.nf_vpn_status,
                        Intent().setComponent(Components.MAIN_ACTIVITY),
                        pendingIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
                    )
                )
                if (Build.VERSION.SDK_INT >= 29) {
                    setMetered(false)
                }

                establish()?.detachFd() ?: throw NullPointerException("Establish VPN rejected by system")
            }

            val pcapFd = try {
                PcapOutput.open(name).detachFd()
            } catch (e: Exception) {
                ParcelFileDescriptor.adoptFd(vpnFd).close()
                throw e
            }
            capturePcapName = name

            attach(
                TunModule.TunDevice(
                    fd = vpnFd,
                    stack = CAPTURE_STACK,
                    gateway = "$TUN_GATEWAY/$TUN_SUBNET_PREFIX",
                    portal = TUN_PORTAL,
                    dns = if (store.dnsHijacking) NET_ANY else TUN_DNS,
                    pcapFd = pcapFd,
                )
            )
        } catch (e: Exception) {
            android.util.Log.e(CAPTURE_LOG_TAG, "rejected: ${e.message}")
            throw e
        }

        android.util.Log.i(
            CAPTURE_LOG_TAG,
            "started file=${PcapOutput.files.final(name)} apps=${packages.joinToString(",")}"
        )
    }

    companion object {
        private const val CAPTURE_SESSION = "TunPcap"

        // mips never writes rewritten app packets back to the TUN, so the relay
        // in the core sees exactly what the captured apps sent and received.
        private const val CAPTURE_STACK = "mips"

        private const val TUN_MTU = 9000
        private const val TUN_SUBNET_PREFIX = 30
        private const val TUN_GATEWAY = "172.19.0.1"
        private const val TUN_SUBNET_PREFIX6 = 126
        private const val TUN_GATEWAY6 = "fdfe:dcba:9876::1"
        private const val TUN_PORTAL = "172.19.0.2"
        private const val TUN_PORTAL6 = "fdfe:dcba:9876::2"
        private const val TUN_DNS = TUN_PORTAL
        private const val TUN_DNS6 = TUN_PORTAL6
        private const val NET_ANY = "0.0.0.0"
        private const val NET_ANY6 = "::"

        private val HTTP_PROXY_LOCAL_LIST: List<String> = listOf(
            "localhost",
            "*.local",
            "127.*",
            "10.*",
            "172.16.*",
            "172.17.*",
            "172.18.*",
            "172.19.*",
            "172.2*",
            "172.30.*",
            "172.31.*",
            "192.168.*"
        )
        private val HTTP_PROXY_BLACK_LIST: List<String> = listOf(
            "*zhihu.com",
            "*zhimg.com",
            "*jd.com",
            "100ime-iat-api.xfyun.cn",
            "*360buyimg.com",
        )
    }
}
