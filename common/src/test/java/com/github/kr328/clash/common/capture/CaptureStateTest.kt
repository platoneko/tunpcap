package com.github.kr328.clash.common.capture

import com.github.kr328.clash.common.store.StoreProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private class MemoryStoreProvider : StoreProvider {
    private val values = mutableMapOf<String, Any>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> get(key: String, defaultValue: T): T = (values[key] as T?) ?: defaultValue

    override fun getInt(key: String, defaultValue: Int) = get(key, defaultValue)
    override fun setInt(key: String, value: Int) { values[key] = value }
    override fun getLong(key: String, defaultValue: Long) = get(key, defaultValue)
    override fun setLong(key: String, value: Long) { values[key] = value }
    override fun getString(key: String, defaultValue: String) = get(key, defaultValue)
    override fun setString(key: String, value: String) { values[key] = value }
    override fun getStringSet(key: String, defaultValue: Set<String>) = get(key, defaultValue)
    override fun setStringSet(key: String, value: Set<String>) { values[key] = value }
    override fun getBoolean(key: String, defaultValue: Boolean) = get(key, defaultValue)
    override fun setBoolean(key: String, value: Boolean) { values[key] = value }
}

class CaptureStateTest {
    private val provider = MemoryStoreProvider()
    private val session = CaptureSession(setOf("com.a", "com.b"), "x.pcap")

    // Two views over the same storage, like CaptureCtrl (app) and TunService (:background).
    private val ctrl = CaptureState(provider)
    private val service = CaptureState(provider)

    @Test
    fun requestIsTakenOnceByTheService() {
        ctrl.request(session)
        assertEquals(session, ctrl.pending())

        assertEquals(session, service.take())
        assertTrue(ctrl.active)
        assertNull(ctrl.pending())

        // A later start without a new request is a normal proxy start.
        service.clear()
        assertNull(service.take())
    }

    @Test
    fun normalStartClearsStaleActiveFlag() {
        ctrl.request(session)
        service.take()
        // Process killed here: onDestroy never cleared the flag.

        assertNull(service.take())
        assertFalse(ctrl.active)
    }

    @Test
    fun clearCancelsPendingRequest() {
        ctrl.request(session)
        ctrl.clear()

        assertNull(ctrl.pending())
        assertNull(service.take())
        assertFalse(ctrl.active)
    }

    @Test
    fun newRequestReplacesPendingOne() {
        ctrl.request(session)
        val newer = CaptureSession(setOf("com.c"), "y.pcap")
        ctrl.request(newer)

        assertEquals(newer, service.take())
    }
}
