package com.github.kr328.clash.common.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

class PcapFilesTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val dir: File get() = File(tmp.root, "TunPcap")
    private val files: PcapFiles get() = PcapFiles(dir)

    @Test
    fun createWritesToPartFileUntilFinished() {
        val part = files.create("x.pcap")

        assertEquals(File(dir, "x.pcap.part"), part)
        assertTrue(part.exists())
        assertFalse(files.final("x.pcap").exists())
    }

    @Test
    fun finishRenamesPartToFinalName() {
        files.create("x.pcap").writeText("data")
        files.finish("x.pcap")

        assertFalse(File(dir, "x.pcap.part").exists())
        assertEquals("data", files.final("x.pcap").readText())
    }

    @Test
    fun existsCountsUnfinishedCaptures() {
        assertFalse(files.exists("x.pcap"))
        files.create("x.pcap")
        assertTrue(files.exists("x.pcap"))
    }

    @Test(expected = IOException::class)
    fun createRefusesExistingFinalFile() {
        files.create("x.pcap")
        files.finish("x.pcap")
        files.create("x.pcap")
    }

    @Test(expected = IOException::class)
    fun createRefusesExistingPartFile() {
        files.create("x.pcap")
        files.create("x.pcap")
    }

    @Test(expected = IOException::class)
    fun finishWithoutPartFails() {
        dir.mkdirs()
        files.finish("missing.pcap")
    }
}
