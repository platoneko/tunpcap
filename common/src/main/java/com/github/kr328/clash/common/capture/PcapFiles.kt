package com.github.kr328.clash.common.capture

import java.io.File
import java.io.IOException

/**
 * A capture is written to `<name>.part` and renamed to `<name>` only after the
 * pcap is fully flushed, so the final name appearing means the file is complete.
 */
class PcapFiles(private val dir: File) {
    fun final(name: String): File = File(dir, name)

    private fun part(name: String): File = File(dir, "$name$PART_SUFFIX")

    /** A finished or unfinished capture already uses this name. */
    fun exists(name: String): Boolean = final(name).exists() || part(name).exists()

    /** Creates the `.part` file to write to; never reuses an existing name. */
    fun create(name: String): File {
        if (!dir.isDirectory && !dir.mkdirs())
            throw IOException("cannot create $dir")
        if (final(name).exists())
            throw IOException("file exists: ${final(name)}")

        val part = part(name)
        if (!part.createNewFile())
            throw IOException("file exists: $part")
        return part
    }

    fun finish(name: String) {
        val part = part(name)
        if (!part.renameTo(final(name)))
            throw IOException("cannot rename $part to ${final(name)}")
    }

    companion object {
        private const val PART_SUFFIX = ".part"
    }
}
