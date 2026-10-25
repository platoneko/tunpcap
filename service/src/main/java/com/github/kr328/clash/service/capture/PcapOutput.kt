package com.github.kr328.clash.service.capture

import android.os.Environment
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.IOException

/** Where captures land: /sdcard/Download/TunPcap/<name>, pullable with adb. */
object PcapOutput {
    fun dir(): File =
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "TunPcap")

    fun file(name: String): File = File(dir(), name)

    /** Creates a new pcap file; never overwrites an existing capture. */
    fun create(name: String): ParcelFileDescriptor {
        val dir = dir()
        if (!dir.isDirectory && !dir.mkdirs())
            throw IOException("cannot create $dir")

        val file = file(name)
        if (!file.createNewFile())
            throw IOException("file exists: $file")

        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_WRITE_ONLY)
    }
}
