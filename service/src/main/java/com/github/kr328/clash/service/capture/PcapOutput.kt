package com.github.kr328.clash.service.capture

import android.os.Environment
import android.os.ParcelFileDescriptor
import com.github.kr328.clash.common.capture.PcapFiles
import java.io.File

/** Where captures land: /sdcard/Download/TunPcap/<name>, pullable with adb. */
object PcapOutput {
    val files: PcapFiles
        get() = PcapFiles(
            File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "TunPcap")
        )

    /** Opens `<name>.part` for the core to write; [PcapFiles.finish] publishes it. */
    fun open(name: String): ParcelFileDescriptor =
        ParcelFileDescriptor.open(files.create(name), ParcelFileDescriptor.MODE_WRITE_ONLY)
}
