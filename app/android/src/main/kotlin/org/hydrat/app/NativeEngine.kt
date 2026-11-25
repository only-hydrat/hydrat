package org.hydrat.app

import android.content.Context
import android.system.Os
import java.io.File

internal object NativeEngine {
    init { System.loadLibrary("hydrat") }

    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        val directory = File(context.noBackupFilesDir, "h")
        check(directory.isDirectory || directory.mkdir())
        Os.chmod(directory.path, 0b111000000)
        val geo = File(directory, "geo")
        check(geo.isDirectory || geo.mkdir())
        for (asset in listOf("geoip.dat", "geosite.dat")) {
            val destination = File(geo, asset)
            val pending = File(geo, "$asset.tmp")
            context.assets.open(asset).use { source ->
                pending.outputStream().use { target -> source.copyTo(target) }
            }
            Os.rename(pending.path, destination.path)
        }
        val binaries = File(context.applicationInfo.nativeLibraryDir)
        val tor = File(binaries, "libtor.so")
        val lyrebird = File(binaries, "liblyrebird.so")
        check(tor.canExecute() && lyrebird.canExecute())
        check(open(directory.path, tor.path, lyrebird.path, geo.path) == 0)
        check(setHWID(ConnectionPreferences(context).hwid))
        initialized = true
    }

    private var initialized = false
    private external fun open(directory: String, tor: String, lyrebird: String, geo: String): Int
    external fun importSources(input: ByteArray, hwid: String): String?
    external fun status(): ByteArray?
    external fun refreshSources(): String?
    external fun checkUpdate(): String?
    external fun importSuggested(): String?
    external fun prepare(): Int
    external fun removeSource(id: String): Boolean
    external fun setHWID(value: String): Boolean
    external fun setSourceHWID(id: String, value: String): String?
    external fun sourceHWID(id: String): String?
    external fun geoSettings(): String?
    external fun saveGeoSettings(settings: String): String?
    external fun setScreenInteractive(interactive: Boolean)
    external fun run(tunFD: Int, dnsPreset: Int, geoRules: Boolean, settings: String): Int
    external fun stop()
}
