[app]
title = PAK TOOL
package.name = paktool
package.domain = com.paktool
source.dir = .
source.include_exts = py,kv
version = 1.0
requirements = python3,kivy,pycryptodome,zstandard,android
orientation = portrait
fullscreen = 0
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 30
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
