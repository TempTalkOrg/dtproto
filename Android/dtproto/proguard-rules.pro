# Keep all UniFFI generated classes
-keep class uniffi.dtproto.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
