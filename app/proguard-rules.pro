# Keep native method names — exp.c binds to them via JNI.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the app package: exp.c does FindClass("df/root/IReporter") and
# view binding generates df.root.databinding.* referenced reflectively.
-keep class df.root.** { *; }
-keep class df.root.databinding.** { *; }

# Keep click-handler wiring used by Material components.
-keepclassmembers class * {
    void *Click(...);
}

# df.d2.Harness is entered by app_process, not by app code: the launcher names the class in
# argv and app_process is pointed at this APK, so R8 sees no reference to any of it. Without
# this the vault writer is silently shrunk out of a release build.
-keep class df.d2.** { *; }
-dontwarn df.d2.**

-dontwarn df.root.**