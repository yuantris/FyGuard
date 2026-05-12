# ============================================================
# FY Guard ProGuard 规则
# ============================================================

# 保留加固壳的入口类（不能被混淆，否则 native 层找不到）
-keep class com.fy.guard_stub.** { *; }

# 保留用户的 Application 类（StubApplication 通过类名反射加载）
-keep class com.example.myapp.MyApplication { *; }

# 保留所有 native 方法（JNI 需要通过方法名查找）
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留 JNI 回调方法
-keep class com.fy.guard_stub.VmBridge {
    public static long nativeInvoke(int, long[], int);
}

# 保留 Activity / Service / Provider / Receiver（Android 框架需要）
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.content.BroadcastReceiver
