package com.fy.guard;

import android.app.Application;
import android.util.Log;

/**
 * 用户的真实 Application
 *
 * 这个类在加固前后保持不变。
 * 加固时，Gradle 插件会：
 *   1. 在 AndroidManifest.xml 中记录此类的类名
 *   2. 将 Application 替换为 StubApplication
 *   3. StubApplication 在运行时从解密的 DEX 中加载此类
 *   4. 委托所有生命周期回调到此类
 *
 * 所以这里的 onCreate、onLowMemory 等方法都会被正常调用。
 */
public class MyApplication extends Application {

    private static final String TAG = "MyApp";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "========================================");
        Log.i(TAG, "  MyApplication.onCreate()");
        Log.i(TAG, "  This is the REAL application running");
        Log.i(TAG, "  All code is loaded from encrypted DEX");
        Log.i(TAG, "========================================");

        // 这里可以放置你的正常初始化逻辑
        // 例如：初始化 SDK、数据库、网络库等
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        Log.w(TAG, "onLowMemory: releasing caches...");
    }
}

