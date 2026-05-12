package com.fy.guard;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * 示例 Activity
 *
 * 展示加固后的 App 正常运行。
 * 这个类的字节码会被加密保护。
 */
public class MainActivity extends Activity {

    private static final String TAG = "MyApp";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "MainActivity.onCreate() — loaded from encrypted DEX");

        // 构建简单的 UI（不依赖 XML 布局）
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(64, 64, 64, 64);

        // 标题
        TextView title = new TextView(this);
        title.setText("FY Guard Demo");
        title.setTextSize(28);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // 间距
        TextView spacer = new TextView(this);
        spacer.setText("\n");
        root.addView(spacer);

        // 状态信息
        TextView status = new TextView(this);
        status.setText("App is running with encrypted DEX protection.\n\n"
                + "This Activity's bytecode is protected.\n"
                + "Frida dump will only see stub code.");
        status.setTextSize(16);
        status.setGravity(Gravity.CENTER);
        root.addView(status);

        // 间距
        TextView spacer2 = new TextView(this);
        spacer2.setText("\n");
        root.addView(spacer2);

        // 安全状态
        TextView security = new TextView(this);
        try {
            int checkResult = com.fy.guard_stub.NativeLoader.nativeSecurityCheck(this);
            String statusText;
            switch (checkResult) {
                case 0: statusText = "SECURE — no threats detected"; break;
                case 1: statusText = "WARNING — debugger detected"; break;
                case 2: statusText = "WARNING — Frida/Xposed detected"; break;
                case 3: statusText = "WARNING — integrity check failed"; break;
                default: statusText = "UNKNOWN (" + checkResult + ")"; break;
            }
            security.setText("Security status: " + statusText);
        } catch (Exception e) {
            security.setText("Security check: " + e.getMessage());
        }
        security.setTextSize(14);
        security.setGravity(Gravity.CENTER);
        root.addView(security);

        // 间距
        TextView spacer3 = new TextView(this);
        spacer3.setText("\n");
        root.addView(spacer3);

        // 页面大小信息
        TextView pageInfo = new TextView(this);
        try {
            String info = com.fy.guard_stub.NativeLoader.nativeGetPageInfo();
            pageInfo.setText("Native info: " + info);
        } catch (Exception e) {
            pageInfo.setText("Native info: unavailable");
        }
        pageInfo.setTextSize(12);
        pageInfo.setGravity(Gravity.CENTER);
        root.addView(pageInfo);

        setContentView(root);
    }
}
