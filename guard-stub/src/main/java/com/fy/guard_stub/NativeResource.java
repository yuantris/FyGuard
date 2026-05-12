package com.fy.guard_stub;

import android.content.Context;

/**
 * NativeResource — 运行时资源解密桥接
 *
 * 与 buildSrc ResourceEncryptor 配合使用。
 *
 * 构建时 ResourceEncryptor 将敏感资源加密为 .fyr 格式：
 *   config.json → config.fyr
 *   secret.key  → secret.fyr
 *
 * 运行时通过此类获取解密后的内容。
 *
 * 使用示例：
 *   // 在代码中需要读取加密资源时
 *   byte[] data = NativeResource.decryptAsset(context, "config.json");
 *   if (data != null) {
 *       String json = new String(data, "UTF-8");
 *       // 使用解密后的 JSON...
 *   }
 *
 * 注意：
 *   资源解密密钥在 JNI_OnLoad 中自动派生并设置，
 *   通常不需要手动调用 initKey()。
 */
public class NativeResource {

    /**
     * 初始化资源解密密钥
     *
     * 通常不需要手动调用，密钥在 JNI_OnLoad 中已自动设置。
     * 仅在需要外部注入密钥的场景下使用。
     *
     * @param context Application context
     * @param key     32 字节 AES-256 密钥
     */
    public static native void initKey(Context context, byte[] key);

    /**
     * 解密并获取资源内容
     *
     * 自动将资源路径转换为加密路径：
     *   "config.json" → 查找 assets "config.fyr"
     *   "data/secret.key" → 查找 assets "data/secret.fyr"
     *
     * 加密文件格式 (.fyr):
     *   magic(4):     "FYR\0"
     *   name_len(2):  文件名长度
     *   name(N):      文件名
     *   iv(16):       AES IV
     *   ciphertext:   加密数据
     *
     * @param context    Application context
     * @param assetPath  原始资源路径（如 "config.json"）
     * @return 解密后的字节数组，失败返回 null
     */
    public static native byte[] decryptAsset(Context context, String assetPath);

    /**
     * 便捷方法：解密资源并返回 String
     *
     * @param context   Application context
     * @param assetPath 资源路径
     * @param charset   字符编码（如 "UTF-8"）
     * @return 解密后的字符串，失败返回 null
     */
    public static String decryptAssetAsString(Context context, String assetPath, String charset) {
        try {
            byte[] data = decryptAsset(context, assetPath);
            if (data != null) {
                return new String(data, charset);
            }
        } catch (Exception e) {
            android.util.Log.e("FY_RES", "decryptAssetAsString failed", e);
        }
        return null;
    }

    /**
     * 便捷方法：解密 JSON 资源
     *
     * @param context   Application context
     * @param assetPath 资源路径（如 "config.json"）
     * @return 解密后的 JSON 字符串，失败返回 null
     */
    public static String decryptJson(Context context, String assetPath) {
        return decryptAssetAsString(context, assetPath, "UTF-8");
    }
}
