#include <jni.h>
#include <string>
#include <android/log.h>
#include <thread>
#include <unistd.h>
#include <link.h>
#include <atomic>
#include <fstream>
#include <sys/stat.h>
#include <shadowhook.h> // 透過 Prefab 引入，使用標準角括號 
// the data u get is a dll!!

// 🎯 依要求修改 TAG
#define TAG "HOOK"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 🎯 目標函數：Framework.Aes.AesDecrypt
// RVA: 0x2fedd30 -> public static Byte[] AesDecrypt(Byte[] dataToDecrypt)
#define TARGET_RVA 0x2fedd30

// --- IL2CPP 底層的 C# Byte 陣列結構定義 ---
struct Il2CppArray {
    void* klass;
    void* monitor;
    void* bounds;
    uintmax_t max_length; // 陣列的長度 (ARM64 下為 64-bit)
    uint8_t vector[0];    // 實際的 byte 數據起始指標
};

// 函數指標定義 (Static 函數無 this 指標，最後一個為 Il2Cpp 隱藏參數 MethodInfo)
typedef Il2CppArray* (*AesDecrypt_t)(Il2CppArray* dataToDecrypt, void* method);
AesDecrypt_t orig_AesDecrypt = nullptr;
void* hook_stub = nullptr;

// 狀態控制：30 秒黃金收割窗
std::atomic<bool> is_harvesting{false};

// --- 檔案存儲邏輯：將解密後的二進位/JSON 數據寫入實體檔案 ---
void save_to_bin(uint8_t* raw_bytes, uintmax_t len) {
    if (!raw_bytes || len <= 0) return;

    // 建立獨立的存檔目錄
    std::string dir = "/data/data/com.habby.capybara/cache/Dumps/";
    mkdir("/data/data/com.habby.capybara/cache/Dumps/", 0777);
    mkdir(dir.c_str(), 0777);

    // 以資料長度命名，避免重複與覆蓋，方便後續排查哪個才是真正的 Config
    std::string path = dir + "decrypted_cfg_" + std::to_string(len) + ".json";

    // 使用 binary 模式寫入原始明文數據
    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (ofs.is_open()) {
        ofs.write((char*)raw_bytes, len);
        ofs.close();
        LOGD("💾 [Harvested] 成功收割 Config -> %s (長度: %lu bytes)", path.c_str(), len);
    }
}

// --- 代理函數：攔截核心 ---
Il2CppArray* proxy_AesDecrypt(Il2CppArray* dataToDecrypt, void* method) {
    // 1. 優先執行原函數，確保遊戲正常加載不卡死
    Il2CppArray* decrypted_array = orig_AesDecrypt(dataToDecrypt, method);

    // 2. 在 30 秒黃金窗內進行數據捕捉
    if (is_harvesting.load() && decrypted_array != nullptr) {
        uintmax_t len = decrypted_array->max_length;
        uint8_t* raw_bytes = decrypted_array->vector;

        // 進行基礎長度過濾（過小的資料通常是密鑰片段或無效快取，Config 通常較大）
        if (len > 100) {
            // 印出前 4 位元組，方便在 Logcat 觀察是否為 JSON 檔案頭（例如 0x7B = '{'）
            LOGD("🔓 [AesDecrypt] 捕獲解密資料 -> 長度: %lu | 標頭: %02X %02X %02X %02X",
                 len, raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]);

            // 執行非同步或直接儲存
            save_to_bin(raw_bytes, len);
        }
    }
    return decrypted_array;
}

// --- JNI 入口與動態注入執行緒 ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("⚡ [JNI_OnLoad] Harvester 模組已成功注入，啟動背景監聽執行緒...");

    // 初始化 ShadowHook
    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);

    std::thread([]() {
        // A. 循環尋找 libil2cpp.so 基址
        uintptr_t base = 0;
        while (base == 0) {
            struct { const char* n; uintptr_t b; } mi = {"libil2cpp.so", 0};
            dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) {
                auto m = (decltype(mi)*)data;
                if (info->dlpi_name && strstr(info->dlpi_name, m->n)) {
                    m->b = (uintptr_t)info->dlpi_addr;
                    return 1;
                }
                return 0;
            }, &mi);
            base = mi.b;
            if (base == 0) usleep(100000); // 100ms 檢查一次
        }

        LOGD("📍 [Step 1] 找到 libil2cpp.so 基址: 0x%lx", base);

        // B. 延遲 5 秒，等待遊戲引擎完成初期記憶體解密與解壓
        // (註：因為換了新目標，原本的固定指紋檢查 FE 67 BC A9 暫時拿掉，改採穩定延遲策略)
        LOGD("⏳ [Step 2] 等待 5 秒進入安全加載期...");
        sleep(5);

        // C. 計算絕對位址並部署 Hook
        uint8_t* target_addr = (uint8_t*)(base + TARGET_RVA);
        LOGD("🚀 [Step 3] 開始對目標位址 0x%lx 部署 ShadowHook...", (uintptr_t)target_addr);

        hook_stub = shadowhook_hook_func_addr(target_addr, (void*)proxy_AesDecrypt, (void**)&orig_AesDecrypt);

        if (hook_stub) {
            LOGD("✅ [Step 4] Hook 部署成功！啟動 30 秒全自動收割視窗...");
            is_harvesting.store(true);

            // D. 維持收割狀態 30 秒
            for(int i = 30; i > 0; i--) {
                if (i % 10 == 0) LOGD("⏳ [Harvesting] 數值擷取中，剩餘 %d 秒...", i);
                sleep(1);
            }

            // E. 安全撤離機制：還原記憶體結構，避開遊戲後期的常規反作弊/CRC 掃描
            is_harvesting.store(false);
            shadowhook_unhook(hook_stub);
            hook_stub = nullptr;
            LOGD("🛡️ [Step 5] 任務完成，Hook 已安全撤離！你可以去檢查 Dumps 目錄了。");
        } else {
            LOGE("❌ [Error] ShadowHook 部署失敗，請檢查 RVA 是否正確或位址是否被保護。");
        }
    }).detach();

    return JNI_VERSION_1_6;
}
