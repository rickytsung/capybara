#include <jni.h>
#include <string>
#include <android/log.h>
#include <thread>
#include <unistd.h>
#include <link.h>
#include <atomic>
#include <fstream>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>
#include <shadowhook.h>

#define TAG "HOOK"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 🎯 核心精準攔截點：Luban.ByteBuf::.ctor(byte[] bytes)
#define TARGET_RVA 0x495131c

// IL2CPP Byte[] 陣列記憶體結構
struct Il2CppArray {
    void* klass;
    void* monitor;
    void* bounds;
    uintmax_t max_length; // 陣列實際持有的二進位數據長度
    uint8_t vector[0];    // 原始 byte 數據起始指標
};

// 宣告原函數指標 (構造函式 .ctor 在底層編譯後返回值為 void，x0 為新分配的物件實例指针)
typedef void (*ByteBuf_ctor_t)(void* __this, Il2CppArray* bytes, void* method);
ByteBuf_ctor_t orig_ByteBuf_ctor = nullptr;
void* hook_stub = nullptr;

std::atomic<bool> is_harvesting{false};

// --- 🎯 標準化二進位文件導出函式 ---
void export_luban_bin(uint8_t* raw_bytes, uintmax_t len) {
    if (!raw_bytes || len <= 0) return;

    // 1. 優先路徑：直接送進 MuMu 模擬器的電腦共用資料夾，Windows 端直接秒收檔案
    std::string dir = "/storage/emulated/0/MuMu12Shared/Dumps/";
    mkdir("/storage/emulated/0/MuMu12Shared/", 0777);
    mkdir(dir.c_str(), 0777);

    // 2. 計算前 4 個 byte 的 Hex 作為特徵 Hash，避免長度相同的檔案互相覆蓋
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < 4 && i < len; i++) {
        ss << std::setw(2) << (int)raw_bytes[i];
    }
    std::string hex_hash = ss.str();

    // 組合出極具辨識度的 Luban 專屬檔名
    std::string filename = "Luban_Bin_" + std::to_string(len) + "_" + hex_hash + ".bin";
    std::string full_path = dir + filename;

    // 3. 執行二進位寫檔
    std::ofstream ofs(full_path, std::ios::out | std::ios::binary | std::ios::trunc);

    // 🛡️ 權限安全防線：若外部共用資料夾權限沒開，自動退守至沙盒私有快取目錄
    if (!ofs.is_open()) {
        dir = "/data/data/com.habby.capybara/cache/Dumps/";
        mkdir("/data/data/com.habby.capybara/cache/", 0777);
        mkdir(dir.c_str(), 0777);
        full_path = dir + filename;
        ofs.open(full_path, std::ios::out | std::ios::binary | std::ios::trunc);
    }

    if (ofs.is_open()) {
        ofs.write((char*)raw_bytes, len);
        ofs.close();
        LOGD("💾 [SUCCESS] Luban 二進位設定檔已導出 -> %s", full_path.c_str());
    } else {
        LOGE("❌ [ERROR] 無法寫入檔案，雙重路徑皆失敗。");
    }
}

// --- 🕵️ 代理構造攔截核心 ---
void proxy_ByteBuf_ctor(void* __this, Il2CppArray* bytes, void* method) {
    // 1. 優先執行原構造函式，讓 Luban 正常的物件記憶體順利初始化，確保遊戲不卡死
    orig_ByteBuf_ctor(__this, bytes, method);

    // 2. 觸發動態收割
    if (is_harvesting.load() && bytes != nullptr) {
        uintmax_t len = bytes->max_length;

        // 門檻過濾：過濾掉極小的記憶體碎片暫存（如小於 128 bytes 的日常資料），只抓核心配置大表
        if (len > 128) {
            LOGD("🔓 [Luban Hook] 成功堵截二進位數據流！大小: %lu bytes", len);

            // 3. 直接將原始 vector 數據指標與長度送入導出函式
            export_luban_bin(bytes->vector, len);
        }
    }
}

// --- JNI 環境載入與監聽執行緒 ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("⚡ [JNI_OnLoad] 魯班鎖動態收割核心模組已加載！");

    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);

    std::thread([]() {
        uintptr_t base = 0;
        while (base == 0) {
            struct { const char* n; uintptr_t b; } mi = {"libil2cpp.so", 0};
            dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) {
                auto m = (decltype(mi)*)data;
                if (info->dlpi_name && strstr(info->dlpi_name, m->n)) {
                    m->b = (uintptr_t)info->dlpi_addr; return 1;
                }
                return 0;
            }, &mi);
            base = mi.b;
            if (base == 0) usleep(100000);
        }

        LOGD("📍 [Step 1] libil2cpp.so 基址已就位: 0x%lx", base);
        sleep(5); // 5 秒安全延遲

        uint8_t* target_addr = (uint8_t*)(base + TARGET_RVA);
        LOGD("🚀 [Step 2] 正在對 Luban.ByteBuf 進行掛載 Hook, 位址: 0x%lx", (uintptr_t)target_addr);

        // 輪詢掛載機制，防範反作弊與記憶體延遲解密
        int attempt = 0;
        while (attempt < 30) {
            attempt++;
            hook_stub = shadowhook_hook_func_addr(target_addr, (void*)proxy_ByteBuf_ctor, (void**)&orig_ByteBuf_ctor);
            if (hook_stub) break;
            usleep(1000000);
        }

        if (hook_stub) {
            LOGD("✅ [Step 3] 🎯 Hook 掛載成功！黃金 30 秒全自動 Luban 封包劫持開始...");
            is_harvesting.store(true);

            for (int i = 30; i > 0; i--) {
                sleep(1);
            }

            is_harvesting.store(false);
            shadowhook_unhook(hook_stub);
            hook_stub = nullptr;
            LOGD("🛡️ [Step 4] 30 秒金視窗關閉，Hook 已安全撤離。");
        } else {
            LOGE("❌ [Step 3] Hook 掛載超時失敗，錯誤碼: %d", shadowhook_get_errno());
        }
    }).detach();

    return JNI_VERSION_1_6;
}
