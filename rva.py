import re
import os

def scan_dump_file(file_path, search_keyword):
    """
    解析 il2cppdumper 的 dump.cs 檔案，並根據關鍵字搜尋方法。
    """
    if not os.path.exists(file_path):
        print(f"❌ 錯誤：找不到檔案 {file_path}")
        return

    print(f"⏳ 正在掃描 {file_path}，搜尋關鍵字: '{search_keyword}' ...")

    # 正規表達式編譯（提升效率）
    dll_pattern = re.compile(r"^// Dll\s*:\s*(.+)$")
    ns_pattern = re.compile(r"^// Namespace\s*:\s*(.+)$")
    # 匹配類別、結構、介面定義
    class_pattern = re.compile(r"(class|struct|interface)\s+(\w+)")
    # 匹配 RVA 與 VA
    rva_pattern = re.compile(r"RVA:\s*(0x[0-9a-fA-F]+)\s+VA:\s*(0x[0-9a-fA-F]+)")

    current_dll = "Unknown"
    current_ns = "Global"
    current_class = "Unknown"
    
    pending_rva = None
    pending_va = None

    match_count = 0

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line_strip = line.strip()
            if not line_strip:
                continue

            # 1. 識別 DLL
            dll_match = dll_pattern.match(line_strip)
            if dll_match:
                current_dll = dll_match.group(1).strip()
                continue

            # 2. 識別 Namespace
            ns_match = ns_pattern.match(line_strip)
            if ns_match:
                current_ns = ns_match.group(1).strip()
                continue

            # 3. 識別 Class / Struct
            # 排除註解行，避免誤判
            if not line_strip.startswith("//"):
                class_match = class_pattern.search(line_strip)
                if class_match and "{" in line_strip:
                    current_class = class_match.group(2).strip()
                    continue

            # 4. 識別 RVA / VA 註解
            rva_match = rva_pattern.search(line_strip)
            if rva_match:
                pending_rva = rva_match.group(1)
                pending_va = rva_match.group(2)
                continue

            # 5. 如果上一行是 RVA，這行就是方法簽名 (Method Signature)
            if pending_rva:
                # 確保這行不是另一條註解
                if not line_strip.startswith("//"):
                    method_signature = line_strip
                    
                    # 進行關鍵字比對（不區分大小寫）
                    # 會同時檢查 方法簽名 與 類別名稱
                    if (search_keyword.lower() in method_signature.lower()) or \
                       (search_keyword.lower() in current_class.lower()):
                        
                        match_count += 1
                        print("\n" + "="*60)
                        print(f"📦 [DLL]       : {current_dll}")
                        print(f"🔮 [Namespace] : {current_ns}")
                        print(f"🏛️  [Class]     : {current_class}")
                        print(f"🛠️  [Method]    : {method_signature}")
                        print(f"📍 [⚙️ RVA]     : \033[1;32m{pending_rva}\033[0m")
                        print(f"🔗 [VA]        : {pending_va}")
                
                # 釋放狀態，等待下一個方法
                pending_rva = None
                pending_va = None

    print("\n" + "="*60)
    print(f"🎉 掃描完成！共找到 {match_count} 個符合條件的結果。")

if __name__ == "__main__":
    # --- 請在此修改你的檔案路徑與想搜尋的關鍵字 ---
    DUMP_FILE_PATH = "dump.cs"  # 你的 dump.cs 路徑
    KEYWORD = "get_text"         # 你想找的關鍵字，例如 "decrypt"、"Config"、"byte[]"
    
    scan_dump_file(DUMP_FILE_PATH, KEYWORD)
