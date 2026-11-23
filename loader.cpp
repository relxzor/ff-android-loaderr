// ============================================================================
// loader.cpp — UNIFIED ANDROID BINARY LOADER (libffloader.so)
// Menjalankan: data.cpp (HeadshotEngine), database.lua, crosshair_aim.cfg,
//              localConfig.json, headCharacter.CT & headCharacter2.CT
// ============================================================================

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cfloat>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>
#include <thread>
#include <atomic>
#include <unordered_set>

extern "C" {
    #include "lua.h"
    #include "lualib.h"
    #include "lauxlib.h"
}

#define LOG_TAG "FF_BINARY_LOADER"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const std::string BASE_DIR_EXT = "/storage/emulated/0/Android/data/com.dts.freefireth/files/";
static const std::string BASE_DIR_INT = "/data/data/com.dts.freefireth/files/";

// ============================================================================
// 1. UTILITI FAIL & LOG DIAGNOSTIK
// ============================================================================
static std::string resolveFile(const std::string& filename) {
    const std::vector<std::string> dirs = { BASE_DIR_EXT, BASE_DIR_INT, "./" };
    for (const auto& d : dirs) {
        std::string full = d + filename;
        std::ifstream f(full);
        if (f.good()) return full;
    }
    return "";
}

static void writeLog(const std::string& msg) {
    LOGI("%s", msg.c_str());
    std::ofstream logFile(BASE_DIR_EXT + "loader_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << msg << "\n";
    }
}

// ============================================================================
// 2. RESOLVER MEMORI & PARSER CHEAT TABLE (.CT)
// ============================================================================
struct CheatTableEntry {
    std::string sourceFile;
    std::string description;
    std::string moduleName;
    uintptr_t   baseOffset = 0;
    std::vector<uintptr_t> pointerOffsets;
    std::string varType;
    std::string valueStr;
};

static uintptr_t getModuleBase(const std::string& libName) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(libName) != std::string::npos) {
            uintptr_t startAddr = 0;
            if (std::sscanf(line.c_str(), "%lx-", &startAddr) == 1) {
                return startAddr;
            }
        }
    }
    return 0;
}

static bool safeWriteMemory(uintptr_t addr, const void* data, size_t len) {
    if (addr == 0 || data == nullptr || len == 0) return false;
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t pageStart = addr & ~(static_cast<uintptr_t>(pageSize) - 1);
    size_t protectLen = (addr + len) - pageStart;

    if (mprotect(reinterpret_cast<void*>(pageStart), protectLen, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        if (mprotect(reinterpret_cast<void*>(pageStart), protectLen, PROT_READ | PROT_WRITE) != 0) {
            return false;
        }
    }
    std::memcpy(reinterpret_cast<void*>(addr), data, len);
    return true;
}

static uintptr_t resolvePointerChain(uintptr_t baseAddr, const std::vector<uintptr_t>& offsets) {
    uintptr_t current = baseAddr;
    for (auto it = offsets.rbegin(); it != offsets.rend(); ++it) {
        if (current < 0x10000) return 0;
        current = *reinterpret_cast<uintptr_t*>(current);
        if (current < 0x10000) return 0;
        current += *it;
    }
    return current;
}

static std::string extractXmlTag(const std::string& block, const std::string& tag) {
    std::string openTag = "<" + tag + ">";
    std::string closeTag = "</" + tag + ">";
    size_t start = block.find(openTag);
    if (start == std::string::npos) return "";
    start += openTag.size();
    size_t end = block.find(closeTag, start);
    if (end == std::string::npos) return "";
    return block.substr(start, end - start);
}

static uintptr_t parseHex(const std::string& s) {
    try {
        return static_cast<uintptr_t>(std::stoull(s, nullptr, 16));
    } catch (...) {
        return 0;
    }
}

static void parseCheatTableFile(const std::string& filename,
                                std::vector<CheatTableEntry>& outEntries,
                                std::unordered_set<std::string>& seenKeys) {
    std::string path = resolveFile(filename);
    if (path.empty()) {
        writeLog("[CT] Fail tidak ditemui: " + filename);
        return;
    }

    std::ifstream file(path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string xml = buffer.str();

    size_t pos = 0;
    int count = 0;
    while ((pos = xml.find("<CheatEntry>", pos)) != std::string::npos) {
        size_t end = xml.find("</CheatEntry>", pos);
        if (end == std::string::npos) break;

        std::string block = xml.substr(pos, end - pos);
        pos = end + 13;

        std::string addrStr = extractXmlTag(block, "Address");
        if (addrStr.empty()) continue;

        std::string desc = extractXmlTag(block, "Description");
        if (desc.size() >= 2 && desc.front() == '"' && desc.back() == '"') {
            desc = desc.substr(1, desc.size() - 2);
        }

        std::string uid = desc + "|" + addrStr;
        if (seenKeys.count(uid)) continue;
        seenKeys.insert(uid);

        CheatTableEntry entry;
        entry.sourceFile = filename;
        entry.description = desc.empty() ? "Unnamed" : desc;
        entry.varType = extractXmlTag(block, "VariableType");
        entry.valueStr = extractXmlTag(block, "Value");

        // Pisahkan format "libil2cpp.so+1A2B3C" atau alamat hex terus
        size_t plusPos = addrStr.find('+');
        if (plusPos != std::string::npos) {
            entry.moduleName = addrStr.substr(0, plusPos);
            entry.baseOffset = parseHex(addrStr.substr(plusPos + 1));
        } else {
            entry.moduleName = "libil2cpp.so";
            entry.baseOffset = parseHex(addrStr);
        }

        // Ekstrak <Offsets><Offset>...</Offset></Offsets> jika wujud
        std::string offsetsBlock = extractXmlTag(block, "Offsets");
        size_t oPos = 0;
        while ((oPos = offsetsBlock.find("<Offset>", oPos)) != std::string::npos) {
            size_t oEnd = offsetsBlock.find("</Offset>", oPos);
            if (oEnd == std::string::npos) break;
            std::string hexOff = offsetsBlock.substr(oPos + 8, oEnd - (oPos + 8));
            entry.pointerOffsets.push_back(parseHex(hexOff));
            oPos = oEnd + 9;
        }

        outEntries.push_back(entry);
        count++;
    }

    writeLog("[CT] Dimuatkan " + std::to_string(count) + " entri unik daripada " + filename);
}

// ============================================================================
// 3. ENJIN TERAS HEADSHOT (TERINTEGRASI DARI data.cpp)
// ============================================================================
struct Vector3 {
    float x, y, z;
    Vector3(float a = 0.0f, float b = 0.0f, float c = 0.0f) : x(a), y(b), z(c) {}
};

struct GameObject {
    int m_FileID;
    long long m_PathID;
    unsigned int m_Layer;
    std::string m_Name;
    unsigned short m_Tag;
    bool m_IsActive;
    Vector3 position;
};

struct HeadshotConfig {
    bool  enabled            = true;
    float crosshairSmooth    = 0.28f;
    float crosshairFov       = 12.0f;
    float maxAimStep         = 1.85f;
    float headWeight         = 0.70f;
    float neckWeight         = 0.90f;
    float headDragOffset     = 0.14f;
    float microJitter        = 0.012f;
    bool  lockOnlyWhenFiring = true;
};

class HeadshotEngine {
public:
    HeadshotEngine() : rng(std::random_device{}()), jitter(-1.0f, 1.0f) {}

    void reloadAllConfigs() {
        loadFromCfg();
        loadFromJson();
        writeLog("[CFG] Segerak: smooth=" + std::to_string(cfg.crosshairSmooth) +
                 " fov=" + std::to_string(cfg.crosshairFov) +
                 " head_drag=" + std::to_string(cfg.headDragOffset));
    }

    void applyCheatTables(const std::vector<CheatTableEntry>& entries) {
        uintptr_t il2cppBase = getModuleBase("libil2cpp.so");
        if (il2cppBase == 0) {
            writeLog("[MEM] libil2cpp.so belum dimuatkan, melangkau patch langsung.");
            return;
        }

        int applied = 0;
        for (const auto& e : entries) {
            if (e.baseOffset == 0) continue;
            uintptr_t modBase = (e.moduleName == "libil2cpp.so") ? il2cppBase : getModuleBase(e.moduleName);
            if (modBase == 0) continue;

            uintptr_t targetAddr = modBase + e.baseOffset;
            if (!e.pointerOffsets.empty()) {
                targetAddr = resolvePointerChain(targetAddr, e.pointerOffsets);
            }
            if (targetAddr == 0 || e.valueStr.empty()) continue;

            if (e.varType == "Float") {
                try {
                    float fVal = std::stof(e.valueStr);
                    if (safeWriteMemory(targetAddr, &fVal, sizeof(float))) applied++;
                } catch (...) {}
            } else if (e.varType == "4 Bytes") {
                try {
                    int32_t iVal = std::stoi(e.valueStr);
                    if (safeWriteMemory(targetAddr, &iVal, sizeof(int32_t))) applied++;
                } catch (...) {}
            }
        }
        writeLog("[MEM] Selesai proses entri .CT (dipatch: " + std::to_string(applied) + ")");
    }

    void updateAim(const std::vector<GameObject>& objects, bool isFiring, float deltaTime) {
        if (!cfg.enabled) return;
        if (cfg.lockOnlyWhenFiring && !isFiring) {
            targetLocked = false;
            lockedBoneID = 0;
            return;
        }

        float bestScore = FLT_MAX;
        const GameObject* bestTarget = nullptr;
        bool isNeck = false;

        for (const auto& obj : objects) {
            if (!obj.m_IsActive) continue;
            bool head = isHeadBone(obj);
            bool neck = isNeckBone(obj);
            if (!head && !neck) continue;

            float dist = distance3D(crosshair, obj.position);
            if (dist > cfg.crosshairFov) continue;

            float score = dist * (head ? cfg.headWeight : cfg.neckWeight);
            if (score < bestScore) {
                bestScore = score;
                bestTarget = &obj;
                isNeck = (neck && !head);
            }
        }

        if (bestTarget) {
            Vector3 aimPos = bestTarget->position;
            if (isNeck && isFiring) aimPos.y += cfg.headDragOffset;
            lockedBoneID = bestTarget->m_PathID;
            targetLocked = true;

            float dtScale = clamp(deltaTime * 60.0f, 0.25f, 2.0f);
            float alpha = clamp(cfg.crosshairSmooth * dtScale, 0.05f, 1.0f);

            crosshair.x += clamp((aimPos.x - crosshair.x) * alpha, -cfg.maxAimStep, cfg.maxAimStep) + jitter(rng) * cfg.microJitter;
            crosshair.y += clamp((aimPos.y - crosshair.y) * alpha, -cfg.maxAimStep, cfg.maxAimStep) + jitter(rng) * cfg.microJitter;
            crosshair.z += clamp((aimPos.z - crosshair.z) * alpha, -cfg.maxAimStep, cfg.maxAimStep);
        } else {
            targetLocked = false;
            lockedBoneID = 0;
        }
    }

    HeadshotConfig& getConfig() { return cfg; }
    Vector3 getCrosshair() const { return crosshair; }
    void setCrosshair(const Vector3& v) { crosshair = v; }

private:
    HeadshotConfig cfg;
    Vector3 crosshair{0.0f, 0.0f, 0.0f};
    long long lockedBoneID = 0;
    bool targetLocked = false;
    std::mt19937 rng;
    std::uniform_real_distribution<float> jitter;

    float clamp(float v, float lo, float hi) const {
        return std::max(lo, std::min(v, hi));
    }

    float distance3D(const Vector3& a, const Vector3& b) const {
        float dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }

    bool isHeadBone(const GameObject& obj) const {
        return obj.m_Name.find("Head") != std::string::npos ||
               obj.m_PathID == -2153026828645120823LL ||
               obj.m_PathID ==  8020702072519905044LL ||
               obj.m_PathID ==  1302001446714693385LL ||
               obj.m_PathID ==  7146749430408510044LL ||
               obj.m_PathID == -7149692112994652396LL;
    }

    bool isNeckBone(const GameObject& obj) const {
        return obj.m_Name.find("Neck") != std::string::npos ||
               obj.m_PathID == 2072821652868188856LL;
    }

    void loadFromCfg() {
        std::string p = resolveFile("crosshair_aim.cfg");
        if (p.empty()) return;
        std::ifstream f(p);
        std::string key;
        float val = 0.0f;
        while (f >> key >> val) {
            if (key == "crosshair_smooth") cfg.crosshairSmooth = clamp(val, 0.05f, 1.0f);
            else if (key == "crosshair_fov") cfg.crosshairFov = clamp(val, 1.0f, 50.0f);
            else if (key == "head_drag") cfg.headDragOffset = clamp(val, 0.0f, 0.5f);
        }
    }

    void loadFromJson() {
        std::string p = resolveFile("localConfig.json");
        if (p.empty()) return;
        std::ifstream f(p);
        std::stringstream ss;
        ss << f.rdbuf();
        std::string content = ss.str();

        if (content.find("\"enabled\": false") != std::string::npos ||
            content.find("\"enabled\":false") != std::string::npos) {
            cfg.enabled = false;
        }
        extractJsonFloat(content, "\"smooth\"", cfg.crosshairSmooth, 0.05f, 1.0f);
        extractJsonFloat(content, "\"fov\"", cfg.crosshairFov, 1.0f, 50.0f);
        extractJsonFloat(content, "\"headDrag\"", cfg.headDragOffset, 0.0f, 0.5f);
    }

    void extractJsonFloat(const std::string& json, const std::string& key, float& target, float lo, float hi) {
        size_t pos = json.find(key);
        if (pos == std::string::npos) return;
        size_t colon = json.find(':', pos + key.size());
        if (colon == std::string::npos) return;
        try {
            target = clamp(std::stof(json.substr(colon + 1)), lo, hi);
        } catch (...) {}
    }
};

static HeadshotEngine g_Engine;
static std::vector<CheatTableEntry> g_CheatEntries;
static std::atomic<bool> g_Running{false};
static lua_State* g_Lua = nullptr;

// ============================================================================
// 4. JAMBATAN LUA C API (HUBUNGKAN database.lua KE BINARY C++)
// ============================================================================
static int lua_getModuleBase(lua_State* L) {
    const char* mod = luaL_optstring(L, 1, "libil2cpp.so");
    uintptr_t base = getModuleBase(mod);
    lua_pushinteger(L, static_cast<lua_Integer>(base));
    return 1;
}

static int lua_writeFloat(lua_State* L) {
    uintptr_t addr = static_cast<uintptr_t>(luaL_checkinteger(L, 1));
    float val = static_cast<float>(luaL_checknumber(L, 2));
    bool ok = safeWriteMemory(addr, &val, sizeof(float));
    lua_pushboolean(L, ok);
    return 1;
}

static int lua_syncEngineConfig(lua_State* L) {
    if (lua_istable(L, 1)) {
        auto& c = g_Engine.getConfig();
        lua_getfield(L, 1, "smooth");
        if (lua_isnumber(L, -1)) c.crosshairSmooth = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);

        lua_getfield(L, 1, "fov");
        if (lua_isnumber(L, -1)) c.crosshairFov = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);

        lua_getfield(L, 1, "headDrag");
        if (lua_isnumber(L, -1)) c.headDragOffset = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
    }
    lua_pushboolean(L, 1);
    return 1;
}

static void initLuaBrain() {
    std::string luaPath = resolveFile("database.lua");
    if (luaPath.empty()) {
        writeLog("[LUA] database.lua tidak ditemui.");
        return;
    }

    g_Lua = luaL_newstate();
    if (!g_Lua) return;
    luaL_openlibs(g_Lua);

    // Dedahkan fungsi native C++ supaya database.lua boleh akses terus
    lua_register(g_Lua, "native_get_base", lua_getModuleBase);
    lua_register(g_Lua, "native_write_float", lua_writeFloat);
    lua_register(g_Lua, "native_sync_config", lua_syncEngineConfig);

    if (luaL_dofile(g_Lua, luaPath.c_str()) != LUA_OK) {
        const char* err = lua_tostring(g_Lua, -1);
        writeLog(std::string("[LUA] Ralat jalankan database.lua: ") + (err ? err : "unknown"));
        lua_pop(g_Lua, 1);
        return;
    }

    // Tarik jadual config daripada nilai return HeadshotBrain jika wujud
    if (lua_istable(g_Lua, -1)) {
        lua_getfield(g_Lua, -1, "config");
        if (lua_istable(g_Lua, -1)) {
            auto& c = g_Engine.getConfig();
            lua_getfield(g_Lua, -1, "smooth");
            if (lua_isnumber(g_Lua, -1)) c.crosshairSmooth = static_cast<float>(lua_tonumber(g_Lua, -1));
            lua_pop(g_Lua, 1);

            lua_getfield(g_Lua, -1, "fov");
            if (lua_isnumber(g_Lua, -1)) c.crosshairFov = static_cast<float>(lua_tonumber(g_Lua, -1));
            lua_pop(g_Lua, 1);

            lua_getfield(g_Lua, -1, "headDrag");
            if (lua_isnumber(g_Lua, -1)) c.headDragOffset = static_cast<float>(lua_tonumber(g_Lua, -1));
            lua_pop(g_Lua, 1);
        }
        lua_pop(g_Lua, 1);
    }

    writeLog("[LUA] database.lua berjaya dimuatkan & disegerakkan: " + luaPath);
}

// ============================================================================
// 5. THREAD UTAMA & ENTRY POINT BINARY (.SO)
// ============================================================================
static void loaderMainThread() {
    writeLog("=== FF BINARY LOADER DIMULAKAN ===");

    // Tunggu sehingga libil2cpp.so selesai dimuatkan oleh proses game
    int waitTicks = 0;
    while (getModuleBase("libil2cpp.so") == 0 && waitTicks < 30) {
        sleep(1);
        waitTicks++;
    }

    // 1. Muat konfigurasi CFG & JSON
    g_Engine.reloadAllConfigs();

    // 2. Muat & gabungkan kedua-dua fail Cheat Table (.CT) tanpa pendua
    std::unordered_set<std::string> seen;
    g_CheatEntries.clear();
    parseCheatTableFile("headCharacter.CT", g_CheatEntries, seen);
    parseCheatTableFile("headCharacter2.CT", g_CheatEntries, seen);
    parseCheatTableFile("headCharater2.CT", g_CheatEntries, seen); // Sokongan ejaan alternatif

    // 3. Jalankan database.lua dalam enjin Lua terbina dalam
    initLuaBrain();

    // 4. Laksanakan entri memori daripada headCharacter.CT & headCharacter2.CT
    g_Engine.applyCheatTables(g_CheatEntries);

    writeLog("=== SEMUA MODUL AKTIF (" + std::to_string(g_CheatEntries.size()) + " entri CT) ===");

    // Loop pemantauan konfigurasi hidup (reload automatik setiap 3 saat jika fail diubah)
    while (g_Running.load()) {
        sleep(3);
        g_Engine.reloadAllConfigs();
    }
}

static void startLoaderOnce() {
    if (!g_Running.exchange(true)) {
        std::thread(loaderMainThread).detach();
    }
}

// Auto-jalan sebaik binary .so dimuatkan (dlopen / LD_PRELOAD / injector)
__attribute__((constructor))
static void onLoaderAttach() {
    startLoaderOnce();
}

// Auto-jalan jika dimuatkan melalui Java/Smali: System.loadLibrary("ffloader")
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    startLoaderOnce();
    return JNI_VERSION_1_6;
}
