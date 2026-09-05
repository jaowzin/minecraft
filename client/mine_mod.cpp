#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

HMODULE g_self = nullptr;
HMODULE g_minecraft = nullptr;
FILE* g_log = nullptr;
std::atomic_bool g_xrayEnabled{false};
std::atomic_bool g_unloading{false};

std::vector<std::string> g_visibleTokens;

struct CodePatch {
    std::uint8_t* address = nullptr;
    std::array<std::uint8_t, 12> original{};
    bool installed = false;
};

CodePatch g_renderLayerPatch;
std::int32_t g_renderLayerFieldOffset = -1;
void** g_blockLegacyVtable = nullptr;
std::size_t g_renderLayerVtableIndex = static_cast<std::size_t>(-1);
void* g_clientInstance = nullptr;

using RebuildChunkFn = void(__fastcall*)(void*);
RebuildChunkFn g_rebuildChunk = nullptr;

void logLine(const char* format, ...) {
    char buffer[1400]{};
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    if (g_log) {
        std::fprintf(g_log, "%s\n", buffer);
        std::fflush(g_log);
    }
}

std::filesystem::path moduleDirectory() {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(g_self, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return {};
    return std::filesystem::path(path).parent_path();
}

void openLog() {
    wchar_t tempPath[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempPath)) return;

    std::wstring path = tempPath;
    path += L"MineMod.log";
    _wfopen_s(&g_log, path.c_str(), L"w");
}

std::string trim(std::string text) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), notSpace));
    text.erase(std::find_if(text.rbegin(), text.rend(), notSpace).base(), text.end());
    return text;
}

std::string lowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return text;
}

void loadVisibleTokens() {
    g_visibleTokens.clear();

    const auto path = moduleDirectory() / L"xray-blocks.txt";
    std::ifstream input(path);
    if (input) {
        std::string line;
        while (std::getline(input, line)) {
            const auto hash = line.find('#');
            if (hash != std::string::npos) line.resize(hash);
            line = lowerCopy(trim(line));
            if (!line.empty()) g_visibleTokens.push_back(line);
        }
    }

    if (g_visibleTokens.empty()) {
        g_visibleTokens = {
            "ore",
            "ancient_debris",
            "lava",
            "water",
            "chest",
            "spawner",
            "amethyst",
            "vault"
        };
    }

    logLine("[+] XRay visible token count: %zu", g_visibleTokens.size());
    for (const auto& token : g_visibleTokens) {
        logLine("    keep: %s", token.c_str());
    }
}

bool isReadableAddress(const void* address) {
    if (!address) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) return false;
    return true;
}

bool isReadableRange(const void* address, std::size_t size) {
    if (!address || !size) return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    const auto end = begin + size;
    if (end < begin) return false;

    auto cursor = begin;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) return false;
        const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= cursor) return false;
        cursor = std::min(next, end);
    }
    return true;
}

bool isWritableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS)) return false;
    const DWORD base = protect & 0xFF;
    return base == PAGE_READWRITE
        || base == PAGE_WRITECOPY
        || base == PAGE_EXECUTE_READWRITE
        || base == PAGE_EXECUTE_WRITECOPY;
}

void* safeReadPointer(const void* address) {
#if defined(_MSC_VER)
    __try {
        return *reinterpret_cast<void* const*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
#else
    if (!isReadableRange(address, sizeof(void*))) return nullptr;
    return *reinterpret_cast<void* const*>(address);
#endif
}

bool safeReadInt32(const void* address, std::int32_t& value) {
#if defined(_MSC_VER)
    __try {
        value = *reinterpret_cast<const std::int32_t*>(address);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    if (!isReadableRange(address, sizeof(value))) return false;
    value = *reinterpret_cast<const std::int32_t*>(address);
    return true;
#endif
}

bool copyMsvcString(const void* stringObject, char* output, std::size_t outputCapacity) {
    if (!output || outputCapacity < 2) return false;
    output[0] = '\0';

#if defined(_MSC_VER)
    __try {
        const auto* base = reinterpret_cast<const std::uint8_t*>(stringObject);
        const std::size_t length = *reinterpret_cast<const std::size_t*>(base + 0x10);
        const std::size_t capacity = *reinterpret_cast<const std::size_t*>(base + 0x18);
        if (length == 0 || length >= outputCapacity || length > 255) return false;
        if (capacity < length) return false;

        const char* data = nullptr;
        if (capacity < 16) {
            data = reinterpret_cast<const char*>(base);
        } else {
            data = *reinterpret_cast<const char* const*>(base);
        }
        if (!data || !isReadableRange(data, length)) return false;

        std::memcpy(output, data, length);
        output[length] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    return false;
#endif
}

bool plausibleBlockName(const char* text) {
    if (!text || !*text) return false;
    const std::size_t length = std::strlen(text);
    if (length < 2 || length > 200) return false;

    std::size_t good = 0;
    for (std::size_t i = 0; i < length; ++i) {
        const unsigned char ch = static_cast<unsigned char>(text[i]);
        if (std::isalnum(ch) || ch == '_' || ch == ':' || ch == '.' || ch == '-' || ch == '/') {
            ++good;
        }
    }
    return good == length;
}

bool readBlockName(void* blockLegacy, std::string& result) {
    if (!blockLegacy || !isReadableAddress(blockLegacy)) return false;

    // Current Bedrock layout used by maintained 2026 SDKs:
    // +0x08 std::string translateName (tile.deepslate_diamond_ore)
    // +0x90 HashedString name; its std::string begins at +0x98
    // +0xE0 HashedString namespacedId; its std::string begins at +0xE8
    // +0x30 is kept as a legacy Horion/Borion fallback.
    constexpr std::array<std::size_t, 4> stringOffsets = {0x08, 0xE8, 0x98, 0x30};
    char buffer[256]{};

    for (const auto offset : stringOffsets) {
        if (copyMsvcString(reinterpret_cast<std::uint8_t*>(blockLegacy) + offset, buffer, sizeof(buffer))
            && plausibleBlockName(buffer)) {
            result.assign(buffer);
            return true;
        }
    }
    return false;
}

bool shouldRemainVisible(const std::string& identifier) {
    const std::string name = lowerCopy(identifier);

    // Air has no useful geometry and should keep the vanilla result.
    if (name.find("air") != std::string::npos) return true;

    for (const auto& token : g_visibleTokens) {
        if (name.find(token) != std::string::npos) return true;
    }
    return false;
}

std::vector<int> parsePattern(const char* text) {
    std::vector<int> result;
    const char* p = text;

    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;

        if (*p == '?') {
            result.push_back(-1);
            ++p;
            if (*p == '?') ++p;
        } else {
            char token[3]{};
            token[0] = *p++;
            if (!*p) return {};
            token[1] = *p++;
            char* end = nullptr;
            const long value = std::strtol(token, &end, 16);
            if (!end || *end != '\0' || value < 0 || value > 0xFF) return {};
            result.push_back(static_cast<int>(value));
        }
        while (*p == ' ') ++p;
    }
    return result;
}

std::uint8_t* getSection(HMODULE module, const char* name, std::size_t& size) {
    auto* base = reinterpret_cast<std::uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char sectionName[9]{};
        std::memcpy(sectionName, section[i].Name, 8);
        if (std::strcmp(sectionName, name) == 0) {
            size = section[i].Misc.VirtualSize;
            return base + section[i].VirtualAddress;
        }
    }
    return nullptr;
}

std::uint8_t* findPattern(std::uint8_t* start, std::size_t size, const std::vector<int>& pattern) {
    if (!start || pattern.empty() || size < pattern.size()) return nullptr;

    for (std::size_t i = 0; i + pattern.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] >= 0 && start[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                match = false;
                break;
            }
        }
        if (match) return start + i;
    }
    return nullptr;
}

std::vector<std::uint8_t*> findPatterns(std::uint8_t* start, std::size_t size,
                                        const std::vector<int>& pattern, std::size_t limit) {
    std::vector<std::uint8_t*> matches;
    if (!start || pattern.empty() || size < pattern.size()) return matches;

    for (std::size_t i = 0; i + pattern.size() <= size && matches.size() < limit; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] >= 0 && start[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                match = false;
                break;
            }
        }
        if (match) matches.push_back(start + i);
    }
    return matches;
}

std::uintptr_t resolveRip(std::uint8_t* instruction, std::size_t dispOffset, std::size_t instructionSize) {
    std::int32_t displacement{};
    std::memcpy(&displacement, instruction + dispOffset, sizeof(displacement));
    return reinterpret_cast<std::uintptr_t>(instruction + instructionSize) + static_cast<std::intptr_t>(displacement);
}

bool addressInSection(const void* address, std::uint8_t* section, std::size_t size) {
    if (!address || !section || !size) return false;
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    const auto begin = reinterpret_cast<std::uintptr_t>(section);
    return value >= begin && value < begin + size;
}

std::vector<std::uintptr_t> findWritablePointers(std::uintptr_t target, std::size_t limit) {
    std::vector<std::uintptr_t> results;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    auto cursor = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maxAddress = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    constexpr std::size_t chunkSize = 1024 * 1024;
    HANDLE self = GetCurrentProcess();

    while (cursor < maxAddress && results.size() < limit) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi))) break;

        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionSize = static_cast<std::size_t>(mbi.RegionSize);

        if (mbi.State == MEM_COMMIT && isWritableProtection(mbi.Protect) && regionSize >= sizeof(std::uintptr_t)) {
            std::size_t offset = 0;
            while (offset < regionSize && results.size() < limit) {
                const auto toRead = std::min(chunkSize, regionSize - offset);
                std::vector<std::uint8_t> bytes(toRead);
                SIZE_T read = 0;
                if (ReadProcessMemory(self, reinterpret_cast<const void*>(regionBase + offset),
                                      bytes.data(), toRead, &read)
                    && read >= sizeof(std::uintptr_t)) {
                    const auto absoluteBase = regionBase + offset;
                    std::size_t i = static_cast<std::size_t>((8 - (absoluteBase & 7)) & 7);
                    for (; i + sizeof(std::uintptr_t) <= read && results.size() < limit; i += 8) {
                        std::uintptr_t value{};
                        std::memcpy(&value, bytes.data() + i, sizeof(value));
                        if (value == target) results.push_back(absoluteBase + i);
                    }
                }
                offset += toRead;
            }
        }

        const auto next = regionBase + regionSize;
        if (next <= cursor) break;
        cursor = next;
    }

    return results;
}

void** findBlockLegacyVtable() {
    if (!g_minecraft) return nullptr;

    std::size_t textSize = 0;
    auto* text = getSection(g_minecraft, ".text", textSize);
    std::size_t rdataSize = 0;
    auto* rdata = getSection(g_minecraft, ".rdata", rdataSize);
    if (!text || !rdata) return nullptr;

    // Borion/Horion constructor anchor. It is only used to resolve the vtable;
    // the actual render function is validated separately before patching.
    const auto constructorPattern = parsePattern(
        "48 8D 05 ?? ?? ?? ?? 48 89 01 4C 8B 72 ?? 48 B9");
    if (auto* match = findPattern(text, textSize, constructorPattern)) {
        const auto target = resolveRip(match, 3, 7);
        if (addressInSection(reinterpret_cast<void*>(target), rdata, rdataSize)) {
            logLine("[+] BlockLegacy vtable resolved by constructor signature: 0x%llX",
                    static_cast<unsigned long long>(target));
            return reinterpret_cast<void**>(target);
        }
    }

    // MSVC x64 RTTI fallback: TypeDescriptor name -> CompleteObjectLocator -> vtable[-1].
    constexpr char rttiName[] = ".?AVBlockLegacy@@";
    std::uint8_t* nameAddress = nullptr;
    for (std::size_t i = 0; i + sizeof(rttiName) <= rdataSize; ++i) {
        if (std::memcmp(rdata + i, rttiName, sizeof(rttiName) - 1) == 0) {
            nameAddress = rdata + i;
            break;
        }
    }
    if (!nameAddress || nameAddress < rdata + 16) {
        logLine("[-] BlockLegacy RTTI name not found");
        return nullptr;
    }

    const auto moduleBase = reinterpret_cast<std::uintptr_t>(g_minecraft);
    const auto typeDescriptor = reinterpret_cast<std::uintptr_t>(nameAddress - 16);
    const std::uint32_t typeDescriptorRva = static_cast<std::uint32_t>(typeDescriptor - moduleBase);

    for (std::size_t i = 0; i + 24 <= rdataSize; i += 4) {
        const auto* candidate = rdata + i;
        std::uint32_t signature{};
        std::uint32_t pTypeDescriptor{};
        std::uint32_t selfRva{};
        std::memcpy(&signature, candidate + 0, sizeof(signature));
        std::memcpy(&pTypeDescriptor, candidate + 12, sizeof(pTypeDescriptor));
        std::memcpy(&selfRva, candidate + 20, sizeof(selfRva));
        if (signature != 1 || pTypeDescriptor != typeDescriptorRva) continue;
        if (moduleBase + selfRva != reinterpret_cast<std::uintptr_t>(candidate)) continue;

        const auto colAddress = reinterpret_cast<std::uintptr_t>(candidate);
        for (std::size_t p = 0; p + sizeof(std::uintptr_t) <= rdataSize; p += sizeof(std::uintptr_t)) {
            std::uintptr_t value{};
            std::memcpy(&value, rdata + p, sizeof(value));
            if (value != colAddress) continue;

            auto** vtable = reinterpret_cast<void**>(rdata + p + sizeof(std::uintptr_t));
            void* firstFunction = safeReadPointer(vtable);
            if (addressInSection(firstFunction, text, textSize)) {
                logLine("[+] BlockLegacy vtable resolved by RTTI: 0x%llX",
                        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(vtable)));
                return vtable;
            }
        }
    }

    logLine("[-] BlockLegacy vtable not resolved");
    return nullptr;
}

bool decodeSimpleIntGetter(std::uint8_t* function, std::int32_t& fieldOffset) {
    if (!function || !isReadableRange(function, 12)) return false;

    std::size_t length = 0;
    if (function[0] == 0x8B && function[1] == 0x81 && function[6] == 0xC3) {
        std::memcpy(&fieldOffset, function + 2, sizeof(fieldOffset));
        length = 7;
    } else if (function[0] == 0x8B && function[1] == 0x41 && function[3] == 0xC3) {
        fieldOffset = static_cast<std::int8_t>(function[2]);
        length = 4;
    } else {
        return false;
    }

    if (fieldOffset < 0 || fieldOffset > 0x2000) return false;

    // We overwrite 12 bytes with mov rax,imm64 / jmp rax. Only accept a tiny
    // getter that is followed by compiler padding, so no neighboring function is touched.
    for (std::size_t i = length; i < 12; ++i) {
        if (function[i] != 0xCC && function[i] != 0x90) return false;
    }
    return true;
}

std::uint8_t* findRenderLayerGetter() {
    std::size_t textSize = 0;
    auto* text = getSection(g_minecraft, ".text", textSize);
    if (!text) return nullptr;

    g_blockLegacyVtable = findBlockLegacyVtable();

    // Historic Horion/Borion signature for BlockLegacy::getRenderLayer.
    // Prefer an exact match that is also present in the resolved BlockLegacy vtable.
    const auto exactPattern = parsePattern(
        "8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC F3 0F 10 81");
    const auto exactMatches = findPatterns(text, textSize, exactPattern, 16);
    logLine("[+] getRenderLayer exact-pattern matches: %zu", exactMatches.size());

    if (g_blockLegacyVtable) {
        for (std::size_t index = 0; index < 384; ++index) {
            auto* function = reinterpret_cast<std::uint8_t*>(safeReadPointer(g_blockLegacyVtable + index));
            if (!addressInSection(function, text, textSize)) break;
            if (std::find(exactMatches.begin(), exactMatches.end(), function) != exactMatches.end()) {
                std::int32_t offset = -1;
                if (decodeSimpleIntGetter(function, offset)) {
                    g_renderLayerVtableIndex = index;
                    g_renderLayerFieldOffset = offset;
                    logLine("[+] getRenderLayer found in BlockLegacy vtable slot %zu, field +0x%X",
                            index, static_cast<unsigned>(offset));
                    return function;
                }
            }
        }
    }

    if (exactMatches.size() == 1) {
        std::int32_t offset = -1;
        if (decodeSimpleIntGetter(exactMatches.front(), offset)) {
            g_renderLayerFieldOffset = offset;
            logLine("[+] getRenderLayer accepted from unique exact signature, field +0x%X",
                    static_cast<unsigned>(offset));
            return exactMatches.front();
        }
    }

    // Borion's known historical vtable index. Never patch it blindly: the function
    // must still decode as a padded no-argument int getter.
    if (g_blockLegacyVtable) {
        constexpr std::size_t preferredIndex = 180;
        auto* function = reinterpret_cast<std::uint8_t*>(safeReadPointer(g_blockLegacyVtable + preferredIndex));
        std::int32_t offset = -1;
        if (addressInSection(function, text, textSize) && decodeSimpleIntGetter(function, offset)) {
            g_renderLayerVtableIndex = preferredIndex;
            g_renderLayerFieldOffset = offset;
            logLine("[+] getRenderLayer accepted from validated vtable slot 180, field +0x%X",
                    static_cast<unsigned>(offset));
            return function;
        }

        logLine("[!] BlockLegacy slot 180 is not the expected padded int getter on this build");
    }

    logLine("[-] Could not safely resolve BlockLegacy::getRenderLayer");
    return nullptr;
}

int __fastcall hookedRenderLayer(void* blockLegacy) {
    std::int32_t originalLayer = 0;
    if (g_renderLayerFieldOffset < 0
        || !safeReadInt32(reinterpret_cast<std::uint8_t*>(blockLegacy) + g_renderLayerFieldOffset, originalLayer)) {
        return 0;
    }

    if (!g_xrayEnabled.load(std::memory_order_relaxed) || g_unloading.load(std::memory_order_relaxed)) {
        return originalLayer;
    }

    std::string identifier;
    if (!readBlockName(blockLegacy, identifier)) {
        // Unknown layout: fail open instead of making every block disappear.
        return originalLayer;
    }

    if (shouldRemainVisible(identifier)) return originalLayer;

    // Horion/Borion XRay uses render layer 10 for blocks that should disappear.
    return 10;
}

bool installRenderLayerPatch() {
    if (g_renderLayerPatch.installed) return true;

    auto* target = findRenderLayerGetter();
    if (!target) return false;

    std::int32_t verifiedOffset = -1;
    if (!decodeSimpleIntGetter(target, verifiedOffset) || verifiedOffset != g_renderLayerFieldOffset) {
        logLine("[-] Refusing render-layer patch: target validation changed");
        return false;
    }

    std::array<std::uint8_t, 12> patch{};
    patch[0] = 0x48;
    patch[1] = 0xB8; // mov rax, imm64
    const auto hookAddress = reinterpret_cast<std::uintptr_t>(&hookedRenderLayer);
    std::memcpy(patch.data() + 2, &hookAddress, sizeof(hookAddress));
    patch[10] = 0xFF;
    patch[11] = 0xE0; // jmp rax

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        logLine("[-] VirtualProtect(getRenderLayer) failed: %lu", GetLastError());
        return false;
    }

    std::memcpy(g_renderLayerPatch.original.data(), target, g_renderLayerPatch.original.size());
    std::memcpy(target, patch.data(), patch.size());
    FlushInstructionCache(GetCurrentProcess(), target, patch.size());

    DWORD ignored = 0;
    VirtualProtect(target, patch.size(), oldProtect, &ignored);

    g_renderLayerPatch.address = target;
    g_renderLayerPatch.installed = true;
    logLine("[+] BlockLegacy::getRenderLayer patched at 0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(target)));
    return true;
}

void uninstallRenderLayerPatch() {
    if (!g_renderLayerPatch.installed || !g_renderLayerPatch.address) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(g_renderLayerPatch.address, g_renderLayerPatch.original.size(),
                       PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::memcpy(g_renderLayerPatch.address, g_renderLayerPatch.original.data(),
                    g_renderLayerPatch.original.size());
        FlushInstructionCache(GetCurrentProcess(), g_renderLayerPatch.address,
                              g_renderLayerPatch.original.size());
        DWORD ignored = 0;
        VirtualProtect(g_renderLayerPatch.address, g_renderLayerPatch.original.size(), oldProtect, &ignored);
    }

    g_renderLayerPatch = {};
    logLine("[+] getRenderLayer patch removed");
}

void* findClientInstance() {
    if (g_clientInstance && isReadableAddress(g_clientInstance)) return g_clientInstance;

    std::size_t textSize = 0;
    auto* text = getSection(g_minecraft, ".text", textSize);
    if (!text) return nullptr;

    constexpr const char* clientVtablePattern =
        "48 8D 05 ?? ?? ?? ?? 49 89 45 00 48 8D 05 ?? ?? ?? ?? 49 89 45 18 "
        "48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ??";

    auto* match = findPattern(text, textSize, parsePattern(clientVtablePattern));
    if (!match) return nullptr;

    const auto clientVtable = resolveRip(match, 3, 7);
    const auto hits = findWritablePointers(clientVtable, 8);
    if (hits.empty()) return nullptr;

    g_clientInstance = reinterpret_cast<void*>(hits.front());
    logLine("[+] ClientInstance: 0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g_clientInstance)));
    return g_clientInstance;
}

void resolveRebuildFunction() {
    if (g_rebuildChunk) return;

    std::size_t textSize = 0;
    auto* text = getSection(g_minecraft, ".text", textSize);
    if (!text) return;

    const auto pattern = parsePattern(
        "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC ?? "
        "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 48 8B F9 48 8D A9");
    auto* match = findPattern(text, textSize, pattern);
    if (match) {
        g_rebuildChunk = reinterpret_cast<RebuildChunkFn>(match);
        logLine("[+] RenderChunkCoordinator::rebuildAllRenderChunkGeometry candidate: 0x%llX",
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(match)));
    } else {
        logLine("[!] Chunk rebuild signature not found; enter/re-enter the world to rebuild geometry");
    }
}

bool safeCallRebuild(void* coordinator) {
    if (!g_rebuildChunk || !coordinator) return false;
#if defined(_MSC_VER)
    __try {
        g_rebuildChunk(coordinator);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    g_rebuildChunk(coordinator);
    return true;
#endif
}

bool forceChunkRebuild() {
    resolveRebuildFunction();
    if (!g_rebuildChunk) return false;

    auto* client = reinterpret_cast<std::uint8_t*>(findClientInstance());
    if (!client) {
        logLine("[!] Chunk rebuild: ClientInstance unavailable (enter a world first)");
        return false;
    }

    // Current maintained Bedrock SDK layout for ClientInstance::levelRenderer.
    void* levelRenderer = safeReadPointer(client + 0x1B8);
    if (!levelRenderer || !isReadableAddress(levelRenderer)) {
        logLine("[!] Chunk rebuild: ClientInstance+0x1B8 is not a readable LevelRenderer");
        return false;
    }

    // Borion rebuild path: LevelRenderer+0x20 -> sentinel list;
    // each node's +0x18 points at a RenderChunkCoordinator.
    void* sentinel = safeReadPointer(reinterpret_cast<std::uint8_t*>(levelRenderer) + 0x20);
    if (!sentinel || !isReadableAddress(sentinel)) {
        logLine("[!] Chunk rebuild: LevelRenderer+0x20 list unavailable");
        return false;
    }

    void* node = safeReadPointer(sentinel);
    std::size_t rebuilt = 0;
    std::size_t iterations = 0;
    while (node && node != sentinel && iterations++ < 512) {
        if (!isReadableAddress(node)) break;
        void* coordinator = safeReadPointer(reinterpret_cast<std::uint8_t*>(node) + 0x18);
        if (coordinator && isReadableAddress(coordinator) && safeCallRebuild(coordinator)) {
            ++rebuilt;
        }
        node = safeReadPointer(node);
    }

    logLine("[+] Chunk rebuild request completed: %zu coordinator(s)", rebuilt);
    return rebuilt > 0;
}

void dumpBlockLegacyDiagnostics() {
    if (!g_blockLegacyVtable) g_blockLegacyVtable = findBlockLegacyVtable();
    if (!g_blockLegacyVtable) return;

    const auto hits = findWritablePointers(reinterpret_cast<std::uintptr_t>(g_blockLegacyVtable), 32);
    logLine("[+] Live BlockLegacy candidates: %zu", hits.size());
    std::size_t shown = 0;
    for (const auto address : hits) {
        std::string name;
        if (readBlockName(reinterpret_cast<void*>(address), name)) {
            logLine("    BlockLegacy 0x%llX -> %s",
                    static_cast<unsigned long long>(address), name.c_str());
            if (++shown >= 12) break;
        }
    }
}

void setXray(bool enabled, bool rebuild) {
    if (enabled && !g_renderLayerPatch.installed) {
        if (!installRenderLayerPatch()) {
            logLine("[-] XRay cannot enable: render-layer hook unresolved");
            Beep(300, 140);
            return;
        }
    }

    g_xrayEnabled.store(enabled, std::memory_order_relaxed);
    logLine("[+] XRAY %s", enabled ? "ON" : "OFF");
    Beep(enabled ? 900 : 500, 90);

    if (rebuild) forceChunkRebuild();
}

void runDiagnostics() {
    logLine("---------------- diagnostics ----------------");
    if (!g_renderLayerPatch.installed) installRenderLayerPatch();
    logLine("[+] hook installed=%s, xray=%s, renderField=0x%X, vslot=%s",
            g_renderLayerPatch.installed ? "true" : "false",
            g_xrayEnabled.load() ? "ON" : "OFF",
            static_cast<unsigned>(g_renderLayerFieldOffset),
            g_renderLayerVtableIndex == static_cast<std::size_t>(-1) ? "unknown" : "resolved");
    findClientInstance();
    dumpBlockLegacyDiagnostics();
    resolveRebuildFunction();
    logLine("-------------------------------------------------");
}

DWORD WINAPI workerThread(void*) {
    openLog();
    logLine("============================================================");
    logLine("MINE MOD - internal Bedrock XRay");
    logLine("Target fingerprint: Minecraft Bedrock 1.26.4501.0 / 26.45");
    logLine("Reference design: BlockLegacy render-layer XRay (Horion/Borion style)");
    logLine("F6 = toggle XRay | F7 = diagnostics | F8 = rebuild chunks | F12 = unload");

    g_minecraft = GetModuleHandleW(L"Minecraft.Windows.exe");
    if (!g_minecraft) {
        logLine("[-] Minecraft.Windows.exe module not found");
        if (g_log) {
            std::fclose(g_log);
            g_log = nullptr;
        }
        FreeLibraryAndExitThread(g_self, 1);
        return 1;
    }

    loadVisibleTokens();
    Sleep(1000);

    if (installRenderLayerPatch()) {
        // Enable immediately. If injected before entering a world, new chunk geometry
        // is generated through the XRay hook even when the rebuild signature changed.
        setXray(true, true);
    } else {
        logLine("[-] Initial XRay hook failed. Press F7 after entering a world for diagnostics.");
        Beep(250, 180);
    }

    while (true) {
        if (GetAsyncKeyState(VK_F6) & 1) {
            setXray(!g_xrayEnabled.load(std::memory_order_relaxed), true);
        }
        if (GetAsyncKeyState(VK_F7) & 1) {
            runDiagnostics();
        }
        if (GetAsyncKeyState(VK_F8) & 1) {
            forceChunkRebuild();
        }
        if (GetAsyncKeyState(VK_F12) & 1) {
            logLine("[+] F12 pressed: unloading MINE MOD");
            break;
        }
        Sleep(30);
    }

    g_unloading.store(true, std::memory_order_relaxed);
    g_xrayEnabled.store(false, std::memory_order_relaxed);
    forceChunkRebuild();
    Sleep(100);
    uninstallRenderLayerPatch();

    if (g_log) {
        std::fclose(g_log);
        g_log = nullptr;
    }

    FreeLibraryAndExitThread(g_self, 0);
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, workerThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
