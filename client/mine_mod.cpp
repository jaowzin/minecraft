#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

HMODULE g_self = nullptr;
FILE* g_log = nullptr;

void logLine(const char* format, ...) {
    char buffer[1024]{};
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

void openLog() {
    wchar_t tempPath[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempPath)) return;

    std::wstring path = tempPath;
    path += L"MineMod.log";
    _wfopen_s(&g_log, path.c_str(), L"a+, ccs=UTF-8");
}

bool isWritableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS)) return false;
    const DWORD base = protect & 0xFF;
    return base == PAGE_READWRITE
        || base == PAGE_WRITECOPY
        || base == PAGE_EXECUTE_READWRITE
        || base == PAGE_EXECUTE_WRITECOPY;
}

bool isReadableAddress(const void* address) {
    if (!address) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) return false;
    return true;
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

std::uintptr_t resolveRip(std::uint8_t* instruction, std::size_t dispOffset, std::size_t instructionSize) {
    std::int32_t displacement{};
    std::memcpy(&displacement, instruction + dispOffset, sizeof(displacement));
    return reinterpret_cast<std::uintptr_t>(instruction + instructionSize) + static_cast<std::intptr_t>(displacement);
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
                if (ReadProcessMemory(self, reinterpret_cast<const void*>(regionBase + offset), bytes.data(), toRead, &read) && read >= sizeof(std::uintptr_t)) {
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

template <typename R>
R callVirtual(void* self, std::size_t index) {
    auto** table = *reinterpret_cast<void***>(self);
    using Fn = R(__fastcall*)(void*);
    return reinterpret_cast<Fn>(table[index])(self);
}

void probeClient() {
    HMODULE minecraft = GetModuleHandleW(L"Minecraft.Windows.exe");
    if (!minecraft) {
        logLine("[-] Minecraft.Windows.exe module not found");
        return;
    }

    constexpr const char* kClientVtablePattern =
        "48 8D 05 ?? ?? ?? ?? 49 89 45 00 48 8D 05 ?? ?? ?? ?? 49 89 45 18 "
        "48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ??";

    std::size_t textSize = 0;
    auto* text = getSection(minecraft, ".text", textSize);
    const auto pattern = parsePattern(kClientVtablePattern);
    auto* match = findPattern(text, textSize, pattern);
    if (!match) {
        logLine("[-] ClientInstance vtable signature not found");
        return;
    }

    const auto moduleBase = reinterpret_cast<std::uintptr_t>(minecraft);
    const auto clientVtable = resolveRip(match, 3, 7);
    logLine("[+] Minecraft base=0x%llX", static_cast<unsigned long long>(moduleBase));
    logLine("[+] ClientInstance signature RVA=0x%llX", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(match) - moduleBase));
    logLine("[+] ClientInstance vtable=0x%llX RVA=0x%llX",
        static_cast<unsigned long long>(clientVtable),
        static_cast<unsigned long long>(clientVtable - moduleBase));

    const auto hits = findWritablePointers(clientVtable, 16);
    logLine("[+] live ClientInstance candidates=%zu", hits.size());
    for (std::size_t i = 0; i < hits.size(); ++i) {
        logLine("    [%zu] 0x%llX", i, static_cast<unsigned long long>(hits[i]));
    }
    if (hits.empty()) {
        logLine("[-] No live ClientInstance found. Enter a world and press F7.");
        return;
    }

    void* client = reinterpret_cast<void*>(hits.front());
    auto** table = *reinterpret_cast<void***>(client);
    logLine("[+] ClientInstance=0x%llX", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(client)));
    logLine("[+] vslot 0x1E function=0x%llX", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(table[0x1E])));
    logLine("[+] vslot 0x1F function=0x%llX", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(table[0x1F])));

    void* region = nullptr;
    void* localPlayer = nullptr;

#if defined(_MSC_VER)
    __try {
        region = callVirtual<void*>(client, 0x1E);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logLine("[-] vslot 0x1E raised SEH exception 0x%08lX", GetExceptionCode());
    }

    __try {
        localPlayer = callVirtual<void*>(client, 0x1F);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logLine("[-] vslot 0x1F raised SEH exception 0x%08lX", GetExceptionCode());
    }
#else
    region = callVirtual<void*>(client, 0x1E);
    localPlayer = callVirtual<void*>(client, 0x1F);
#endif

    logLine("[+] getRegion/BlockSource -> 0x%llX readable=%s",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(region)),
        isReadableAddress(region) ? "true" : "false");
    logLine("[+] getLocalPlayer -> 0x%llX readable=%s",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(localPlayer)),
        isReadableAddress(localPlayer) ? "true" : "false");

    if (region && localPlayer && isReadableAddress(region) && isReadableAddress(localPlayer)) {
        logLine("[+] PASS: internal ClientInstance -> BlockSource + LocalPlayer path is live.");
    } else {
        logLine("[!] Internal path did not fully validate yet. Stay in a world and press F7 to retry.");
    }
}

DWORD WINAPI workerThread(void*) {
    openLog();
    logLine("============================================================");
    logLine("MineMod internal probe loaded. Build target: Bedrock 1.26.4501.0");
    logLine("F7 = reprobe ClientInstance/BlockSource/LocalPlayer");
    logLine("F12 = unload MineMod.dll");

    Sleep(1500);
    probeClient();

    while (true) {
        if (GetAsyncKeyState(VK_F7) & 1) {
            logLine("[+] F7 pressed: reprobe");
            probeClient();
        }
        if (GetAsyncKeyState(VK_F12) & 1) {
            logLine("[+] F12 pressed: unloading");
            break;
        }
        Sleep(50);
    }

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
