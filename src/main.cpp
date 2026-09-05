#include "pattern.hpp"
#include "process.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

struct Options {
    std::wstring processName = L"Minecraft.Windows.exe";
    std::wstring moduleName = L"Minecraft.Windows.exe";
    std::string section = ".text";
    std::optional<std::string> pattern;
    std::optional<std::size_t> ripDispOffset;
    std::optional<std::size_t> ripInstructionSize;
    std::optional<std::uintptr_t> pointerValue;
    std::optional<std::uintptr_t> dumpAddress;
    std::optional<std::size_t> dumpSize;
    std::optional<std::uintptr_t> vtableAddress;
    std::optional<std::size_t> vtableIndex;
    std::size_t limit = 128;
    bool help = false;
};

std::optional<std::uintptr_t> parseAddress(const char* text) {
    try {
        return static_cast<std::uintptr_t>(std::stoull(text, nullptr, 0));
    } catch (...) {
        return std::nullopt;
    }
}

void printUsage() {
    std::cout
        << "BedrockScanner - external read-only Bedrock discovery tool\n\n"
        << "Usage:\n"
        << "  BedrockScanner.exe\n"
        << "  BedrockScanner.exe --pattern \"48 8B 0D ? ? ? ?\" --rip 3 7\n"
        << "  BedrockScanner.exe --pointer 0x7FF600001000\n"
        << "  BedrockScanner.exe --dump 0x7FF600001000 96\n"
        << "  BedrockScanner.exe --vslot 0x7FF600001000 0x1F\n\n"
        << "Options:\n"
        << "  --process <exe>          Target process (default Minecraft.Windows.exe)\n"
        << "  --module <exe>           Module to scan (default Minecraft.Windows.exe)\n"
        << "  --section <name>         PE section for AOB scan (default .text)\n"
        << "  --pattern <AOB>          Hex bytes separated by spaces; ? or ?? = wildcard\n"
        << "  --rip <dispOff> <size>   Resolve signed disp32 relative to instruction end\n"
        << "  --pointer <address>      Find aligned copies of a pointer in writable committed memory\n"
        << "  --dump <address> <size>  Hex-dump remote memory\n"
        << "  --vslot <vtable> <idx>   Read a vtable function pointer and dump its first 96 bytes\n"
        << "  --limit <n>              Maximum pointer matches printed (default 128)\n"
        << "  --help                   Show this message\n";
}

std::optional<Options> parseArgs(int argc, char** argv) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto requireValue = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                return nullptr;
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--process") {
            const char* value = requireValue("--process");
            if (!value) return std::nullopt;
            options.processName = widen(value);
        } else if (arg == "--module") {
            const char* value = requireValue("--module");
            if (!value) return std::nullopt;
            options.moduleName = widen(value);
        } else if (arg == "--section") {
            const char* value = requireValue("--section");
            if (!value) return std::nullopt;
            options.section = value;
        } else if (arg == "--pattern") {
            const char* value = requireValue("--pattern");
            if (!value) return std::nullopt;
            options.pattern = value;
        } else if (arg == "--rip") {
            if (i + 2 >= argc) {
                std::cerr << "--rip needs <dispOffset> <instructionSize>\n";
                return std::nullopt;
            }
            try {
                options.ripDispOffset = static_cast<std::size_t>(std::stoull(argv[++i], nullptr, 0));
                options.ripInstructionSize = static_cast<std::size_t>(std::stoull(argv[++i], nullptr, 0));
            } catch (...) {
                std::cerr << "Invalid numeric arguments for --rip\n";
                return std::nullopt;
            }
        } else if (arg == "--pointer") {
            const char* value = requireValue("--pointer");
            if (!value) return std::nullopt;
            options.pointerValue = parseAddress(value);
            if (!options.pointerValue) {
                std::cerr << "Invalid pointer address\n";
                return std::nullopt;
            }
        } else if (arg == "--dump") {
            if (i + 2 >= argc) {
                std::cerr << "--dump needs <address> <size>\n";
                return std::nullopt;
            }
            options.dumpAddress = parseAddress(argv[++i]);
            try {
                options.dumpSize = static_cast<std::size_t>(std::stoull(argv[++i], nullptr, 0));
            } catch (...) {
                options.dumpSize.reset();
            }
            if (!options.dumpAddress || !options.dumpSize || *options.dumpSize == 0 || *options.dumpSize > 4096) {
                std::cerr << "Invalid --dump arguments (size must be 1..4096)\n";
                return std::nullopt;
            }
        } else if (arg == "--vslot") {
            if (i + 2 >= argc) {
                std::cerr << "--vslot needs <vtable> <index>\n";
                return std::nullopt;
            }
            options.vtableAddress = parseAddress(argv[++i]);
            try {
                options.vtableIndex = static_cast<std::size_t>(std::stoull(argv[++i], nullptr, 0));
            } catch (...) {
                options.vtableIndex.reset();
            }
            if (!options.vtableAddress || !options.vtableIndex) {
                std::cerr << "Invalid --vslot arguments\n";
                return std::nullopt;
            }
        } else if (arg == "--limit") {
            const char* value = requireValue("--limit");
            if (!value) return std::nullopt;
            try {
                options.limit = static_cast<std::size_t>(std::stoull(value, nullptr, 0));
            } catch (...) {
                return std::nullopt;
            }
            if (options.limit == 0 || options.limit > 4096) options.limit = 128;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return std::nullopt;
        }
    }

    if (options.ripDispOffset.has_value() != options.ripInstructionSize.has_value()) {
        std::cerr << "Incomplete --rip arguments\n";
        return std::nullopt;
    }

    return options;
}

std::string sectionFlags(DWORD c) {
    std::string flags;
    if (c & IMAGE_SCN_MEM_READ) flags += 'R';
    if (c & IMAGE_SCN_MEM_WRITE) flags += 'W';
    if (c & IMAGE_SCN_MEM_EXECUTE) flags += 'X';
    return flags.empty() ? "-" : flags;
}

std::vector<std::uintptr_t> scanRemoteSection(
    const RemoteProcess& process,
    const SectionInfo& section,
    const BytePattern& pattern
) {
    constexpr std::size_t chunkSize = 4 * 1024 * 1024;
    std::vector<std::uintptr_t> results;
    std::vector<std::uint8_t> tail;

    std::size_t offset = 0;
    while (offset < section.virtualSize) {
        const std::size_t toRead = std::min(chunkSize, section.virtualSize - offset);
        auto chunk = process.readBytes(section.address + offset, toRead);
        if (chunk.empty()) {
            tail.clear();
            offset += toRead;
            continue;
        }

        std::vector<std::uint8_t> scanBuffer;
        scanBuffer.reserve(tail.size() + chunk.size());
        scanBuffer.insert(scanBuffer.end(), tail.begin(), tail.end());
        scanBuffer.insert(scanBuffer.end(), chunk.begin(), chunk.end());

        const auto localMatches = findPatternMatches(scanBuffer, pattern);
        const std::uintptr_t bufferBase = section.address + offset - tail.size();
        for (const auto local : localMatches) {
            const auto absolute = bufferBase + local;
            if (results.empty() || results.back() != absolute) results.push_back(absolute);
        }

        const std::size_t keep = pattern.size() > 1
            ? std::min(pattern.size() - 1, scanBuffer.size())
            : 0;
        tail.assign(scanBuffer.end() - static_cast<std::ptrdiff_t>(keep), scanBuffer.end());
        offset += toRead;
    }
    return results;
}

bool isWritableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS)) return false;
    const DWORD base = protect & 0xFF;
    return base == PAGE_READWRITE
        || base == PAGE_WRITECOPY
        || base == PAGE_EXECUTE_READWRITE
        || base == PAGE_EXECUTE_WRITECOPY;
}

std::vector<std::uintptr_t> scanWritablePointer(
    const RemoteProcess& process,
    std::uintptr_t target,
    std::size_t limit
) {
    std::vector<std::uintptr_t> results;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto cursor = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maxAddress = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    constexpr std::size_t chunkSize = 1024 * 1024;

    while (cursor < maxAddress && results.size() < limit) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(process.handle(), reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0) break;

        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionSize = static_cast<std::size_t>(mbi.RegionSize);
        if (mbi.State == MEM_COMMIT && isWritableProtection(mbi.Protect) && regionSize >= sizeof(std::uintptr_t)) {
            std::size_t offset = 0;
            while (offset < regionSize && results.size() < limit) {
                const auto toRead = std::min(chunkSize, regionSize - offset);
                auto bytes = process.readBytes(regionBase + offset, toRead);
                if (!bytes.empty()) {
                    const auto absoluteBase = regionBase + offset;
                    std::size_t i = static_cast<std::size_t>((8 - (absoluteBase & 7)) & 7);
                    for (; i + sizeof(std::uintptr_t) <= bytes.size() && results.size() < limit; i += 8) {
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

void printHexAddress(std::uintptr_t value) {
    std::cout << "0x" << std::hex << std::uppercase << value << std::dec;
}

void dumpBytes(const RemoteProcess& process, std::uintptr_t address, std::size_t size) {
    const auto bytes = process.readBytes(address, size);
    if (bytes.empty()) {
        std::cout << "[-] Could not read requested memory.\n";
        return;
    }

    for (std::size_t i = 0; i < bytes.size(); i += 16) {
        printHexAddress(address + i);
        std::cout << "  ";
        const auto row = std::min<std::size_t>(16, bytes.size() - i);
        for (std::size_t j = 0; j < row; ++j) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(bytes[i + j]) << ' ';
        }
        std::cout << std::setfill(' ') << std::dec << "\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    const auto parsed = parseArgs(argc, argv);
    if (!parsed) {
        printUsage();
        return 2;
    }

    const Options options = *parsed;
    if (options.help) {
        printUsage();
        return 0;
    }

    RemoteProcess process;
    std::cout << "[+] Waiting for process: " << narrow(options.processName) << "\n";
    if (!process.attach(options.processName)) {
        std::cerr << "[-] Could not attach. Open Minecraft Bedrock first and try again.\n";
        return 1;
    }
    std::cout << "[+] PID: " << process.pid() << "\n";

    const auto module = process.findModule(options.moduleName);
    if (!module) {
        std::cerr << "[-] Module not found: " << narrow(options.moduleName) << "\n";
        return 1;
    }

    std::cout << "[+] Module: " << narrow(module->name) << "\n";
    std::cout << "[+] Path:   " << narrow(module->path) << "\n";
    std::cout << "[+] Base:   "; printHexAddress(module->base);
    std::cout << "\n[+] Size:   0x" << std::hex << std::uppercase << module->size << std::dec << " bytes\n";

    const auto sections = process.enumerateSections(*module);
    if (sections.empty()) {
        std::cerr << "[-] Could not parse remote PE sections.\n";
        return 1;
    }

    std::cout << "\nPE sections:\n";
    for (const auto& section : sections) {
        std::cout << "  " << std::left << std::setw(9) << section.name
                  << " " << std::setw(3) << sectionFlags(section.characteristics)
                  << " addr=";
        printHexAddress(section.address);
        std::cout << " rva=0x" << std::hex << std::uppercase
                  << (section.address - module->base)
                  << " size=0x" << section.virtualSize << std::dec << "\n";
    }

    if (options.dumpAddress && options.dumpSize) {
        std::cout << "\n[+] Dumping "; printHexAddress(*options.dumpAddress);
        std::cout << " size=" << *options.dumpSize << "\n";
        dumpBytes(process, *options.dumpAddress, *options.dumpSize);
        return 0;
    }

    if (options.vtableAddress && options.vtableIndex) {
        const auto slotAddress = *options.vtableAddress + (*options.vtableIndex * sizeof(std::uintptr_t));
        const auto function = process.readValue<std::uintptr_t>(slotAddress);
        std::cout << "\n[+] VTable="; printHexAddress(*options.vtableAddress);
        std::cout << " index=0x" << std::hex << std::uppercase << *options.vtableIndex << std::dec;
        std::cout << " slot="; printHexAddress(slotAddress);
        if (!function || *function == 0) {
            std::cout << " function=<read failed>\n";
            return 3;
        }
        std::cout << " function="; printHexAddress(*function);
        if (*function >= module->base && *function < module->base + module->size) {
            std::cout << " (RVA=0x" << std::hex << std::uppercase << (*function - module->base) << std::dec << ")";
        }
        std::cout << "\n[+] First 96 function bytes:\n";
        dumpBytes(process, *function, 96);
        return 0;
    }

    if (options.pointerValue) {
        std::cout << "\n[+] Scanning writable committed memory for aligned pointer ";
        printHexAddress(*options.pointerValue);
        std::cout << " ...\n";
        const auto hits = scanWritablePointer(process, *options.pointerValue, options.limit);
        std::cout << "[+] Pointer matches (capped at " << options.limit << "): " << hits.size() << "\n";
        for (std::size_t i = 0; i < hits.size(); ++i) {
            std::cout << "  [" << i << "] "; printHexAddress(hits[i]); std::cout << "\n";
        }
        return hits.empty() ? 3 : 0;
    }

    if (!options.pattern) {
        std::cout << "\n[+] Ready. Pass --pattern, --pointer, --dump or --vslot.\n";
        return 0;
    }

    const auto sectionIt = std::find_if(sections.begin(), sections.end(), [&](const SectionInfo& section) {
        return section.name == options.section;
    });
    if (sectionIt == sections.end()) {
        std::cerr << "[-] Section not found: " << options.section << "\n";
        return 1;
    }

    std::string patternError;
    const auto pattern = parsePattern(*options.pattern, patternError);
    if (!pattern) {
        std::cerr << "[-] " << patternError << "\n";
        return 2;
    }

    std::cout << "\n[+] Scanning " << options.section << " for " << pattern->size() << " bytes...\n";
    const auto matches = scanRemoteSection(process, *sectionIt, *pattern);
    std::cout << "[+] Matches: " << matches.size() << "\n";

    for (std::size_t i = 0; i < matches.size(); ++i) {
        const auto match = matches[i];
        std::cout << "  [" << i << "] VA="; printHexAddress(match);
        std::cout << " RVA=0x" << std::hex << std::uppercase << (match - module->base) << std::dec;

        if (options.ripDispOffset && options.ripInstructionSize) {
            const auto displacement = process.readValue<std::int32_t>(match + *options.ripDispOffset);
            if (displacement) {
                const auto target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(match + *options.ripInstructionSize)
                    + static_cast<std::intptr_t>(*displacement)
                );
                std::cout << " RIP_TARGET="; printHexAddress(target);
                if (target >= module->base && target < module->base + module->size) {
                    std::cout << " (RVA=0x" << std::hex << std::uppercase << (target - module->base) << std::dec << ")";
                }
            } else {
                std::cout << " RIP_TARGET=<read failed>";
            }
        }
        std::cout << "\n";
    }

    return matches.empty() ? 3 : 0;
}
