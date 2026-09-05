#include "pattern.hpp"
#include "process.hpp"

#include <algorithm>
#include <cstdint>
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
    bool help = false;
};

void printUsage() {
    std::cout
        << "BedrockScanner - external read-only AOB scanner\n\n"
        << "Usage:\n"
        << "  BedrockScanner.exe\n"
        << "  BedrockScanner.exe --pattern \"48 8B 0D ? ? ? ? 48 85 C9\"\n"
        << "  BedrockScanner.exe --pattern \"48 8B 0D ? ? ? ?\" --rip 3 7\n\n"
        << "Options:\n"
        << "  --process <exe>          Target process (default Minecraft.Windows.exe)\n"
        << "  --module <exe>           Module to scan (default Minecraft.Windows.exe)\n"
        << "  --section <name>         PE section to scan (default .text)\n"
        << "  --pattern <AOB>          Hex bytes separated by spaces; ? or ?? = wildcard\n"
        << "  --rip <dispOff> <size>   Resolve signed disp32 relative to instruction end\n"
        << "  --help                    Show this message\n\n"
        << "With no --pattern the tool prints PID, module information and PE sections.\n";
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
            if (results.empty() || results.back() != absolute) {
                results.push_back(absolute);
            }
        }

        const std::size_t keep = pattern.size() > 1
            ? std::min(pattern.size() - 1, scanBuffer.size())
            : 0;
        tail.assign(scanBuffer.end() - static_cast<std::ptrdiff_t>(keep), scanBuffer.end());
        offset += toRead;
    }

    return results;
}

void printHexAddress(std::uintptr_t value) {
    std::cout << "0x" << std::hex << std::uppercase << value << std::dec;
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
    std::cout << "[+] Base:   ";
    printHexAddress(module->base);
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

    if (!options.pattern) {
        std::cout << "\n[+] Ready. Pass --pattern to scan a section.\n";
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
        std::cout << "  [" << i << "] VA=";
        printHexAddress(match);
        std::cout << " RVA=0x" << std::hex << std::uppercase << (match - module->base) << std::dec;

        if (options.ripDispOffset && options.ripInstructionSize) {
            const auto displacement = process.readValue<std::int32_t>(match + *options.ripDispOffset);
            if (displacement) {
                const auto target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(match + *options.ripInstructionSize)
                    + static_cast<std::intptr_t>(*displacement)
                );
                std::cout << " RIP_TARGET=";
                printHexAddress(target);
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
