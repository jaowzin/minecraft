#include "process.hpp"

#include <TlHelp32.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace {

bool iequals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(), [](wchar_t lhs, wchar_t rhs) {
        return towlower(lhs) == towlower(rhs);
    });
}

} // namespace

RemoteProcess::~RemoteProcess() {
    close();
}

bool RemoteProcess::attach(const std::wstring& processName) {
    close();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (iequals(entry.szExeFile, processName)) {
                pid_ = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (pid_ == 0) {
        return false;
    }

    handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_);
    if (!handle_) {
        pid_ = 0;
        return false;
    }

    return true;
}

void RemoteProcess::close() {
    if (handle_) {
        CloseHandle(handle_);
        handle_ = nullptr;
    }
    pid_ = 0;
}

std::optional<ModuleInfo> RemoteProcess::findModule(const std::wstring& moduleName) const {
    if (!valid()) {
        return std::nullopt;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<ModuleInfo> result;

    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (iequals(entry.szModule, moduleName)) {
                result = ModuleInfo{
                    entry.szModule,
                    entry.szExePath,
                    reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
                    static_cast<std::size_t>(entry.modBaseSize)
                };
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return result;
}

std::vector<SectionInfo> RemoteProcess::enumerateSections(const ModuleInfo& module) const {
    std::vector<SectionInfo> sections;

    IMAGE_DOS_HEADER dos{};
    if (!read(module.base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return sections;
    }

    IMAGE_NT_HEADERS64 nt{};
    const auto ntAddress = module.base + static_cast<std::uintptr_t>(dos.e_lfanew);
    if (!read(ntAddress, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return sections;
    }

    const auto sectionTable = ntAddress
        + sizeof(DWORD)
        + sizeof(IMAGE_FILE_HEADER)
        + nt.FileHeader.SizeOfOptionalHeader;

    sections.reserve(nt.FileHeader.NumberOfSections);

    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER header{};
        const auto address = sectionTable + static_cast<std::uintptr_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (!read(address, &header, sizeof(header))) {
            break;
        }

        std::array<char, IMAGE_SIZEOF_SHORT_NAME + 1> name{};
        std::memcpy(name.data(), header.Name, IMAGE_SIZEOF_SHORT_NAME);

        std::size_t size = static_cast<std::size_t>(header.Misc.VirtualSize);
        if (size == 0) {
            size = static_cast<std::size_t>(header.SizeOfRawData);
        }

        sections.push_back(SectionInfo{
            std::string(name.data()),
            module.base + static_cast<std::uintptr_t>(header.VirtualAddress),
            size,
            header.Characteristics
        });
    }

    return sections;
}

bool RemoteProcess::read(std::uintptr_t address, void* buffer, std::size_t size) const {
    if (!valid() || !buffer || size == 0) {
        return false;
    }

    SIZE_T bytesRead = 0;
    return ReadProcessMemory(
        handle_,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytesRead
    ) != FALSE && bytesRead == size;
}

std::vector<std::uint8_t> RemoteProcess::readBytes(std::uintptr_t address, std::size_t size) const {
    std::vector<std::uint8_t> bytes(size);
    if (!read(address, bytes.data(), bytes.size())) {
        bytes.clear();
    }
    return bytes;
}

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), required, nullptr, nullptr);
    return result;
}

std::wstring widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int required = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }

    std::wstring result(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), required);
    return result;
}
