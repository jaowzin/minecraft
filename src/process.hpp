#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct ModuleInfo {
    std::wstring name;
    std::wstring path;
    std::uintptr_t base{};
    std::size_t size{};
};

struct SectionInfo {
    std::string name;
    std::uintptr_t address{};
    std::size_t virtualSize{};
    DWORD characteristics{};
};

class RemoteProcess {
public:
    RemoteProcess() = default;
    ~RemoteProcess();

    RemoteProcess(const RemoteProcess&) = delete;
    RemoteProcess& operator=(const RemoteProcess&) = delete;

    bool attach(const std::wstring& processName);
    void close();

    [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
    [[nodiscard]] DWORD pid() const noexcept { return pid_; }
    [[nodiscard]] HANDLE handle() const noexcept { return handle_; }

    [[nodiscard]] std::optional<ModuleInfo> findModule(const std::wstring& moduleName) const;
    [[nodiscard]] std::vector<SectionInfo> enumerateSections(const ModuleInfo& module) const;
    [[nodiscard]] bool read(std::uintptr_t address, void* buffer, std::size_t size) const;
    [[nodiscard]] std::vector<std::uint8_t> readBytes(std::uintptr_t address, std::size_t size) const;

    template <typename T>
    [[nodiscard]] std::optional<T> readValue(std::uintptr_t address) const {
        T value{};
        if (!read(address, &value, sizeof(T))) {
            return std::nullopt;
        }
        return value;
    }

private:
    DWORD pid_{};
    HANDLE handle_{};
};

std::string narrow(const std::wstring& value);
std::wstring widen(const std::string& value);
