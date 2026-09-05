#include <windows.h>
#include <tlhelp32.h>

#include <filesystem>
#include <iostream>
#include <string>

namespace {

DWORD findProcessId(const wchar_t* processName) {
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

std::filesystem::path ownDirectory() {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return {};
    return std::filesystem::path(path).parent_path();
}

void printWinError(const char* label) {
    const DWORD error = GetLastError();
    std::cerr << "[-] " << label << " failed. GetLastError=" << error << "\n";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::wcout << L"MineModLoader - simple LoadLibraryW loader\n";
    std::wcout << L"Target: Minecraft.Windows.exe\n\n";

    std::filesystem::path dllPath;
    if (argc >= 2) {
        dllPath = std::filesystem::absolute(argv[1]);
    } else {
        dllPath = ownDirectory() / L"MineMod.dll";
    }

    if (!std::filesystem::exists(dllPath)) {
        std::wcerr << L"[-] DLL not found: " << dllPath.wstring() << L"\n";
        return 1;
    }

    const DWORD pid = findProcessId(L"Minecraft.Windows.exe");
    if (!pid) {
        std::wcerr << L"[-] Minecraft.Windows.exe not found. Open the game first.\n";
        return 1;
    }

    std::wcout << L"[+] PID: " << pid << L"\n";
    std::wcout << L"[+] DLL: " << dllPath.wstring() << L"\n";

    const DWORD access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;

    HANDLE process = OpenProcess(access, FALSE, pid);
    if (!process) {
        printWinError("OpenProcess");
        return 2;
    }

    const std::wstring dll = dllPath.wstring();
    const SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);

    void* remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        printWinError("VirtualAllocEx");
        CloseHandle(process);
        return 3;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remotePath, dll.c_str(), bytes, &written) || written != bytes) {
        printWinError("WriteProcessMemory");
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 4;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto* loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
    if (!loadLibrary) {
        printWinError("GetProcAddress(LoadLibraryW)");
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 5;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remotePath, 0, nullptr);
    if (!thread) {
        printWinError("CreateRemoteThread");
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 6;
    }

    const DWORD wait = WaitForSingleObject(thread, 10000);
    if (wait != WAIT_OBJECT_0) {
        std::cerr << "[-] Timed out waiting for LoadLibraryW.\n";
        CloseHandle(thread);
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 7;
    }

    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);

    CloseHandle(thread);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);

    if (exitCode == 0) {
        std::cerr << "[-] LoadLibraryW returned 0. The DLL was not loaded.\n";
        return 8;
    }

    std::cout << "[+] MineMod.dll loaded.\n";
    std::cout << "[+] Open %TEMP%\\MineMod.log to see the probe result.\n";
    std::cout << "[+] In game: F7 reprobes, F12 unloads the DLL.\n";
    return 0;
}
