#include <windows.h>
#include <shlobj.h>
#include <string>
#include "vault.h"
#include "gui.h"

static std::string get_vault_path() {
    wchar_t path[MAX_PATH] = {};
    // Store vault in %APPDATA%\PasswordManager\vault.pwmv
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::wstring dir = std::wstring(path) + L"\\PasswordManager";
        CreateDirectoryW(dir.c_str(), nullptr);
        std::wstring full = dir + L"\\vault.pwmv";
        int n = WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, s.data(), n, nullptr, nullptr);
        return s;
    }
    return "vault.pwmv";
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    std::string vault_path = get_vault_path();

    Vault vault;
    vault.load(vault_path);

    return RunApp(hInstance, nCmdShow, vault, vault_path);
}
