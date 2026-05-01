#pragma once
#include <windows.h>
#include "vault.h"

// Entry point for the GUI application
int RunApp(HINSTANCE hInstance, int nCmdShow, Vault& vault, const std::string& vault_path);
