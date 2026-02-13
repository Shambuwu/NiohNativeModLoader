#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>

static HMODULE realDinput8 = nullptr;
static std::wofstream gLog;

// -------- helpers --------

std::filesystem::path GetBaseDir() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    return std::filesystem::path(exePath).parent_path();
}

std::wstring Now() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t buf[64];
    swprintf_s(buf, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return buf;
}

// process-wide single init guard
bool AcquireProcessGuard() {
    HANDLE h = CreateMutexW(nullptr, TRUE, L"Global\\NiohModLoader_Init");
    if (!h) return true;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(h);
        return false;
    }
    return true;
}

// -------- logging --------

void OpenLog() {
    try {
        auto modsDir = GetBaseDir() / L"mods";
        if (!std::filesystem::exists(modsDir)) {
            std::filesystem::create_directory(modsDir);
        }
        gLog.open(modsDir / L"loader.log", std::ios::out | std::ios::app);
    }
    catch (...) {}
}

void Log(const std::wstring& msg) {
    try {
        if (gLog.is_open()) {
            gLog << Now() << msg << L"\n";
            gLog.flush();
        }
    }
    catch (...) {}
}

// -------- proxy forwarding --------

void LoadReal() {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, L"\\dinput8.dll");
    realDinput8 = LoadLibraryW(path);
}

FARPROC GetReal(const char* name) {
    if (!realDinput8) return nullptr;
    return GetProcAddress(realDinput8, name);
}

extern "C" {

    HRESULT WINAPI DirectInput8Create(HINSTANCE a, DWORD b, REFIID c, LPVOID* d, LPUNKNOWN e) {
        auto fn = (decltype(&DirectInput8Create))GetReal("DirectInput8Create");
        return fn ? fn(a, b, c, d, e) : E_FAIL;
    }

    HRESULT WINAPI DllCanUnloadNow() {
        auto fn = (decltype(&DllCanUnloadNow))GetReal("DllCanUnloadNow");
        return fn ? fn() : S_FALSE;
    }

    HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
        auto fn = (decltype(&DllGetClassObject))GetReal("DllGetClassObject");
        return fn ? fn(rclsid, riid, ppv) : E_FAIL;
    }

    HRESULT WINAPI DllRegisterServer() {
        auto fn = (decltype(&DllRegisterServer))GetReal("DllRegisterServer");
        return fn ? fn() : S_OK;
    }

    HRESULT WINAPI DllUnregisterServer() {
        auto fn = (decltype(&DllUnregisterServer))GetReal("DllUnregisterServer");
        return fn ? fn() : S_OK;
    }

}

// -------- mod loading --------

void LoadMods() {
    try {
        auto modsDir = GetBaseDir() / L"mods";
        Log(L"[Loader] Scanning mods directory");

        if (!std::filesystem::exists(modsDir)) {
            std::filesystem::create_directory(modsDir);
            Log(L"[Loader] Created mods directory");
            return;
        }

        for (auto& p : std::filesystem::directory_iterator(modsDir)) {
            if (p.path().extension() == L".dll") {
                Log(L"[Loader] Loading mod: " + p.path().wstring());
                LoadLibraryW(p.path().c_str());
            }
        }

        Log(L"[Loader] Finished loading mods");
    }
    catch (...) {
        Log(L"[Loader] Exception during LoadMods");
    }
}

DWORD WINAPI InitThread(LPVOID) {
    OpenLog();
    Log(L"[Loader] Session started");
    Sleep(5000);
    Log(L"[Loader] InitThread started");
    LoadMods();
    return 0;
}

// -------- entry --------

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (!AcquireProcessGuard()) {
            return TRUE;
        }
        DisableThreadLibraryCalls(GetModuleHandle(nullptr));
        LoadReal();
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
