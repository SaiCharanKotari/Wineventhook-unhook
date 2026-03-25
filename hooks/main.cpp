#include <windows.h>
#include <stdio.h>
#include <utility>
#include <psapi.h>
#include <ctype.h>

extern "C" {
#include "MinHook.h"
}

#include <dxgi.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "psapi.lib")

// ================= LOG FUNCTION =================
void Log(const char* msg) {
    FILE* f = fopen("C:\\temp\\hooklog.txt", "a+");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

// ================= TARGET FILTER LOGIC =================
static bool IsTarget(const char* str) {
    if (!str || str[0] == '\0') return false;
    char lower[512] = {0};
    for (int i = 0; str[i] && i < 511; i++) {
        lower[i] = (char)tolower((unsigned char)str[i]);
    }
    // Block case-insensitive matches for whatsapp, chrome, google
    if (strstr(lower, "whatsapp") != NULL) return true;
    if (strstr(lower, "chrome") != NULL) return true;
    if (strstr(lower, "google") != NULL) return true;
    return false;
}

static bool IsTargetW(const wchar_t* wstr) {
    if (!wstr || wstr[0] == L'\0') return false;
    char strA[512] = {0};
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, strA, sizeof(strA), NULL, NULL);
    return IsTarget(strA);
}

// Original function pointers
typedef int   (WINAPI* GetWindowTextA_t)(HWND, LPSTR, int);
typedef int   (WINAPI* GetWindowTextW_t)(HWND, LPWSTR, int);
typedef DWORD (WINAPI* GetWindowThreadProcessId_t)(HWND, LPDWORD);
static GetWindowTextA_t origGetWindowTextA = NULL;
static GetWindowTextW_t origGetWindowTextW = NULL;
static GetWindowThreadProcessId_t origGetWindowThreadProcessId = NULL;

static void ExeFromHwnd(HWND hwnd, char* out, int outLen) {
    out[0] = 0;
    DWORD pid = 0;
    if (origGetWindowThreadProcessId) origGetWindowThreadProcessId(hwnd, &pid);
    else GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return;
    GetModuleBaseNameA(h, NULL, out, outLen);
    CloseHandle(h);
}

static bool IsHwndBlocked(HWND hwnd) {
    char title[512] = {0};
    if (origGetWindowTextA) origGetWindowTextA(hwnd, title, sizeof(title));
    else GetWindowTextA(hwnd, title, sizeof(title));
    if (IsTarget(title)) return true;

    char exe[MAX_PATH] = {0};
    ExeFromHwnd(hwnd, exe, sizeof(exe));
    if (IsTarget(exe)) return true;

    return false;
}

// ================= HOOKS =================

int WINAPI hookedGetWindowTextA(HWND hwnd, LPSTR lpString, int nMaxCount) {
    int r = origGetWindowTextA(hwnd, lpString, nMaxCount);
    if (r > 0) {
        if (IsTarget(lpString) || IsHwndBlocked(hwnd)) {
            lpString[0] = '\0';
            return 0;
        }
    }
    return r;
}

int WINAPI hookedGetWindowTextW(HWND hwnd, LPWSTR lpString, int nMaxCount) {
    int r = origGetWindowTextW(hwnd, lpString, nMaxCount);
    if (r > 0) {
        if (IsTargetW(lpString) || IsHwndBlocked(hwnd)) {
            lpString[0] = L'\0';
            return 0;
        }
    }
    return r;
}

typedef BOOL (WINAPI* EnumWindows_t)(WNDENUMPROC, LPARAM);
static EnumWindows_t origEnumWindows = NULL;
static WNDENUMPROC g_appEnumCallback = NULL;
static LPARAM g_appEnumLParam = 0;

BOOL CALLBACK FilteredEnumWindowsProc(HWND hwnd, LPARAM) {
    if (IsHwndBlocked(hwnd)) return TRUE; // skip
    return g_appEnumCallback(hwnd, g_appEnumLParam); // pass to app
}

BOOL WINAPI hookedEnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    g_appEnumCallback = lpEnumFunc;
    g_appEnumLParam = lParam;
    return origEnumWindows(FilteredEnumWindowsProc, 0);
}

DWORD WINAPI hookedGetWindowThreadProcessId(HWND hwnd, LPDWORD lpdwProcessId) {
    DWORD tid = origGetWindowThreadProcessId(hwnd, lpdwProcessId);
    if (IsHwndBlocked(hwnd)) {
        if (lpdwProcessId) *lpdwProcessId = 0;
        return 0;
    }
    return tid;
}

typedef BOOL (WINAPI* IsWindowVisible_t)(HWND);
static IsWindowVisible_t origIsWindowVisible = NULL;
BOOL WINAPI hookedIsWindowVisible(HWND hwnd) {
    if (IsHwndBlocked(hwnd)) return FALSE;
    return origIsWindowVisible(hwnd);
}

// ================= EnumDisplayMonitors =================
typedef BOOL (WINAPI* EnumDisplayMonitors_t)(
    HDC, LPCRECT, MONITORENUMPROC, LPARAM);

EnumDisplayMonitors_t originalEnumDisplayMonitors = NULL;
HMONITOR g_firstMonitor = NULL;

BOOL CALLBACK GrabFirstMonitor(HMONITOR hMon, HDC hdc, LPRECT rect, LPARAM data) {
    if (!g_firstMonitor) {
        g_firstMonitor = hMon;
    }
    return FALSE; // stop after first
}

BOOL WINAPI hookedEnumDisplayMonitors(
    HDC hdc, LPCRECT lprcClip,
    MONITORENUMPROC lpfnEnum, LPARAM dwData)
{
    Log("EnumDisplayMonitors called");

    if (!lpfnEnum)
        return FALSE;

    g_firstMonitor = NULL;
    originalEnumDisplayMonitors(hdc, lprcClip, GrabFirstMonitor, 0);

    if (!g_firstMonitor)
        return FALSE;

    MONITORINFOEXA mi = {0};
    mi.cbSize = sizeof(mi);
    GetMonitorInfoA(g_firstMonitor, (LPMONITORINFO)&mi);

    char dbg[256];
    snprintf(dbg, sizeof(dbg), "Captured Monitor: %s | Resolution: %dx%d",
        mi.szDevice,
        mi.rcMonitor.right - mi.rcMonitor.left,
        mi.rcMonitor.bottom - mi.rcMonitor.top);
    Log(dbg);

    lpfnEnum(g_firstMonitor, NULL, &mi.rcMonitor, dwData);

    return TRUE;
}

// ================= INIT =================
DWORD WINAPI InitHook(LPVOID) {
    CreateDirectoryA("C:\\temp", NULL);

    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "MinHook init failed", "Error", MB_OK);
        return 0;
    }

    HMODULE user32 = GetModuleHandleA("user32.dll");

    MH_CreateHook((LPVOID)GetProcAddress(user32, "GetWindowTextA"), (LPVOID)hookedGetWindowTextA, (LPVOID*)&origGetWindowTextA);
    MH_CreateHook((LPVOID)GetProcAddress(user32, "GetWindowTextW"), (LPVOID)hookedGetWindowTextW, (LPVOID*)&origGetWindowTextW);
    MH_CreateHook((LPVOID)GetProcAddress(user32, "GetWindowThreadProcessId"), (LPVOID)hookedGetWindowThreadProcessId, (LPVOID*)&origGetWindowThreadProcessId);
    MH_CreateHook((LPVOID)GetProcAddress(user32, "EnumWindows"), (LPVOID)hookedEnumWindows, (LPVOID*)&origEnumWindows);
    MH_CreateHook((LPVOID)GetProcAddress(user32, "IsWindowVisible"), (LPVOID)hookedIsWindowVisible, (LPVOID*)&origIsWindowVisible);
    
    // Existing monitor hook
    MH_CreateHook((LPVOID)GetProcAddress(user32, "EnumDisplayMonitors"),
                  (LPVOID)hookedEnumDisplayMonitors,
                  (LPVOID*)&originalEnumDisplayMonitors);

    // ---- ENABLE ----
    MH_EnableHook(MH_ALL_HOOKS);

    MessageBoxA(NULL, "ALL HOOKS ACTIVE", "SUCCESS", MB_OK);

    return 0;
}

// ================= DLL ENTRY =================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, InitHook, NULL, 0, NULL);
    }
    return TRUE;
}