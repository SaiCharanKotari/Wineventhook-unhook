#include <windows.h>
#include <stdio.h>
#include <utility>

extern "C" {
#include "MinHook.h"
}

#include <dxgi.h>
#pragma comment(lib, "dxgi.lib")

// ================= LOG FUNCTION =================
void Log(const char* msg) {
    FILE* f = fopen("C:\\temp\\hooklog.txt", "a+");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

// ================= DXGI HOOK =================
/*
typedef HRESULT(__stdcall* EnumOutputs_t)(
    IDXGIAdapter* This,
    UINT Output,
    IDXGIOutput** ppOutput
);

EnumOutputs_t originalEnumOutputs = nullptr;

HRESULT __stdcall hookedEnumOutputs(
    IDXGIAdapter* This,
    UINT Output,
    IDXGIOutput** ppOutput)
{
    Log("DXGI EnumOutputs called");
    MessageBoxA(NULL, "DXGI USED", "IMPORTANT", MB_OK);

    if (Output > 0) {
        return DXGI_ERROR_NOT_FOUND;
    }

    return originalEnumOutputs(This, Output, ppOutput);
}
*/


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

    // Step 1: get REAL first monitor
    g_firstMonitor = NULL;
    originalEnumDisplayMonitors(hdc, lprcClip, GrabFirstMonitor, 0);

    if (!g_firstMonitor)
        return FALSE;

    // Step 2: get its real rectangle
    MONITORINFO mi = {0};
    mi.cbSize = sizeof(mi);
    GetMonitorInfo(g_firstMonitor, &mi);

    // Step 3: call callback ONCE with REAL data
    lpfnEnum(g_firstMonitor, NULL, &mi.rcMonitor, dwData);

    return TRUE;
}

// ================= EnumDisplayDevices =================
/*
typedef BOOL (WINAPI* EnumDisplayDevicesA_t)(
    LPCSTR, DWORD, PDISPLAY_DEVICEA, DWORD);

EnumDisplayDevicesA_t originalEnumDisplayDevices = NULL;

BOOL WINAPI hookedEnumDisplayDevices(
    LPCSTR lpDevice, DWORD iDevNum,
    PDISPLAY_DEVICEA lpDisplayDevice, DWORD dwFlags) {

    Log("EnumDisplayDevices called");

    if (iDevNum > 0) {
        return FALSE;
    }

    return originalEnumDisplayDevices(lpDevice, iDevNum, lpDisplayDevice, dwFlags);
}
// ================= GetSystemMetrics =================
typedef int (WINAPI* GetSystemMetrics_t)(int);
GetSystemMetrics_t originalGetSystemMetrics = NULL;

int WINAPI hookedGetSystemMetrics(int nIndex) {
    if (nIndex == SM_CMONITORS) {
        Log("GetSystemMetrics called");
        MessageBoxA(NULL, "GetSystemMetrics used", "DEBUG", MB_OK);
        return 1;
    }
    return originalGetSystemMetrics(nIndex);
}
*/

// ================= INIT =================
DWORD WINAPI InitHook(LPVOID) {
    CreateDirectoryA("C:\\temp", NULL);

    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "MinHook init failed", "Error", MB_OK);
        return 0;
    }

    // ---- USER32 HOOKS ----
    /*
    MH_CreateHook((LPVOID)GetSystemMetrics,
                  (LPVOID)hookedGetSystemMetrics,
                  (LPVOID*)&originalGetSystemMetrics);
    */

    MH_CreateHook((LPVOID)EnumDisplayMonitors,
                  (LPVOID)hookedEnumDisplayMonitors,
                  (LPVOID*)&originalEnumDisplayMonitors);

    /*
    MH_CreateHook((LPVOID)EnumDisplayDevicesA,
                  (LPVOID)hookedEnumDisplayDevices,
                  (LPVOID*)&originalEnumDisplayDevices);
    */

    // ---- DXGI HOOK ----
    /*
    IDXGIFactory* factory = nullptr;
    if (CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&factory) != S_OK) {
        MessageBoxA(NULL, "DXGI Factory failed", "Error", MB_OK);
        return 0;
    }

    IDXGIAdapter* adapter = nullptr;
    if (factory->EnumAdapters(0, &adapter) != S_OK) {
        MessageBoxA(NULL, "Adapter failed", "Error", MB_OK);
        return 0;
    }

    void** vtable = *(void***)adapter;
    void* target = vtable[7]; // EnumOutputs

    if (!target) {
        MessageBoxA(NULL, "DXGI target null", "Error", MB_OK);
        return 0;
    }

    MH_CreateHook(target,
                  (LPVOID)hookedEnumOutputs,
                  (LPVOID*)&originalEnumOutputs);
    */

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