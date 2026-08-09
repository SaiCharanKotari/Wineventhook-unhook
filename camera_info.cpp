#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <devpkey.h>
#include <stdio.h>
#include <mfapi.h>
#include <mfidl.h>
#include "MinHook.h"

// Define our own DEVPROPKEY to avoid missing definitions in MinGW
const DEVPROPKEY MY_DEVPKEY_Device_RemovalPolicy = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 35 };
// 14 = SPDRP_FRIENDLYNAME, 2 = SPDRP_DEVICEDESC, 3 = SPDRP_HARDWAREID in the newer API
const DEVPROPKEY MY_DEVPKEY_Device_FriendlyName = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 14 };
const DEVPROPKEY MY_DEVPKEY_Device_DeviceDesc   = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 2 };
const DEVPROPKEY MY_DEVPKEY_Device_HardwareIds  = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 3 };

typedef BOOL (WINAPI* SetupDiGetDeviceRegistryPropertyW_t)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
typedef BOOL (WINAPI* SetupDiGetDeviceRegistryPropertyA_t)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
typedef BOOL (WINAPI* SetupDiGetDevicePropertyW_t)(HDEVINFO, PSP_DEVINFO_DATA, const DEVPROPKEY*, DEVPROPTYPE*, PBYTE, DWORD, PDWORD, DWORD);
typedef BOOL (WINAPI* SetupDiGetDevicePropertyA_t)(HDEVINFO, PSP_DEVINFO_DATA, const DEVPROPKEY*, DEVPROPTYPE*, PBYTE, DWORD, PDWORD, DWORD);
typedef HRESULT (WINAPI* MFEnumDeviceSources_t)(IMFAttributes*, IMFActivate***, UINT32*);
typedef LSTATUS (WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI* RegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

SetupDiGetDeviceRegistryPropertyW_t orig_SetupDiGetDeviceRegistryPropertyW = NULL;
SetupDiGetDeviceRegistryPropertyA_t orig_SetupDiGetDeviceRegistryPropertyA = NULL;
SetupDiGetDevicePropertyW_t orig_SetupDiGetDevicePropertyW = NULL;
SetupDiGetDevicePropertyA_t orig_SetupDiGetDevicePropertyA = NULL;
MFEnumDeviceSources_t orig_MFEnumDeviceSources = NULL;
RegQueryValueExW_t orig_RegQueryValueExW = NULL;
RegQueryValueExA_t orig_RegQueryValueExA = NULL;

void LogA(const char* format, ...) {
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    OutputDebugStringA(buf);
}

// -----------------------------------------------------------------------------
// Registry Hooks
// -----------------------------------------------------------------------------
LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    LSTATUS status = orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    
    if (status == ERROR_SUCCESS && lpValueName && lpData && lpcbData) {
        if (_wcsicmp(lpValueName, L"FriendlyName") == 0 || _wcsicmp(lpValueName, L"DeviceDesc") == 0) {
            const wchar_t* fakeName = L"Integrated Camera";
            size_t bytesNeeded = (wcslen(fakeName) + 1) * sizeof(wchar_t);
            if (*lpcbData >= bytesNeeded) {
                wcscpy((wchar_t*)lpData, fakeName);
                LogA("[HOOK] RegQueryValueExW spoofed %ws", lpValueName);
            }
        } else if (_wcsicmp(lpValueName, L"DevicePath") == 0 || _wcsicmp(lpValueName, L"SymbolicLink") == 0) {
            const wchar_t* fakePath = L"\\\\?\\pci#ven_10ec&dev_5229&subsys_382317aa&rev_01#4&289e6eb7&0&00e3#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";
            size_t bytesNeeded = (wcslen(fakePath) + 1) * sizeof(wchar_t);
            if (*lpcbData >= bytesNeeded) {
                wcscpy((wchar_t*)lpData, fakePath);
                LogA("[HOOK] RegQueryValueExW spoofed %ws", lpValueName);
            }
        }
    }
    return status;
}

LSTATUS WINAPI Hook_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    LSTATUS status = orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    
    if (status == ERROR_SUCCESS && lpValueName && lpData && lpcbData) {
        if (_stricmp(lpValueName, "FriendlyName") == 0 || _stricmp(lpValueName, "DeviceDesc") == 0) {
            const char* fakeName = "Integrated Camera";
            size_t bytesNeeded = strlen(fakeName) + 1;
            if (*lpcbData >= bytesNeeded) {
                strcpy((char*)lpData, fakeName);
                LogA("[HOOK] RegQueryValueExA spoofed %s", lpValueName);
            }
        } else if (_stricmp(lpValueName, "DevicePath") == 0 || _stricmp(lpValueName, "SymbolicLink") == 0) {
            const char* fakePath = "\\\\?\\pci#ven_10ec&dev_5229&subsys_382317aa&rev_01#4&289e6eb7&0&00e3#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";
            size_t bytesNeeded = strlen(fakePath) + 1;
            if (*lpcbData >= bytesNeeded) {
                strcpy((char*)lpData, fakePath);
                LogA("[HOOK] RegQueryValueExA spoofed %s", lpValueName);
            }
        }
    }
    return status;
}

// -----------------------------------------------------------------------------
// SetupAPI Hooks
// -----------------------------------------------------------------------------
BOOL WINAPI Hook_SetupDiGetDeviceRegistryPropertyW(HDEVINFO a1, PSP_DEVINFO_DATA a2, DWORD prop, PDWORD a4, PBYTE buf, DWORD size, PDWORD reqSize) {
    BOOL res = orig_SetupDiGetDeviceRegistryPropertyW(a1, a2, prop, a4, buf, size, reqSize);
    if (res && buf && size > 0) {
        if (prop == SPDRP_REMOVAL_POLICY && size >= sizeof(DWORD)) {
            DWORD* val = (DWORD*)buf;
            if (*val == 3 || *val == 2) {
                *val = 1;
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyW spoofed RemovalPolicy to 1");
            }
        } else if (prop == SPDRP_FRIENDLYNAME || prop == SPDRP_DEVICEDESC) {
            const wchar_t* fakeName = L"Integrated Camera";
            size_t bytesNeeded = (wcslen(fakeName) + 1) * sizeof(wchar_t);
            if (size >= bytesNeeded) {
                wcscpy((wchar_t*)buf, fakeName);
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyW spoofed FriendlyName/Desc");
            }
        } else if (prop == SPDRP_HARDWAREID) {
            const wchar_t* fakeHwId = L"PCI\\VEN_10EC&DEV_5229\0";
            size_t bytesNeeded = (wcslen(fakeHwId) + 2) * sizeof(wchar_t); // Double null terminated
            if (size >= bytesNeeded) {
                memcpy(buf, fakeHwId, bytesNeeded);
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyW spoofed HardwareID");
            }
        }
    }
    return res;
}

BOOL WINAPI Hook_SetupDiGetDeviceRegistryPropertyA(HDEVINFO a1, PSP_DEVINFO_DATA a2, DWORD prop, PDWORD a4, PBYTE buf, DWORD size, PDWORD reqSize) {
    BOOL res = orig_SetupDiGetDeviceRegistryPropertyA(a1, a2, prop, a4, buf, size, reqSize);
    if (res && buf && size > 0) {
        if (prop == SPDRP_REMOVAL_POLICY && size >= sizeof(DWORD)) {
            DWORD* val = (DWORD*)buf;
            if (*val == 3 || *val == 2) {
                *val = 1;
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyA spoofed RemovalPolicy to 1");
            }
        } else if (prop == SPDRP_FRIENDLYNAME || prop == SPDRP_DEVICEDESC) {
            const char* fakeName = "Integrated Camera";
            size_t bytesNeeded = strlen(fakeName) + 1;
            if (size >= bytesNeeded) {
                strcpy((char*)buf, fakeName);
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyA spoofed FriendlyName/Desc");
            }
        } else if (prop == SPDRP_HARDWAREID) {
            const char* fakeHwId = "PCI\\VEN_10EC&DEV_5229\0";
            size_t bytesNeeded = strlen(fakeHwId) + 2;
            if (size >= bytesNeeded) {
                memcpy(buf, fakeHwId, bytesNeeded);
                LogA("[HOOK] SetupDiGetDeviceRegistryPropertyA spoofed HardwareID");
            }
        }
    }
    return res;
}

BOOL WINAPI Hook_SetupDiGetDevicePropertyW(HDEVINFO a1, PSP_DEVINFO_DATA a2, const DEVPROPKEY* propKey, DEVPROPTYPE* propType, PBYTE buf, DWORD size, PDWORD reqSize, DWORD flags) {
    BOOL res = orig_SetupDiGetDevicePropertyW(a1, a2, propKey, propType, buf, size, reqSize, flags);
    if (propKey && res && buf && size > 0) {
        if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_RemovalPolicy.fmtid.Data1 && propKey->pid == MY_DEVPKEY_Device_RemovalPolicy.pid && size >= sizeof(DWORD)) {
            DWORD* val = (DWORD*)buf;
            if (*val == 3 || *val == 2) {
                *val = 1;
                LogA("[HOOK] SetupDiGetDevicePropertyW spoofed RemovalPolicy");
            }
        } else if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_FriendlyName.fmtid.Data1 && 
                  (propKey->pid == MY_DEVPKEY_Device_FriendlyName.pid || propKey->pid == MY_DEVPKEY_Device_DeviceDesc.pid)) {
            const wchar_t* fakeName = L"Integrated Camera";
            size_t bytesNeeded = (wcslen(fakeName) + 1) * sizeof(wchar_t);
            if (size >= bytesNeeded) {
                wcscpy((wchar_t*)buf, fakeName);
                LogA("[HOOK] SetupDiGetDevicePropertyW spoofed FriendlyName/Desc");
            }
        } else if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_HardwareIds.fmtid.Data1 && propKey->pid == MY_DEVPKEY_Device_HardwareIds.pid) {
            const wchar_t* fakeHwId = L"PCI\\VEN_10EC&DEV_5229\0";
            size_t bytesNeeded = (wcslen(fakeHwId) + 2) * sizeof(wchar_t);
            if (size >= bytesNeeded) {
                memcpy(buf, fakeHwId, bytesNeeded);
                LogA("[HOOK] SetupDiGetDevicePropertyW spoofed HardwareIds");
            }
        }
    }
    return res;
}

BOOL WINAPI Hook_SetupDiGetDevicePropertyA(HDEVINFO a1, PSP_DEVINFO_DATA a2, const DEVPROPKEY* propKey, DEVPROPTYPE* propType, PBYTE buf, DWORD size, PDWORD reqSize, DWORD flags) {
    BOOL res = orig_SetupDiGetDevicePropertyA(a1, a2, propKey, propType, buf, size, reqSize, flags);
    if (propKey && res && buf && size > 0) {
        if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_RemovalPolicy.fmtid.Data1 && propKey->pid == MY_DEVPKEY_Device_RemovalPolicy.pid && size >= sizeof(DWORD)) {
            DWORD* val = (DWORD*)buf;
            if (*val == 3 || *val == 2) {
                *val = 1;
                LogA("[HOOK] SetupDiGetDevicePropertyA spoofed RemovalPolicy");
            }
        } else if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_FriendlyName.fmtid.Data1 && 
                  (propKey->pid == MY_DEVPKEY_Device_FriendlyName.pid || propKey->pid == MY_DEVPKEY_Device_DeviceDesc.pid)) {
            const char* fakeName = "Integrated Camera";
            size_t bytesNeeded = strlen(fakeName) + 1;
            if (size >= bytesNeeded) {
                strcpy((char*)buf, fakeName);
                LogA("[HOOK] SetupDiGetDevicePropertyA spoofed FriendlyName/Desc");
            }
        } else if (propKey->fmtid.Data1 == MY_DEVPKEY_Device_HardwareIds.fmtid.Data1 && propKey->pid == MY_DEVPKEY_Device_HardwareIds.pid) {
            const char* fakeHwId = "PCI\\VEN_10EC&DEV_5229\0";
            size_t bytesNeeded = strlen(fakeHwId) + 2;
            if (size >= bytesNeeded) {
                memcpy(buf, fakeHwId, bytesNeeded);
                LogA("[HOOK] SetupDiGetDevicePropertyA spoofed HardwareIds");
            }
        }
    }
    return res;
}

// -----------------------------------------------------------------------------
// Media Foundation Hooks
// -----------------------------------------------------------------------------
HRESULT WINAPI Hook_MFEnumDeviceSources(IMFAttributes *pAttributes, IMFActivate ***pppSourceActivate, UINT32 *pcSourceActivate) {
    HRESULT hr = orig_MFEnumDeviceSources(pAttributes, pppSourceActivate, pcSourceActivate);
    LogA("[HOOK] MFEnumDeviceSources called. hr: 0x%lX", hr);

    if (SUCCEEDED(hr) && pppSourceActivate && pcSourceActivate && *pcSourceActivate > 0) {
        UINT32 count = *pcSourceActivate;
        IMFActivate** ppDevices = *pppSourceActivate;
        LogA("[HOOK] Found %lu devices. Spoofing them...", count);
        
        for (UINT32 i = 0; i < count; i++) {
            if (ppDevices[i]) {
                HRESULT hrName = ppDevices[i]->SetString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, L"Integrated Camera");
                LogA("[HOOK] Spoofed MF Friendly Name result: 0x%lX", hrName);
                
                HRESULT hrSym = ppDevices[i]->SetString(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, L"\\\\?\\pci#ven_10ec&dev_5229&subsys_382317aa&rev_01#4&289e6eb7&0&00e3#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global");
                LogA("[HOOK] Spoofed MF Symbolic Link result: 0x%lX", hrSym);
            }
        }
    }
    return hr;
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------
void SetupHooks() {
    if (MH_Initialize() != MH_OK) {
        LogA("[HOOK] MH_Initialize failed");
        return;
    }

    // Advapi32 (Registry)
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) hAdvapi32 = LoadLibraryW(L"advapi32.dll");
    if (hAdvapi32) {
        void* pRegW = (void*)GetProcAddress(hAdvapi32, "RegQueryValueExW");
        if (pRegW) { MH_CreateHook(pRegW, (LPVOID)&Hook_RegQueryValueExW, (LPVOID*)&orig_RegQueryValueExW); MH_EnableHook(pRegW); }
        void* pRegA = (void*)GetProcAddress(hAdvapi32, "RegQueryValueExA");
        if (pRegA) { MH_CreateHook(pRegA, (LPVOID)&Hook_RegQueryValueExA, (LPVOID*)&orig_RegQueryValueExA); MH_EnableHook(pRegA); }
    }

    // SetupAPI
    HMODULE hSetupApi = GetModuleHandleW(L"setupapi.dll");
    if (!hSetupApi) hSetupApi = LoadLibraryW(L"setupapi.dll");
    if (hSetupApi) {
        void* pW = (void*)GetProcAddress(hSetupApi, "SetupDiGetDeviceRegistryPropertyW");
        if (pW) { MH_CreateHook(pW, (LPVOID)&Hook_SetupDiGetDeviceRegistryPropertyW, (LPVOID*)&orig_SetupDiGetDeviceRegistryPropertyW); MH_EnableHook(pW); }
        void* pA = (void*)GetProcAddress(hSetupApi, "SetupDiGetDeviceRegistryPropertyA");
        if (pA) { MH_CreateHook(pA, (LPVOID)&Hook_SetupDiGetDeviceRegistryPropertyA, (LPVOID*)&orig_SetupDiGetDeviceRegistryPropertyA); MH_EnableHook(pA); }
        void* pPropW = (void*)GetProcAddress(hSetupApi, "SetupDiGetDevicePropertyW");
        if (pPropW) { MH_CreateHook(pPropW, (LPVOID)&Hook_SetupDiGetDevicePropertyW, (LPVOID*)&orig_SetupDiGetDevicePropertyW); MH_EnableHook(pPropW); }
        void* pPropA = (void*)GetProcAddress(hSetupApi, "SetupDiGetDevicePropertyA");
        if (pPropA) { MH_CreateHook(pPropA, (LPVOID)&Hook_SetupDiGetDevicePropertyA, (LPVOID*)&orig_SetupDiGetDevicePropertyA); MH_EnableHook(pPropA); }
    }

    // Media Foundation
    HMODULE hMf = GetModuleHandleW(L"mf.dll");
    if (!hMf) hMf = LoadLibraryW(L"mf.dll");
    if (hMf) {
        void* pMFEnum = (void*)GetProcAddress(hMf, "MFEnumDeviceSources");
        if (pMFEnum) {
            MH_CreateHook(pMFEnum, (LPVOID)&Hook_MFEnumDeviceSources, (LPVOID*)&orig_MFEnumDeviceSources);
            MH_EnableHook(pMFEnum);
            LogA("[HOOK] MFEnumDeviceSources hook installed");
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        SetupHooks();
        Beep(750, 100); // Play a short beep to confirm successful injection
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
