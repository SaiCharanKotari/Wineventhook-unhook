// ============================================================
//  FULL DIAGNOSTIC HOOK DLL
//  Purpose : Find EXACTLY which APIs the target app uses
//            for process / window detection
//  Each hook → writes to log file + shows MessageBox
//  Build   : x64 DLL, link MinHook, psapi, ntdll
// ============================================================

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

extern "C" {
#include "MinHook.h"
}

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dxgi.lib")

// ============================================================
//  HELPERS
// ============================================================

static void Log(const char* tag, const char* detail = "") {
    FILE* f = fopen("C:\\temp\\detect_log.txt", "a+");
    if (f) {
        fprintf(f, "[FIRED] %-45s | %s\n", tag, detail);
        fclose(f);
    }
}

// Shows a MessageBox once per unique API — so you see it clearly
// Pass __COUNTER__ or a unique ID so it only pops once per API
static void AlertOnce(const char* apiName, int id) {
    static bool shown[128] = {};
    if (id < 128 && !shown[id]) {
        shown[id] = true;
        char msg[256];
        snprintf(msg, sizeof(msg),
            "API DETECTED:\n\n%s\n\nCheck C:\\temp\\detect_log.txt", apiName);
        MessageBoxA(NULL, msg, "Hook Diagnostic", MB_OK | MB_ICONWARNING | MB_TOPMOST);
    }
}

// Gets exe name from PID — utility used by multiple hooks
static void ExeFromPid(DWORD pid, char* out, int outLen) {
    out[0] = 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h) {
        GetModuleBaseNameA(h, NULL, out, outLen);
        CloseHandle(h);
    }
}

// ============================================================
//  1. EnumWindows
//     App uses this to list all visible windows → get PIDs
// ============================================================
typedef BOOL (WINAPI* EnumWindows_t)(WNDENUMPROC, LPARAM);
EnumWindows_t origEnumWindows = NULL;

static WNDENUMPROC  g_ewCallback = NULL;
static LPARAM       g_ewLParam   = 0;

BOOL CALLBACK EW_Proxy(HWND hwnd, LPARAM) {
    return g_ewCallback(hwnd, g_ewLParam);
}

BOOL WINAPI hook_EnumWindows(WNDENUMPROC fn, LPARAM lp) {
    Log("EnumWindows");
    AlertOnce("EnumWindows", 0);
    g_ewCallback = fn;
    g_ewLParam   = lp;
    return origEnumWindows(EW_Proxy, 0);
}

// ============================================================
//  2. EnumDesktopWindows
//     Same as EnumWindows but scoped to a desktop object
// ============================================================
typedef BOOL (WINAPI* EnumDesktopWindows_t)(HDESK, WNDENUMPROC, LPARAM);
EnumDesktopWindows_t origEnumDesktopWindows = NULL;

static WNDENUMPROC  g_edwCallback = NULL;
static LPARAM       g_edwLParam   = 0;

BOOL CALLBACK EDW_Proxy(HWND hwnd, LPARAM) {
    return g_edwCallback(hwnd, g_edwLParam);
}

BOOL WINAPI hook_EnumDesktopWindows(HDESK hDesk, WNDENUMPROC fn, LPARAM lp) {
    Log("EnumDesktopWindows");
    AlertOnce("EnumDesktopWindows", 1);
    g_edwCallback = fn;
    g_edwLParam   = lp;
    return origEnumDesktopWindows(hDesk, EDW_Proxy, 0);
}

// ============================================================
//  3. GetWindowThreadProcessId
//     App calls this after EnumWindows to get PID from HWND
// ============================================================
typedef DWORD (WINAPI* GetWindowThreadProcessId_t)(HWND, LPDWORD);
GetWindowThreadProcessId_t origGetWindowThreadProcessId = NULL;

DWORD WINAPI hook_GetWindowThreadProcessId(HWND hwnd, LPDWORD lpPid) {
    DWORD tid = origGetWindowThreadProcessId(hwnd, lpPid);
    char title[128] = {0};
    GetWindowTextA(hwnd, title, sizeof(title));
    char detail[256];
    snprintf(detail, sizeof(detail), "HWND=%p | Title=\"%s\" | PID=%lu",
        (void*)hwnd, title, lpPid ? *lpPid : 0);
    Log("GetWindowThreadProcessId", detail);
    AlertOnce("GetWindowThreadProcessId", 2);
    return tid;
}

// ============================================================
//  4. FindWindowA / FindWindowW
//     App searches for a specific window by class/title name
//     e.g. FindWindowA(NULL, "WhatsApp") to detect it
// ============================================================
typedef HWND (WINAPI* FindWindowA_t)(LPCSTR, LPCSTR);
FindWindowA_t origFindWindowA = NULL;

HWND WINAPI hook_FindWindowA(LPCSTR cls, LPCSTR title) {
    char detail[256];
    snprintf(detail, sizeof(detail), "Class=\"%s\" | Title=\"%s\"",
        cls ? cls : "(null)", title ? title : "(null)");
    Log("FindWindowA", detail);
    AlertOnce("FindWindowA", 3);
    return origFindWindowA(cls, title);
}

typedef HWND (WINAPI* FindWindowW_t)(LPCWSTR, LPCWSTR);
FindWindowW_t origFindWindowW = NULL;

HWND WINAPI hook_FindWindowW(LPCWSTR cls, LPCWSTR title) {
    char clsA[128] = {0}, titleA[128] = {0};
    if (cls)   WideCharToMultiByte(CP_ACP,0,cls,  -1,clsA,  128,0,0);
    if (title) WideCharToMultiByte(CP_ACP,0,title,-1,titleA,128,0,0);
    char detail[256];
    snprintf(detail, sizeof(detail), "Class=\"%s\" | Title=\"%s\"", clsA, titleA);
    Log("FindWindowW", detail);
    AlertOnce("FindWindowW", 4);
    return origFindWindowW(cls, title);
}

// ============================================================
//  5. FindWindowExA / FindWindowExW
//     Same but can search child windows — also used for detection
// ============================================================
typedef HWND (WINAPI* FindWindowExA_t)(HWND,HWND,LPCSTR,LPCSTR);
FindWindowExA_t origFindWindowExA = NULL;

HWND WINAPI hook_FindWindowExA(HWND p, HWND c, LPCSTR cls, LPCSTR title) {
    char detail[256];
    snprintf(detail, sizeof(detail), "Class=\"%s\" | Title=\"%s\"",
        cls ? cls : "(null)", title ? title : "(null)");
    Log("FindWindowExA", detail);
    AlertOnce("FindWindowExA", 5);
    return origFindWindowExA(p, c, cls, title);
}

typedef HWND (WINAPI* FindWindowExW_t)(HWND,HWND,LPCWSTR,LPCWSTR);
FindWindowExW_t origFindWindowExW = NULL;

HWND WINAPI hook_FindWindowExW(HWND p, HWND c, LPCWSTR cls, LPCWSTR title) {
    char clsA[128]={0}, titleA[128]={0};
    if (cls)   WideCharToMultiByte(CP_ACP,0,cls,  -1,clsA,  128,0,0);
    if (title) WideCharToMultiByte(CP_ACP,0,title,-1,titleA,128,0,0);
    char detail[256];
    snprintf(detail, sizeof(detail), "Class=\"%s\" | Title=\"%s\"", clsA, titleA);
    Log("FindWindowExW", detail);
    AlertOnce("FindWindowExW", 6);
    return origFindWindowExW(p, c, cls, title);
}

// ============================================================
//  6. CreateToolhelp32Snapshot
//     Creating the snapshot itself — if this fires with
//     TH32CS_SNAPPROCESS flag, app is doing process enumeration
// ============================================================
typedef HANDLE (WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
CreateToolhelp32Snapshot_t origCreateToolhelp32Snapshot = NULL;

HANDLE WINAPI hook_CreateToolhelp32Snapshot(DWORD flags, DWORD pid) {
    char detail[128];
    const char* flagName = (flags & TH32CS_SNAPPROCESS) ? "SNAPPROCESS" :
                           (flags & TH32CS_SNAPTHREAD)  ? "SNAPTHREAD"  :
                           (flags & TH32CS_SNAPMODULE)  ? "SNAPMODULE"  : "OTHER";
    snprintf(detail, sizeof(detail), "Flags=0x%08X (%s) | PID=%lu", flags, flagName, pid);
    Log("CreateToolhelp32Snapshot", detail);
    AlertOnce("CreateToolhelp32Snapshot", 7);
    return origCreateToolhelp32Snapshot(flags, pid);
}

// ============================================================
//  7. Process32First / Process32Next (A and W variants)
//     Walking the snapshot to read process names
// ============================================================
typedef BOOL (WINAPI* Process32First_t)(HANDLE, LPPROCESSENTRY32);
Process32First_t origProcess32First = NULL;

BOOL WINAPI hook_Process32First(HANDLE hSnap, LPPROCESSENTRY32 pe) {
    BOOL r = origProcess32First(hSnap, pe);
    if (r) {
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "First: %s (PID %lu)", pe->szExeFile, pe->th32ProcessID);
        Log("Process32First", detail);
    }
    AlertOnce("Process32First", 8);
    return r;
}

typedef BOOL (WINAPI* Process32Next_t)(HANDLE, LPPROCESSENTRY32);
Process32Next_t origProcess32Next = NULL;

BOOL WINAPI hook_Process32Next(HANDLE hSnap, LPPROCESSENTRY32 pe) {
    BOOL r = origProcess32Next(hSnap, pe);
    if (r) {
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Next: %s (PID %lu)", pe->szExeFile, pe->th32ProcessID);
        Log("Process32Next", detail);
    }
    // No AlertOnce here — would pop for every process, too noisy
    return r;
}

// Wide variants — some apps use these
typedef BOOL (WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
Process32FirstW_t origProcess32FirstW = NULL;

BOOL WINAPI hook_Process32FirstW(HANDLE hSnap, LPPROCESSENTRY32W pe) {
    BOOL r = origProcess32FirstW(hSnap, pe);
    if (r) {
        char nameA[MAX_PATH]={0};
        WideCharToMultiByte(CP_ACP,0,pe->szExeFile,-1,nameA,MAX_PATH,0,0);
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "First(W): %s (PID %lu)", nameA, pe->th32ProcessID);
        Log("Process32FirstW", detail);
    }
    AlertOnce("Process32FirstW", 9);
    return r;
}

typedef BOOL (WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
Process32NextW_t origProcess32NextW = NULL;

BOOL WINAPI hook_Process32NextW(HANDLE hSnap, LPPROCESSENTRY32W pe) {
    BOOL r = origProcess32NextW(hSnap, pe);
    if (r) {
        char nameA[MAX_PATH]={0};
        WideCharToMultiByte(CP_ACP,0,pe->szExeFile,-1,nameA,MAX_PATH,0,0);
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Next(W): %s (PID %lu)", nameA, pe->th32ProcessID);
        Log("Process32NextW", detail);
    }
    return r;
}

// ============================================================
//  8. EnumProcesses  (PSAPI — completely separate from Toolhelp32)
//     Returns array of PIDs — app then opens each to get name
// ============================================================
typedef BOOL (WINAPI* EnumProcesses_t)(DWORD*, DWORD, DWORD*);
EnumProcesses_t origEnumProcesses = NULL;

BOOL WINAPI hook_EnumProcesses(DWORD* pids, DWORD cb, DWORD* needed) {
    BOOL r = origEnumProcesses(pids, cb, needed);
    char detail[64];
    snprintf(detail, sizeof(detail), "Returned %lu PIDs", needed ? *needed/sizeof(DWORD) : 0);
    Log("EnumProcesses (PSAPI)", detail);
    AlertOnce("EnumProcesses (PSAPI)", 10);
    return r;
}

// ============================================================
//  9. OpenProcess
//     After getting a PID, app opens it to query exe name
//     We log which PID it's trying to open
// ============================================================
typedef HANDLE (WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
OpenProcess_t origOpenProcess = NULL;

HANDLE WINAPI hook_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    char detail[128];
    snprintf(detail, sizeof(detail), "PID=%lu | Access=0x%08X", pid, access);
    Log("OpenProcess", detail);
    AlertOnce("OpenProcess", 11);
    return origOpenProcess(access, inherit, pid);
}

// ============================================================
// 10. GetModuleBaseNameA/W
//     After OpenProcess, app reads exe name this way
// ============================================================
typedef DWORD (WINAPI* GetModuleBaseNameA_t)(HANDLE,HMODULE,LPSTR,DWORD);
GetModuleBaseNameA_t origGetModuleBaseNameA = NULL;

DWORD WINAPI hook_GetModuleBaseNameA(HANDLE hProc, HMODULE hMod, LPSTR name, DWORD size) {
    DWORD r = origGetModuleBaseNameA(hProc, hMod, name, size);
    if (r) {
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Result: %s", name);
        Log("GetModuleBaseNameA", detail);
    }
    AlertOnce("GetModuleBaseNameA", 12);
    return r;
}

typedef DWORD (WINAPI* GetModuleBaseNameW_t)(HANDLE,HMODULE,LPWSTR,DWORD);
GetModuleBaseNameW_t origGetModuleBaseNameW = NULL;

DWORD WINAPI hook_GetModuleBaseNameW(HANDLE hProc, HMODULE hMod, LPWSTR name, DWORD size) {
    DWORD r = origGetModuleBaseNameW(hProc, hMod, name, size);
    if (r) {
        char nameA[MAX_PATH]={0};
        WideCharToMultiByte(CP_ACP,0,name,-1,nameA,MAX_PATH,0,0);
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Result: %s", nameA);
        Log("GetModuleBaseNameW", detail);
    }
    AlertOnce("GetModuleBaseNameW", 13);
    return r;
}

// ============================================================
// 11. QueryFullProcessImageNameA/W
//     Alternative to GetModuleBaseName — returns full path
//     Used by modern apps as it's more reliable
// ============================================================
typedef BOOL (WINAPI* QueryFullProcessImageNameA_t)(HANDLE,DWORD,LPSTR,PDWORD);
QueryFullProcessImageNameA_t origQueryFullProcessImageNameA = NULL;

BOOL WINAPI hook_QueryFullProcessImageNameA(HANDLE h, DWORD flags, LPSTR name, PDWORD size) {
    BOOL r = origQueryFullProcessImageNameA(h, flags, name, size);
    if (r) {
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Path: %s", name);
        Log("QueryFullProcessImageNameA", detail);
    }
    AlertOnce("QueryFullProcessImageNameA", 14);
    return r;
}

typedef BOOL (WINAPI* QueryFullProcessImageNameW_t)(HANDLE,DWORD,LPWSTR,PDWORD);
QueryFullProcessImageNameW_t origQueryFullProcessImageNameW = NULL;

BOOL WINAPI hook_QueryFullProcessImageNameW(HANDLE h, DWORD flags, LPWSTR name, PDWORD size) {
    BOOL r = origQueryFullProcessImageNameW(h, flags, name, size);
    if (r) {
        char nameA[MAX_PATH]={0};
        WideCharToMultiByte(CP_ACP,0,name,-1,nameA,MAX_PATH,0,0);
        char detail[MAX_PATH+32];
        snprintf(detail, sizeof(detail), "Path: %s", nameA);
        Log("QueryFullProcessImageNameW", detail);
    }
    AlertOnce("QueryFullProcessImageNameW", 15);
    return r;
}

// ============================================================
// 12. NtQuerySystemInformation  (NATIVE — bypasses everything above)
//     Class 5 = SystemProcessInformation = full process list
//     This is the most powerful detection method
//     Rings ntdll directly — no Win32 wrapper
// ============================================================
typedef NTSTATUS (WINAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NtQuerySystemInformation_t origNtQuerySystemInformation = NULL;

NTSTATUS WINAPI hook_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS cls, PVOID buf, ULONG len, PULONG ret)
{
    NTSTATUS r = origNtQuerySystemInformation(cls, buf, len, ret);

    char detail[128];
    const char* clsName = (cls == 5)  ? "SystemProcessInformation (PROCESS LIST!)" :
                          (cls == 8)  ? "SystemProcessorPerformanceInformation" :
                          (cls == 11) ? "SystemModuleInformation" :
                          (cls == 16) ? "SystemHandleInformation" : "Other";
    snprintf(detail, sizeof(detail), "Class=%d (%s)", (int)cls, clsName);
    Log("NtQuerySystemInformation", detail);

    if (cls == 5)
        AlertOnce("NtQuerySystemInformation [Class=5 PROCESS LIST]", 16);

    return r;
}

// ============================================================
// 13. NtQueryInformationProcess  (NATIVE)
//     Used to get info about a SPECIFIC process
//     Class 27 = ProcessImageFileName
// ============================================================
typedef NTSTATUS (WINAPI* NtQueryInformationProcess_t)(
    HANDLE, DWORD, PVOID, ULONG, PULONG);
NtQueryInformationProcess_t origNtQueryInformationProcess = NULL;

NTSTATUS WINAPI hook_NtQueryInformationProcess(
    HANDLE hProc, DWORD cls, PVOID buf, ULONG len, PULONG ret)
{
    char detail[128];
    const char* clsName = (cls == 0)  ? "ProcessBasicInformation" :
                          (cls == 27) ? "ProcessImageFileName" :
                          (cls == 43) ? "ProcessImageFileNameWin32" : "Other";
    snprintf(detail, sizeof(detail), "Class=%lu (%s)", cls, clsName);
    Log("NtQueryInformationProcess", detail);
    AlertOnce("NtQueryInformationProcess", 17);
    return origNtQueryInformationProcess(hProc, cls, buf, len, ret);
}

// ============================================================
// 14. GetWindowTextA/W
//     After getting HWNDs, app may read window titles directly
//     to match strings like "WhatsApp", "Chrome", etc.
// ============================================================
typedef int (WINAPI* GetWindowTextA_t)(HWND, LPSTR, int);
GetWindowTextA_t origGetWindowTextA = NULL;

int WINAPI hook_GetWindowTextA(HWND hwnd, LPSTR buf, int maxLen) {
    int r = origGetWindowTextA(hwnd, buf, maxLen);
    if (r > 0) {
        char detail[256];
        snprintf(detail, sizeof(detail), "HWND=%p | Title=\"%s\"", (void*)hwnd, buf);
        Log("GetWindowTextA", detail);
    }
    AlertOnce("GetWindowTextA", 18);
    return r;
}

typedef int (WINAPI* GetWindowTextW_t)(HWND, LPWSTR, int);
GetWindowTextW_t origGetWindowTextW = NULL;

int WINAPI hook_GetWindowTextW(HWND hwnd, LPWSTR buf, int maxLen) {
    int r = origGetWindowTextW(hwnd, buf, maxLen);
    if (r > 0) {
        char titleA[256]={0};
        WideCharToMultiByte(CP_ACP,0,buf,-1,titleA,256,0,0);
        char detail[256];
        snprintf(detail, sizeof(detail), "HWND=%p | Title=\"%s\"", (void*)hwnd, titleA);
        Log("GetWindowTextW", detail);
    }
    AlertOnce("GetWindowTextW", 19);
    return r;
}

// ============================================================
// 15. EnumDisplayMonitors
//     VM / sandbox detection — checks monitor count + resolution
// ============================================================
typedef BOOL (WINAPI* EnumDisplayMonitors_t)(HDC,LPCRECT,MONITORENUMPROC,LPARAM);
EnumDisplayMonitors_t origEnumDisplayMonitors = NULL;

BOOL WINAPI hook_EnumDisplayMonitors(HDC hdc, LPCRECT rc, MONITORENUMPROC fn, LPARAM lp) {
    Log("EnumDisplayMonitors");
    AlertOnce("EnumDisplayMonitors", 20);
    return origEnumDisplayMonitors(hdc, rc, fn, lp);
}

// ============================================================
// 16. GetSystemMetrics
//     Apps call SM_CMONITORS to count monitors
//     SM_CXSCREEN/SM_CYSCREEN to check resolution looks real
// ============================================================
typedef int (WINAPI* GetSystemMetrics_t)(int);
GetSystemMetrics_t origGetSystemMetrics = NULL;

int WINAPI hook_GetSystemMetrics(int idx) {
    int r = origGetSystemMetrics(idx);
    const char* name = (idx == SM_CMONITORS) ? "SM_CMONITORS" :
                       (idx == SM_CXSCREEN)  ? "SM_CXSCREEN"  :
                       (idx == SM_CYSCREEN)  ? "SM_CYSCREEN"  :
                       (idx == SM_REMOTESESSION) ? "SM_REMOTESESSION" : NULL;
    if (name) {
        char detail[128];
        snprintf(detail, sizeof(detail), "%s = %d", name, r);
        Log("GetSystemMetrics", detail);
        AlertOnce("GetSystemMetrics [monitor/screen check]", 21);
    }
    return r;
}

// ============================================================
// 17. RegisterHotKey
//     Some proctoring apps register global hotkeys
//     If the target app does this, it shows up here
// ============================================================
typedef BOOL (WINAPI* RegisterHotKey_t)(HWND,int,UINT,UINT);
RegisterHotKey_t origRegisterHotKey = NULL;

BOOL WINAPI hook_RegisterHotKey(HWND hwnd, int id, UINT mod, UINT vk) {
    char detail[128];
    snprintf(detail, sizeof(detail), "Mod=0x%X | VK=0x%X | ID=%d", mod, vk, id);
    Log("RegisterHotKey", detail);
    AlertOnce("RegisterHotKey", 22);
    return origRegisterHotKey(hwnd, id, mod, vk);
}

// ============================================================
// 18. SetWindowsHookExA/W
//     Global keyboard/mouse hooks — detect alt-tab, screen capture
//     Also used by proctoring to block certain key combos
// ============================================================
typedef HHOOK (WINAPI* SetWindowsHookExA_t)(int,HOOKPROC,HINSTANCE,DWORD);
SetWindowsHookExA_t origSetWindowsHookExA = NULL;

HHOOK WINAPI hook_SetWindowsHookExA(int type, HOOKPROC proc, HINSTANCE hInst, DWORD tid) {
    const char* typeName = (type == WH_KEYBOARD_LL) ? "WH_KEYBOARD_LL" :
                           (type == WH_MOUSE_LL)    ? "WH_MOUSE_LL"    :
                           (type == WH_CBT)         ? "WH_CBT"         :
                           (type == WH_SHELL)       ? "WH_SHELL"       : "OTHER";
    char detail[128];
    snprintf(detail, sizeof(detail), "Type=%d (%s)", type, typeName);
    Log("SetWindowsHookExA", detail);
    AlertOnce("SetWindowsHookExA", 23);
    return origSetWindowsHookExA(type, proc, hInst, tid);
}

// ============================================================
//  INSTALL ALL HOOKS
// ============================================================

#define HOOK(module, func, hookedFn, origPtr) \
    MH_CreateHook( \
        GetProcAddress(GetModuleHandleA(module), func), \
        (LPVOID)hookedFn, \
        (LPVOID*)origPtr \
    )

void InstallAllHooks() {
    CreateDirectoryA("C:\\temp", NULL);

    // Clear log
    FILE* f = fopen("C:\\temp\\detect_log.txt", "w");
    if (f) { fprintf(f, "=== DETECTION DIAGNOSTIC LOG ===\n"); fclose(f); }

    if (MH_Initialize() != MH_OK) return;

    // --- user32.dll ---
    HOOK("user32.dll", "EnumWindows",              hook_EnumWindows,              &origEnumWindows);
    HOOK("user32.dll", "EnumDesktopWindows",       hook_EnumDesktopWindows,       &origEnumDesktopWindows);
    HOOK("user32.dll", "GetWindowThreadProcessId", hook_GetWindowThreadProcessId, &origGetWindowThreadProcessId);
    HOOK("user32.dll", "FindWindowA",              hook_FindWindowA,              &origFindWindowA);
    HOOK("user32.dll", "FindWindowW",              hook_FindWindowW,              &origFindWindowW);
    HOOK("user32.dll", "FindWindowExA",            hook_FindWindowExA,            &origFindWindowExA);
    HOOK("user32.dll", "FindWindowExW",            hook_FindWindowExW,            &origFindWindowExW);
    HOOK("user32.dll", "GetWindowTextA",           hook_GetWindowTextA,           &origGetWindowTextA);
    HOOK("user32.dll", "GetWindowTextW",           hook_GetWindowTextW,           &origGetWindowTextW);
    HOOK("user32.dll", "GetSystemMetrics",         hook_GetSystemMetrics,         &origGetSystemMetrics);
    HOOK("user32.dll", "RegisterHotKey",           hook_RegisterHotKey,           &origRegisterHotKey);
    HOOK("user32.dll", "SetWindowsHookExA",        hook_SetWindowsHookExA,        &origSetWindowsHookExA);
    HOOK("user32.dll", "EnumDisplayMonitors",      hook_EnumDisplayMonitors,      &origEnumDisplayMonitors);

    // --- kernel32.dll ---
    HOOK("kernel32.dll", "CreateToolhelp32Snapshot", hook_CreateToolhelp32Snapshot, &origCreateToolhelp32Snapshot);
    HOOK("kernel32.dll", "Process32First",           hook_Process32First,           &origProcess32First);
    HOOK("kernel32.dll", "Process32Next",            hook_Process32Next,            &origProcess32Next);
    HOOK("kernel32.dll", "Process32FirstW",          hook_Process32FirstW,          &origProcess32FirstW);
    HOOK("kernel32.dll", "Process32NextW",           hook_Process32NextW,           &origProcess32NextW);
    HOOK("kernel32.dll", "OpenProcess",              hook_OpenProcess,              &origOpenProcess);
    HOOK("kernel32.dll", "QueryFullProcessImageNameA", hook_QueryFullProcessImageNameA, &origQueryFullProcessImageNameA);
    HOOK("kernel32.dll", "QueryFullProcessImageNameW", hook_QueryFullProcessImageNameW, &origQueryFullProcessImageNameW);

    // --- psapi.dll ---
    HOOK("psapi.dll", "EnumProcesses",       hook_EnumProcesses,       &origEnumProcesses);
    HOOK("psapi.dll", "GetModuleBaseNameA",  hook_GetModuleBaseNameA,  &origGetModuleBaseNameA);
    HOOK("psapi.dll", "GetModuleBaseNameW",  hook_GetModuleBaseNameW,  &origGetModuleBaseNameW);

    // --- ntdll.dll (native — most powerful, bypasses all above) ---
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        LPVOID fnNtQSI  = GetProcAddress(ntdll, "NtQuerySystemInformation");
        LPVOID fnNtQIP  = GetProcAddress(ntdll, "NtQueryInformationProcess");

        if (fnNtQSI) MH_CreateHook(fnNtQSI, hook_NtQuerySystemInformation,
                                    (LPVOID*)&origNtQuerySystemInformation);
        if (fnNtQIP) MH_CreateHook(fnNtQIP, hook_NtQueryInformationProcess,
                                    (LPVOID*)&origNtQueryInformationProcess);
    }

    MH_EnableHook(MH_ALL_HOOKS);
    Log("=== ALL HOOKS INSTALLED ===");
    MessageBoxA(NULL,
        "Diagnostic DLL loaded.\n\nAll process detection hooks are active.\n\nRun the app — a MessageBox will appear for each API it uses.\n\nFull log: C:\\temp\\detect_log.txt",
        "Hook Diagnostic Ready", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
}

// ============================================================
//  DLL ENTRY
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InstallAllHooks();
    }
    return TRUE;
}
