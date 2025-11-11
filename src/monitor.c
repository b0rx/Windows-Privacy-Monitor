// © 2025 B0rx. All rights reserved.
// Last Change: 11.11.2025
// Version: 0.1 Beta

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <commctrl.h>
#include <winreg.h>
#include <ctype.h>
#include "json.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

#define ID_LISTVIEW 1001
#define ID_REFRESH 1002
#define ID_MANAGE 1004
#define ID_TIMER 1003
#define ID_OPEN_PATH 1007
#define ID_LB_BLACK 2001
#define ID_LB_WHITE 2002
#define ID_REMOVE_BLACK 2003
#define ID_REMOVE_WHITE 2004
#define ID_CLOSE_MANAGE 2005
#define WM_UPDATE_LIST (WM_USER + 1)
#define MAX_API_STRING 512
#define MAX_PATH_STR 260

typedef struct {
    DWORD pid;
    char processName[MAX_PATH];
    char fullPath[MAX_PATH];
    BOOL hasScreenAccess;
    char screenAPIs[MAX_API_STRING];
    BOOL hasKeyboardAccess;
    char keyboardAPIs[MAX_API_STRING];
    BOOL hasMouseAccess;
    char mouseAPIs[MAX_API_STRING];
    BOOL hasMicrophoneAccess;
    char microphoneAPIs[MAX_API_STRING];
    BOOL hasCameraAccess;
    char cameraAPIs[MAX_API_STRING];
    BOOL hasClipboardAccess;
    char clipboardAPIs[MAX_API_STRING];
    BOOL hasLocationAccess;
    char locationAPIs[MAX_API_STRING];
    BOOL hasNetworkMonitoring;
    char networkAPIs[MAX_API_STRING];
    BOOL hasFileSystemMonitoring;
    char fileSystemAPIs[MAX_API_STRING];
    BOOL hasRegistrySpying;
    char registryAPIs[MAX_API_STRING];
    BOOL hasProcessInjection;
    char injectionAPIs[MAX_API_STRING];
    BOOL hasBluetoothAccess;
    char bluetoothAPIs[MAX_API_STRING];
    BOOL hasUSBMonitoring;
    char usbAPIs[MAX_API_STRING];
} ProcessInfo;

HWND hListView;
HWND hMainWindow;
HINSTANCE g_hInst;
HANDLE hUpdateThread = NULL;
CRITICAL_SECTION csProcessList;
ProcessInfo* g_processList = NULL;
int g_processCount = 0;
int g_sortColumn = -1;
BOOL g_sortAscending = TRUE;

char g_listsFile[] = "lists.json";
char** g_blacklist = NULL;
int g_blacklistCount = 0;
char** g_whitelist = NULL;
int g_whitelistCount = 0;
int g_filterMode = 0;  // 0 = all, 1 = only whitelist, 2 = all except blacklist

// Forward declaration
void PopulateListBoxes(HWND hwnd);

void AppendAPI(char* apiString, const char* apiName, BOOL* first) {
    if (strlen(apiString) + strlen(apiName) + 3 < MAX_API_STRING) {
        if (!*first) {
            strcat(apiString, ", ");
        }
        strcat(apiString, apiName);
        *first = FALSE;
    }
}
BOOL CheckExportedFunction(HMODULE hModule, const char* functionName) {
    if (!hModule) return FALSE;
    FARPROC proc = GetProcAddress(hModule, functionName);
    return (proc != NULL);
}

BOOL CheckScreenCapture(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // GDI32.dll - BitBlt, StretchBlt, etc.
                if (strstr(lowerMod, "gdi32.dll")) {
                    hasAccess = TRUE;
                    if (CheckExportedFunction(hMods[i], "BitBlt")) {
                        AppendAPI(apiString, "BitBlt", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "StretchBlt")) {
                        AppendAPI(apiString, "StretchBlt", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "GetDC")) {
                        AppendAPI(apiString, "GetDC", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "CreateCompatibleDC")) {
                        AppendAPI(apiString, "CreateCompatibleDC", &first);
                    }
                }
              
                // DXGI.dll - DirectX Graphics Infrastructure
                if (strstr(lowerMod, "dxgi.dll")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "IDXGIOutputDuplication", &first);
                }
              
                // D3D11.dll - Direct3D 11 (Screen Capture)
                if (strstr(lowerMod, "d3d11.dll")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "D3D11CaptureFrame", &first);
                }
              
                // Windows.Graphics.Capture (UWP Screen Capture)
                if (strstr(lowerMod, "windows.graphics")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "Windows.Graphics.Capture", &first);
                }
              
                // DwmApi.dll (Desktop Window Manager)
                if (strstr(lowerMod, "dwmapi.dll")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "DwmGetWindowAttribute", &first);
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

BOOL CheckKeyboardAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // User32.dll - Main source for keyboard APIs
                if (strstr(lowerMod, "user32.dll")) {
                    hasAccess = TRUE;
                  
                    // Low-level Keyboard Hook
                    if (CheckExportedFunction(hMods[i], "SetWindowsHookExA") ||
                        CheckExportedFunction(hMods[i], "SetWindowsHookExW")) {
                        AppendAPI(apiString, "SetWindowsHookEx(WH_KEYBOARD_LL)", &first);
                    }
                  
                    // Raw Input
                    if (CheckExportedFunction(hMods[i], "RegisterRawInputDevices")) {
                        AppendAPI(apiString, "RegisterRawInputDevices", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "GetRawInputData")) {
                        AppendAPI(apiString, "GetRawInputData", &first);
                    }
                  
                    // GetAsyncKeyState
                    if (CheckExportedFunction(hMods[i], "GetAsyncKeyState")) {
                        AppendAPI(apiString, "GetAsyncKeyState", &first);
                    }
                  
                    // GetKeyboardState
                    if (CheckExportedFunction(hMods[i], "GetKeyboardState")) {
                        AppendAPI(apiString, "GetKeyboardState", &first);
                    }
                  
                    // Message Queue
                    if (CheckExportedFunction(hMods[i], "PeekMessageA") ||
                        CheckExportedFunction(hMods[i], "PeekMessageW")) {
                        AppendAPI(apiString, "PeekMessage(WM_KEYDOWN)", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

// Mouse hook detection with API details
BOOL CheckMouseAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // User32.dll - Mouse APIs
                if (strstr(lowerMod, "user32.dll")) {
                    hasAccess = TRUE;
                  
                    // Low-level Mouse Hook
                    if (CheckExportedFunction(hMods[i], "SetWindowsHookExA") ||
                        CheckExportedFunction(hMods[i], "SetWindowsHookExW")) {
                        AppendAPI(apiString, "SetWindowsHookEx(WH_MOUSE_LL)", &first);
                    }
                  
                    // GetCursorPos
                    if (CheckExportedFunction(hMods[i], "GetCursorPos")) {
                        AppendAPI(apiString, "GetCursorPos", &first);
                    }
                  
                    // SetCursorPos (active control)
                    if (CheckExportedFunction(hMods[i], "SetCursorPos")) {
                        AppendAPI(apiString, "SetCursorPos", &first);
                    }
                  
                    // mouse_event (simulated input)
                    if (CheckExportedFunction(hMods[i], "mouse_event")) {
                        AppendAPI(apiString, "mouse_event", &first);
                    }
                  
                    // SendInput (modern method)
                    if (CheckExportedFunction(hMods[i], "SendInput")) {
                        AppendAPI(apiString, "SendInput(MOUSE)", &first);
                    }
                  
                    // Raw input for mouse
                    if (CheckExportedFunction(hMods[i], "RegisterRawInputDevices")) {
                        AppendAPI(apiString, "RegisterRawInputDevices(Mouse)", &first);
                    }
                  
                    // GetAsyncKeyState for mouse buttons
                    if (CheckExportedFunction(hMods[i], "GetAsyncKeyState")) {
                        AppendAPI(apiString, "GetAsyncKeyState(VK_LBUTTON/RBUTTON)", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}
// Registry-Check Auxiliary function
BOOL CheckRegistryPermission(const char* subKey, const char* processPath) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
            0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return FALSE;
        }
    }
   
    HKEY hSubKey;
    if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
        DWORD subKeyCount;
        RegQueryInfoKeyA(hSubKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      
        for (DWORD i = 0; i < subKeyCount; i++) {
            char enumName[MAX_PATH];
            DWORD enumSize = MAX_PATH;
            if (RegEnumKeyExA(hSubKey, i, enumName, &enumSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hEnumKey;
                if (RegOpenKeyExA(hSubKey, enumName, 0, KEY_READ, &hEnumKey) == ERROR_SUCCESS) {
                    DWORD valueType, valueSize = MAX_PATH;
                    char valueData[MAX_PATH];
                    if (RegQueryValueExA(hEnumKey, "Value", NULL, &valueType, (LPBYTE)valueData, &valueSize) == ERROR_SUCCESS) {
                        char upperPath[MAX_PATH * 2], upperValue[MAX_PATH * 2];
                        snprintf(upperPath, sizeof(upperPath), "%s", processPath ? processPath : "");
                        snprintf(upperValue, sizeof(upperValue), "%s", valueData);
                        _strupr(upperPath);
                        _strupr(upperValue);
                      
                        if (strstr(upperValue, upperPath) != NULL || strstr(upperPath, upperValue) != NULL) {
                            RegCloseKey(hEnumKey);
                            RegCloseKey(hSubKey);
                            RegCloseKey(hKey);
                            return TRUE;
                        }
                    }
                    RegCloseKey(hEnumKey);
                }
            }
        }
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hKey);
    return FALSE;
}
// microphone detection with API details
BOOL CheckMicrophoneAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    char processPath[MAX_PATH];
    BOOL hasPath = GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath)) > 0;
    CloseHandle(hProcess);
   
    // Registry-Check
    if (hasPath && (CheckRegistryPermission("microphone\\NonPackaged", processPath) ||
                     CheckRegistryPermission("microphone\\Packaged", processPath))) {
        hasAccess = TRUE;
        AppendAPI(apiString, "Windows.Privacy.Microphone", &first);
    }
   
    // DLL-Check
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
      
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    char lowerMod[MAX_PATH];
                    strcpy(lowerMod, szModName);
                    _strlwr(lowerMod);
                  
                    // Core Audio API
                    if (strstr(lowerMod, "mmdevapi.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "IMMDeviceEnumerator(Capture)", &first);
                    }
                  
                    // Kernel Streaming
                    if (strstr(lowerMod, "ksuser.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "KsCreatePin(Audio)", &first);
                    }
                  
                    // WinMM API
                    if (strstr(lowerMod, "winmm.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "waveInOpen", &first);
                    }
                  
                    // DirectShow
                    if (strstr(lowerMod, "quartz.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "DirectShow(AudioCapture)", &first);
                    }
                  
                    // WebRTC/Discord
                    if (strstr(lowerMod, "webrtc") || strstr(lowerMod, "libjingle")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "WebRTC.AudioDevice", &first);
                    }
                  
                    // Media Foundation
                    if (strstr(lowerMod, "mf.dll") || strstr(lowerMod, "mfplat.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "MediaFoundation.AudioCapture", &first);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
   
    return hasAccess;
}
// Camera Detection with API-Details
BOOL CheckCameraAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    char processPath[MAX_PATH];
    BOOL hasPath = GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath)) > 0;
    CloseHandle(hProcess);
   
    // Registry-Check
    if (hasPath && CheckRegistryPermission("webcam\\NonPackaged", processPath)) {
        hasAccess = TRUE;
        AppendAPI(apiString, "Windows.Privacy.Camera", &first);
    }
   
    // DLL-Check
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
      
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    char lowerMod[MAX_PATH];
                    strcpy(lowerMod, szModName);
                    _strlwr(lowerMod);
                  
                    // Media Foundation
                    if (strstr(lowerMod, "mfplat.dll") || strstr(lowerMod, "mf.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "MediaFoundation.VideoCapture", &first);
                    }
                  
                    // DirectShow
                    if (strstr(lowerMod, "quartz.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "DirectShow.VideoCapture", &first);
                    }
                  
                    // Video for Windows (Legacy)
                    if (strstr(lowerMod, "msvfw32.dll") || strstr(lowerMod, "avicap32.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "VFW.capCreateCaptureWindow", &first);
                    }
                  
                    // Windows Media
                    if (strstr(lowerMod, "wmvcore.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "WindowsMedia.VideoCapture", &first);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
   
    return hasAccess;
}

BOOL CheckClipboardAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // User32.dll - Clipboard APIs
                if (strstr(lowerMod, "user32.dll")) {
                    hasAccess = TRUE;
                  
                    if (CheckExportedFunction(hMods[i], "GetClipboardData")) {
                        AppendAPI(apiString, "GetClipboardData", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "SetClipboardData")) {
                        AppendAPI(apiString, "SetClipboardData", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "OpenClipboard")) {
                        AppendAPI(apiString, "OpenClipboard", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "AddClipboardFormatListener")) {
                        AppendAPI(apiString, "AddClipboardFormatListener", &first);
                    }
                }
              
                // OLE32.dll - OLE Clipboard
                if (strstr(lowerMod, "ole32.dll")) {
                    hasAccess = TRUE;
                    if (CheckExportedFunction(hMods[i], "OleGetClipboard")) {
                        AppendAPI(apiString, "OleGetClipboard", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

// Location/GPS Access Detection
BOOL CheckLocationAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    char processPath[MAX_PATH];
    BOOL hasPath = GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath)) > 0;
    CloseHandle(hProcess);
   
    // Registry-Check for Location Permission
    if (hasPath && (CheckRegistryPermission("location\\NonPackaged", processPath) ||
                     CheckRegistryPermission("location\\Packaged", processPath))) {
        hasAccess = TRUE;
        AppendAPI(apiString, "Windows.Privacy.Location", &first);
    }
   
    // DLL-Check
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
      
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    char lowerMod[MAX_PATH];
                    strcpy(lowerMod, szModName);
                    _strlwr(lowerMod);
                  
                    // Location API
                    if (strstr(lowerMod, "locationapi.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "ILocation", &first);
                    }
                  
                    // Windows.Devices.Geolocation (UWP)
                    if (strstr(lowerMod, "windows.devices.geolocation")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "Windows.Devices.Geolocation", &first);
                    }
                  
                    // Sensor API (may also include GPS)
                    if (strstr(lowerMod, "sensorsapi.dll")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "SensorsAPI.GPS", &first);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
   
    return hasAccess;
}
void ToLowerCase(char* str) {
    for (int j = 0; str[j]; j++) {
        str[j] = tolower((unsigned char)str[j]);
    }
}

// Network/Internet Monitoring Detection
BOOL CheckNetworkMonitoring(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    #ifdef DEBUG
    printf("[DEBUG] Checking PID %d for network monitoring...\n", pid);
    #endif
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        #ifdef DEBUG
        printf("[DEBUG] Failed to open process %d (Error: %lu)\n", pid, GetLastError());
        #endif
        return FALSE;
    }
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        #ifdef DEBUG
        printf("[DEBUG] EnumProcessModules failed for PID %d (Error: %lu)\n", pid, GetLastError());
        #endif
        CloseHandle(hProcess);
        return FALSE;
    }
   
    #ifdef DEBUG
    printf("[DEBUG] Found %d modules for PID %d\n", cbNeeded / sizeof(HMODULE), pid);
    #endif
   
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        char szModName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
            char lowerMod[MAX_PATH];
            strcpy(lowerMod, szModName);
            ToLowerCase(lowerMod);
           
            #ifdef DEBUG
            printf("[DEBUG] Module %d: %s -> %s\n", i, szModName, lowerMod);
            #endif
           
            // WinINet - HTTP/Internet APIs
            if (strstr(lowerMod, "wininet.dll")) {
                #ifdef DEBUG
                printf("[DEBUG] Found WinINet in PID %d\n", pid);
                #endif
                if (CheckExportedFunction(hMods[i], "InternetOpen")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "InternetOpen", &first);
                }
                if (CheckExportedFunction(hMods[i], "InternetConnect")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "InternetConnect", &first);
                }
                if (CheckExportedFunction(hMods[i], "HttpSendRequest")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "HttpSendRequest", &first);
                }
            }
           
            // Winsock - Raw Socket Access (e.g. custom network apps)
            if (strstr(lowerMod, "ws2_32.dll") || strstr(lowerMod, "wsock32.dll")) {
                #ifdef DEBUG
                printf("[DEBUG] Found Winsock in PID %d\n", pid);
                #endif
                if (CheckExportedFunction(hMods[i], "WSAStartup")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "WSAStartup", &first);
                }
                if (CheckExportedFunction(hMods[i], "socket")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "socket", &first);
                }
                if (CheckExportedFunction(hMods[i], "connect")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "connect", &first);
                }
            }
           
            // IP Helper API (network sniffing/enumeration, e.g. network tools)
            if (strstr(lowerMod, "iphlpapi.dll")) {
                #ifdef DEBUG
                printf("[DEBUG] Found IP Helper in PID %d\n", pid);
                #endif
                if (CheckExportedFunction(hMods[i], "GetAdaptersInfo")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "GetAdaptersInfo", &first);
                }
                if (CheckExportedFunction(hMods[i], "GetExtendedTcpTable")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "GetExtendedTcpTable (Sniffing)", &first);
                }
                if (CheckExportedFunction(hMods[i], "GetExtendedUdpTable")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "GetExtendedUdpTable", &first);
                }
            }
           
            // WFP (Windows Filtering Platform)
            if (strstr(lowerMod, "fwpuclnt.dll") || strstr(lowerMod, "wfpapi.dll")) {
                #ifdef DEBUG
                printf("[DEBUG] Found WFP DLL in PID %d (likely firewall/monitor)\n", pid);
                #endif
                if (CheckExportedFunction(hMods[i], "FwpmEngineOpen0") || CheckExportedFunction(hMods[i], "FwpmFilterAdd0")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "WFP (Filter/Monitor)", &first);
                } else {
                    // DLL presence alone is sufficient to raise suspicion
                    hasAccess = TRUE;
                    AppendAPI(apiString, "WFP DLL Loaded", &first);
                }
            }
           
            // WinPcap / Npcap (packet capture, e.g. Wireshark)
            if (strstr(lowerMod, "wpcap.dll") || strstr(lowerMod, "npcap.dll")) {
                #ifdef DEBUG
                printf("[DEBUG] Found Packet Capture DLL in PID %d\n", pid);
                #endif
                hasAccess = TRUE;
                AppendAPI(apiString, "WinPcap/Npcap (PacketCapture)", &first);
            }
        }
    }
   
    CloseHandle(hProcess);
   
    #ifdef DEBUG
    printf("[DEBUG] Final result for PID %d: %s (Details: %s)\n", pid, hasAccess ? "YES" : "NO", apiString);
    #endif
   
    return hasAccess;
}

// File System Monitoring Detection
BOOL CheckFileSystemMonitoring(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // Kernel32 - File Monitoring APIs
                if (strstr(lowerMod, "kernel32.dll")) {
                    hasAccess = TRUE;
                    if (CheckExportedFunction(hMods[i], "ReadDirectoryChangesW")) {
                        AppendAPI(apiString, "ReadDirectoryChangesW", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "FindFirstChangeNotification")) {
                        AppendAPI(apiString, "FindFirstChangeNotification", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "FindNextChangeNotification")) {
                        AppendAPI(apiString, "FindNextChangeNotification", &first);
                    }
                }
              
                // NTDLL - Low-level File System Access
                if (strstr(lowerMod, "ntdll.dll")) {
                    hasAccess = TRUE;
                    if (CheckExportedFunction(hMods[i], "NtQueryDirectoryFile")) {
                        AppendAPI(apiString, "NtQueryDirectoryFile", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "NtNotifyChangeDirectoryFile")) {
                        AppendAPI(apiString, "NtNotifyChangeDirectoryFile", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

// Registry Access/Spying Detection
BOOL CheckRegistrySpying(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // Advapi32 - Registry APIs
                if (strstr(lowerMod, "advapi32.dll")) {
                    hasAccess = TRUE;
                    if (CheckExportedFunction(hMods[i], "RegOpenKeyExA") ||
                        CheckExportedFunction(hMods[i], "RegOpenKeyExW")) {
                        AppendAPI(apiString, "RegOpenKeyEx", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "RegQueryValueExA") ||
                        CheckExportedFunction(hMods[i], "RegQueryValueExW")) {
                        AppendAPI(apiString, "RegQueryValueEx", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "RegEnumKeyA") ||
                        CheckExportedFunction(hMods[i], "RegEnumKeyW") ||
                        CheckExportedFunction(hMods[i], "RegEnumKeyExA") ||
                        CheckExportedFunction(hMods[i], "RegEnumKeyExW")) {
                        AppendAPI(apiString, "RegEnumKey(Scanning)", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "RegNotifyChangeKeyValue")) {
                        AppendAPI(apiString, "RegNotifyChangeKeyValue", &first);
                    }
                }
              
                // NTDLL - Low-level Registry
                if (strstr(lowerMod, "ntdll.dll")) {
                    if (CheckExportedFunction(hMods[i], "NtQueryKey")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "NtQueryKey", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

// Process Injection/Manipulation Detection
BOOL CheckProcessInjection(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // Kernel32 - Process Manipulation
                if (strstr(lowerMod, "kernel32.dll")) {
                    if (CheckExportedFunction(hMods[i], "VirtualAllocEx")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "VirtualAllocEx", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "WriteProcessMemory")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "WriteProcessMemory", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "CreateRemoteThread")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "CreateRemoteThread", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "ReadProcessMemory")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "ReadProcessMemory", &first);
                    }
                }
              
                // NTDLL - Low-level Injection
                if (strstr(lowerMod, "ntdll.dll")) {
                    if (CheckExportedFunction(hMods[i], "NtQueueApcThread")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "NtQueueApcThread(APC)", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "NtCreateThreadEx")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "NtCreateThreadEx", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "NtWriteVirtualMemory")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "NtWriteVirtualMemory", &first);
                    }
                }
              
                // PSAPI - Process Enumeration
                if (strstr(lowerMod, "psapi.dll")) {
                    if (CheckExportedFunction(hMods[i], "EnumProcessModulesEx")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "EnumProcessModulesEx", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

// Bluetooth Access Detection
BOOL CheckBluetoothAccess(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    char processPath[MAX_PATH];
    BOOL hasPath = GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath)) > 0;
    CloseHandle(hProcess);
   
    // Registry-Check für Bluetooth Permission
    if (hasPath && (CheckRegistryPermission("bluetoothSync\\NonPackaged", processPath) ||
                     CheckRegistryPermission("bluetooth\\Packaged", processPath))) {
        hasAccess = TRUE;
        AppendAPI(apiString, "Windows.Privacy.Bluetooth", &first);
    }
   
    // DLL-Check
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
      
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    char lowerMod[MAX_PATH];
                    strcpy(lowerMod, szModName);
                    _strlwr(lowerMod);
                  
                    // Bluetooth APIs
                    if (strstr(lowerMod, "bluetoothapis.dll")) {
                        hasAccess = TRUE;
                        if (CheckExportedFunction(hMods[i], "BluetoothFindFirstDevice")) {
                            AppendAPI(apiString, "BluetoothFindFirstDevice", &first);
                        }
                        if (CheckExportedFunction(hMods[i], "BluetoothFindFirstRadio")) {
                            AppendAPI(apiString, "BluetoothFindFirstRadio", &first);
                        }
                        if (CheckExportedFunction(hMods[i], "BluetoothGetDeviceInfo")) {
                            AppendAPI(apiString, "BluetoothGetDeviceInfo", &first);
                        }
                    }
                  
                    // bthprops (Bluetooth Properties)
                    if (strstr(lowerMod, "bthprops.cpl")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "BthProps.Bluetooth", &first);
                    }
                  
                    // Windows.Devices.Bluetooth (UWP)
                    if (strstr(lowerMod, "windows.devices.bluetooth")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "Windows.Devices.Bluetooth", &first);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
   
    return hasAccess;
}

// USB Device Monitoring Detection
BOOL CheckUSBMonitoring(DWORD pid, char* apiString) {
    apiString[0] = '\0';
    BOOL hasAccess = FALSE;
    BOOL first = TRUE;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
   
    HMODULE hMods[1024];
    DWORD cbNeeded;
   
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char lowerMod[MAX_PATH];
                strcpy(lowerMod, szModName);
                _strlwr(lowerMod);
              
                // SetupAPI - Device Enumeration
                if (strstr(lowerMod, "setupapi.dll")) {
                    if (CheckExportedFunction(hMods[i], "SetupDiGetClassDevsA") ||
                        CheckExportedFunction(hMods[i], "SetupDiGetClassDevsW")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "SetupDiGetClassDevs", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "SetupDiEnumDeviceInfo")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "SetupDiEnumDeviceInfo", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "SetupDiEnumDeviceInterfaces")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "SetupDiEnumDeviceInterfaces", &first);
                    }
                }
              
                // CfgMgr32 - Configuration Manager (USB Detection)
                if (strstr(lowerMod, "cfgmgr32.dll")) {
                    if (CheckExportedFunction(hMods[i], "CM_Get_Device_ID_List")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "CM_Get_Device_ID_List", &first);
                    }
                    if (CheckExportedFunction(hMods[i], "CM_Enumerate_Classes")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "CM_Enumerate_Classes", &first);
                    }
                }
              
                // WinUSB - Direct USB Communication
                if (strstr(lowerMod, "winusb.dll")) {
                    hasAccess = TRUE;
                    AppendAPI(apiString, "WinUSB", &first);
                }
              
                // User32 - Device Change Notifications
                if (strstr(lowerMod, "user32.dll")) {
                    if (CheckExportedFunction(hMods[i], "RegisterDeviceNotificationA") ||
                        CheckExportedFunction(hMods[i], "RegisterDeviceNotificationW")) {
                        hasAccess = TRUE;
                        AppendAPI(apiString, "RegisterDeviceNotification(USB)", &first);
                    }
                }
            }
        }
    }
   
    CloseHandle(hProcess);
    return hasAccess;
}

int CompareProcess(const void* a, const void* b, int column) {
    const ProcessInfo* pa = (const ProcessInfo*)a;
    const ProcessInfo* pb = (const ProcessInfo*)b;
    int cmp = 0;
    switch (column) {
        case 0: cmp = (pa->pid > pb->pid) ? 1 : ((pa->pid < pb->pid) ? -1 : 0); break;
        case 1: cmp = strcmp(pa->processName, pb->processName); break;
        case 2: cmp = (pa->hasScreenAccess > pb->hasScreenAccess) ? 1 : ((pa->hasScreenAccess < pb->hasScreenAccess) ? -1 : 0); break;
        case 3: cmp = (pa->hasKeyboardAccess > pb->hasKeyboardAccess) ? 1 : ((pa->hasKeyboardAccess < pb->hasKeyboardAccess) ? -1 : 0); break;
        case 4: cmp = (pa->hasMouseAccess > pb->hasMouseAccess) ? 1 : ((pa->hasMouseAccess < pb->hasMouseAccess) ? -1 : 0); break;
        case 5: cmp = (pa->hasMicrophoneAccess > pb->hasMicrophoneAccess) ? 1 : ((pa->hasMicrophoneAccess < pb->hasMicrophoneAccess) ? -1 : 0); break;
        case 6: cmp = (pa->hasCameraAccess > pb->hasCameraAccess) ? 1 : ((pa->hasCameraAccess < pb->hasCameraAccess) ? -1 : 0); break;
        case 7: cmp = (pa->hasClipboardAccess > pb->hasClipboardAccess) ? 1 : ((pa->hasClipboardAccess < pb->hasClipboardAccess) ? -1 : 0); break;
        case 8: cmp = (pa->hasLocationAccess > pb->hasLocationAccess) ? 1 : ((pa->hasLocationAccess < pb->hasLocationAccess) ? -1 : 0); break;
        case 9: cmp = (pa->hasNetworkMonitoring > pb->hasNetworkMonitoring) ? 1 : ((pa->hasNetworkMonitoring < pb->hasNetworkMonitoring) ? -1 : 0); break;
        case 10: cmp = (pa->hasFileSystemMonitoring > pb->hasFileSystemMonitoring) ? 1 : ((pa->hasFileSystemMonitoring < pb->hasFileSystemMonitoring) ? -1 : 0); break;
        case 11: cmp = (pa->hasRegistrySpying > pb->hasRegistrySpying) ? 1 : ((pa->hasRegistrySpying < pb->hasRegistrySpying) ? -1 : 0); break;
        case 12: cmp = (pa->hasProcessInjection > pb->hasProcessInjection) ? 1 : ((pa->hasProcessInjection < pb->hasProcessInjection) ? -1 : 0); break;
        case 13: cmp = (pa->hasBluetoothAccess > pb->hasBluetoothAccess) ? 1 : ((pa->hasBluetoothAccess < pb->hasBluetoothAccess) ? -1 : 0); break;
        case 14: cmp = (pa->hasUSBMonitoring > pb->hasUSBMonitoring) ? 1 : ((pa->hasUSBMonitoring < pb->hasUSBMonitoring) ? -1 : 0); break;
    }
    return g_sortAscending ? cmp : -cmp;
}

int QSortWrapper(const void* a, const void* b) {
    return CompareProcess(a, b, g_sortColumn);
}

void SortProcessList() {
    if (g_processCount <= 1 || g_sortColumn == -1) return;
    EnterCriticalSection(&csProcessList);
    qsort(g_processList, g_processCount, sizeof(ProcessInfo), QSortWrapper);
    LeaveCriticalSection(&csProcessList);
}

DWORD WINAPI UpdateThreadProc(LPVOID lpParam) {
    HWND hwnd = (HWND)lpParam;
    ProcessInfo* processList = NULL;
    int count = 0;
    int maxcount = 1024;
    processList = (ProcessInfo*)malloc(maxcount * sizeof(ProcessInfo));
    if (!processList) return 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                char tempname[MAX_PATH];
                strncpy(tempname, pe32.szExeFile, MAX_PATH - 1);
                tempname[MAX_PATH - 1] = '\0';

                if (g_whitelistCount > 0) {
                    if (!IsInList(tempname, g_whitelist, g_whitelistCount)) {
                        continue;
                    }
                } else {
                    if (IsInList(tempname, g_blacklist, g_blacklistCount)) {
                        continue;
                    }
                }
                if (count >= maxcount) {
                    maxcount *= 2;
                    ProcessInfo* newbuf = (ProcessInfo*)realloc(processList, maxcount * sizeof(ProcessInfo));
                    if (!newbuf) break;
                    processList = newbuf;
                }

                memset(&processList[count], 0, sizeof(ProcessInfo));
                processList[count].pid = pe32.th32ProcessID;
                strncpy(processList[count].processName, tempname, MAX_PATH - 1);
                processList[count].processName[MAX_PATH - 1] = '\0';
              
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProc) {
                    DWORD len = MAX_PATH;
                    if (QueryFullProcessImageNameA(hProc, 0, processList[count].fullPath, &len)) {
                    } else {
                        strcpy(processList[count].fullPath, "Unknown Path");
                    }
                    CloseHandle(hProc);
                } else {
                    strcpy(processList[count].fullPath, "Access Denied");
                }
              
                processList[count].hasScreenAccess = CheckScreenCapture(pe32.th32ProcessID, processList[count].screenAPIs);
                processList[count].hasKeyboardAccess = CheckKeyboardAccess(pe32.th32ProcessID, processList[count].keyboardAPIs);
                processList[count].hasMouseAccess = CheckMouseAccess(pe32.th32ProcessID, processList[count].mouseAPIs);
                processList[count].hasMicrophoneAccess = CheckMicrophoneAccess(pe32.th32ProcessID, processList[count].microphoneAPIs);
                processList[count].hasCameraAccess = CheckCameraAccess(pe32.th32ProcessID, processList[count].cameraAPIs);
                processList[count].hasClipboardAccess = CheckClipboardAccess(pe32.th32ProcessID, processList[count].clipboardAPIs);
                processList[count].hasLocationAccess = CheckLocationAccess(pe32.th32ProcessID, processList[count].locationAPIs);
                processList[count].hasNetworkMonitoring = CheckNetworkMonitoring(pe32.th32ProcessID, processList[count].networkAPIs);
                processList[count].hasFileSystemMonitoring = CheckFileSystemMonitoring(pe32.th32ProcessID, processList[count].fileSystemAPIs);
                processList[count].hasRegistrySpying = CheckRegistrySpying(pe32.th32ProcessID, processList[count].registryAPIs);
                processList[count].hasProcessInjection = CheckProcessInjection(pe32.th32ProcessID, processList[count].injectionAPIs);
                processList[count].hasBluetoothAccess = CheckBluetoothAccess(pe32.th32ProcessID, processList[count].bluetoothAPIs);
                processList[count].hasUSBMonitoring = CheckUSBMonitoring(pe32.th32ProcessID, processList[count].usbAPIs);

                count++;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    processList = (ProcessInfo*)realloc(processList, count * sizeof(ProcessInfo));

    EnterCriticalSection(&csProcessList);
    if (g_processList) free(g_processList);
    g_processList = processList;
    g_processCount = count;
    SortProcessList();
    LeaveCriticalSection(&csProcessList);
    PostMessage(hwnd, WM_UPDATE_LIST, 0, 0);
    return 0;
}

void UpdateUI() {
    int topIndex = ListView_GetTopIndex(hListView);
    SCROLLINFO siVert = {0};
    siVert.cbSize = sizeof(SCROLLINFO);
    siVert.fMask = SIF_POS;
    GetScrollInfo(hListView, SB_VERT, &siVert);
    int scrollPosVert = siVert.nPos;
   
    SCROLLINFO siHorz = {0};
    siHorz.cbSize = sizeof(SCROLLINFO);
    siHorz.fMask = SIF_POS;
    GetScrollInfo(hListView, SB_HORZ, &siHorz);
    int scrollPosHorz = siHorz.nPos;
   
    SendMessage(hListView, WM_SETREDRAW, FALSE, 0);
   
    ListView_DeleteAllItems(hListView);
   
    EnterCriticalSection(&csProcessList);
    if (!g_processList || g_processCount == 0) {
        LeaveCriticalSection(&csProcessList);
        SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hListView, NULL, TRUE);
        return;
    }
   
    static char pidStr[32];
    static char screenText[MAX_API_STRING + 10];
    static char keyboardText[MAX_API_STRING + 10];
    static char mouseText[MAX_API_STRING + 10];
    static char micText[MAX_API_STRING + 10];
    static char camText[MAX_API_STRING + 10];
    static char clipboardText[MAX_API_STRING + 10];
    static char locationText[MAX_API_STRING + 10];
    static char networkText[MAX_API_STRING + 10];
    static char fileSystemText[MAX_API_STRING + 10];
    static char registryText[MAX_API_STRING + 10];
    static char injectionText[MAX_API_STRING + 10];
    static char bluetoothText[MAX_API_STRING + 10];
    static char usbText[MAX_API_STRING + 10];
   
    for (int i = 0; i < g_processCount; i++) {
        const ProcessInfo* info = &g_processList[i];
      
        LVITEMA lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
      
        sprintf(pidStr, "%d", info->pid);
        lvi.pszText = pidStr;
        lvi.iSubItem = 0;
        int itemIndex = ListView_InsertItem(hListView, &lvi);
      
        lvi.iItem = itemIndex;
        lvi.pszText = (char*)info->processName;
        lvi.iSubItem = 1;
        ListView_SetItem(hListView, &lvi);
      
        if (info->hasScreenAccess && strlen(info->screenAPIs) > 0) {
            sprintf(screenText, "YES (%s)", info->screenAPIs);
        } else {
            strcpy(screenText, info->hasScreenAccess ? "YES" : "No");
        }
        lvi.pszText = screenText;
        lvi.iSubItem = 2;
        ListView_SetItem(hListView, &lvi);
      
        if (info->hasKeyboardAccess && strlen(info->keyboardAPIs) > 0) {
            sprintf(keyboardText, "YES (%s)", info->keyboardAPIs);
        } else {
            strcpy(keyboardText, info->hasKeyboardAccess ? "YES" : "No");
        }
        lvi.pszText = keyboardText;
        lvi.iSubItem = 3;
        ListView_SetItem(hListView, &lvi);
      
        if (info->hasMouseAccess && strlen(info->mouseAPIs) > 0) {
            sprintf(mouseText, "YES (%s)", info->mouseAPIs);
        } else {
            strcpy(mouseText, info->hasMouseAccess ? "YES" : "No");
        }
        lvi.pszText = mouseText;
        lvi.iSubItem = 4;
        ListView_SetItem(hListView, &lvi);
      
        if (info->hasMicrophoneAccess && strlen(info->microphoneAPIs) > 0) {
            sprintf(micText, "YES (%s)", info->microphoneAPIs);
        } else {
            strcpy(micText, info->hasMicrophoneAccess ? "YES" : "No");
        }
        lvi.pszText = micText;
        lvi.iSubItem = 5;
        ListView_SetItem(hListView, &lvi);
      
        if (info->hasCameraAccess && strlen(info->cameraAPIs) > 0) {
            sprintf(camText, "YES (%s)", info->cameraAPIs);
        } else {
            strcpy(camText, info->hasCameraAccess ? "YES" : "No");
        }
        lvi.pszText = camText;
        lvi.iSubItem = 6;
        ListView_SetItem(hListView, &lvi);

        if (info->hasClipboardAccess && strlen(info->clipboardAPIs) > 0) {
            sprintf(clipboardText, "YES (%s)", info->clipboardAPIs);
        } else {
            strcpy(clipboardText, info->hasClipboardAccess ? "YES" : "No");
        }
        lvi.pszText = clipboardText;
        lvi.iSubItem = 7;
        ListView_SetItem(hListView, &lvi);

        if (info->hasLocationAccess && strlen(info->locationAPIs) > 0) {
            sprintf(locationText, "YES (%s)", info->locationAPIs);
        } else {
            strcpy(locationText, info->hasLocationAccess ? "YES" : "No");
        }
        lvi.pszText = locationText;
        lvi.iSubItem = 8;
        ListView_SetItem(hListView, &lvi);

        if (info->hasNetworkMonitoring && strlen(info->networkAPIs) > 0) {
            sprintf(networkText, "YES (%s)", info->networkAPIs);
        } else {
            strcpy(networkText, info->hasNetworkMonitoring ? "YES" : "No");
        }
        lvi.pszText = networkText;
        lvi.iSubItem = 9;
        ListView_SetItem(hListView, &lvi);

        if (info->hasFileSystemMonitoring && strlen(info->fileSystemAPIs) > 0) {
            sprintf(fileSystemText, "YES (%s)", info->fileSystemAPIs);
        } else {
            strcpy(fileSystemText, info->hasFileSystemMonitoring ? "YES" : "No");
        }
        lvi.pszText = fileSystemText;
        lvi.iSubItem = 10;
        ListView_SetItem(hListView, &lvi);

        if (info->hasRegistrySpying && strlen(info->registryAPIs) > 0) {
            sprintf(registryText, "YES (%s)", info->registryAPIs);
        } else {
            strcpy(registryText, info->hasRegistrySpying ? "YES" : "No");
        }
        lvi.pszText = registryText;
        lvi.iSubItem = 11;
        ListView_SetItem(hListView, &lvi);

        if (info->hasProcessInjection && strlen(info->injectionAPIs) > 0) {
            sprintf(injectionText, "YES (%s)", info->injectionAPIs);
        } else {
            strcpy(injectionText, info->hasProcessInjection ? "YES" : "No");
        }
        lvi.pszText = injectionText;
        lvi.iSubItem = 12;
        ListView_SetItem(hListView, &lvi);

        if (info->hasBluetoothAccess && strlen(info->bluetoothAPIs) > 0) {
            sprintf(bluetoothText, "YES (%s)", info->bluetoothAPIs);
        } else {
            strcpy(bluetoothText, info->hasBluetoothAccess ? "YES" : "No");
        }
        lvi.pszText = bluetoothText;
        lvi.iSubItem = 13;
        ListView_SetItem(hListView, &lvi);

        if (info->hasUSBMonitoring && strlen(info->usbAPIs) > 0) {
            sprintf(usbText, "YES (%s)", info->usbAPIs);
        } else {
            strcpy(usbText, info->hasUSBMonitoring ? "YES" : "No");
        }
        lvi.pszText = usbText;
        lvi.iSubItem = 14;
        ListView_SetItem(hListView, &lvi);
    }
    LeaveCriticalSection(&csProcessList);
   
    SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
   
    if (scrollPosHorz > 0) {
        ListView_Scroll(hListView, scrollPosHorz, 0);
    }
   
    if (topIndex > 0 && topIndex < g_processCount) {
        ListView_EnsureVisible(hListView, min(topIndex + 10, g_processCount - 1), FALSE);
        ListView_EnsureVisible(hListView, topIndex, FALSE);
    }
   
    InvalidateRect(hListView, NULL, TRUE);
    UpdateWindow(hListView);
}
void InitListView(HWND hwnd) {
    RECT rcClient;
    GetClientRect(hwnd, &rcClient);
   
    hListView = CreateWindowExA(0, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER | WS_HSCROLL,
        10, 10, rcClient.right - 20, rcClient.bottom - 60,
        hwnd, (HMENU)ID_LISTVIEW, g_hInst, NULL);
   
    ListView_SetExtendedListViewStyle(hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
   
    LVCOLUMNA lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
   
    lvc.pszText = "PID";
    lvc.cx = 70;
    ListView_InsertColumn(hListView, 0, &lvc);
   
    lvc.pszText = "Process Name";
    lvc.cx = 180;
    ListView_InsertColumn(hListView, 1, &lvc);
   
    lvc.pszText = "Screen Access";
    lvc.cx = 300;
    ListView_InsertColumn(hListView, 2, &lvc);
   
    lvc.pszText = "Keyboard Access";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 3, &lvc);
   
    lvc.pszText = "Mouse Access";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 4, &lvc);
   
    lvc.pszText = "Microphone Access";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 5, &lvc);
   
    lvc.pszText = "Camera Access";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 6, &lvc);

    lvc.pszText = "Clipboard Access";
    lvc.cx = 300;
    ListView_InsertColumn(hListView, 7, &lvc);

    lvc.pszText = "Location/GPS";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 8, &lvc);

    lvc.pszText = "Network Monitoring";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 9, &lvc);

    lvc.pszText = "File System Monitor";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 10, &lvc);

    lvc.pszText = "Registry Spying";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 11, &lvc);

    lvc.pszText = "Process Injection";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 12, &lvc);

    lvc.pszText = "Bluetooth Access";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 13, &lvc);

    lvc.pszText = "USB Monitoring";
    lvc.cx = 350;
    ListView_InsertColumn(hListView, 14, &lvc);
}

LRESULT CALLBACK ManageWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "Blacklist:", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 5, 100, 20, hwnd, NULL, g_hInst, NULL);
            HWND hLbBlack = CreateWindowA("LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS | WS_HSCROLL,
                10, 25, 300, 180, hwnd, (HMENU)ID_LB_BLACK, g_hInst, NULL);

            CreateWindowA("STATIC", "Whitelist:", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 210, 100, 20, hwnd, NULL, g_hInst, NULL);
            HWND hLbWhite = CreateWindowA("LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS | WS_HSCROLL,
                10, 230, 300, 180, hwnd, (HMENU)ID_LB_WHITE, g_hInst, NULL);

            CreateWindowA("BUTTON", "Remove Black", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 320, 25, 100, 25, hwnd, (HMENU)ID_REMOVE_BLACK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Remove White", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 320, 255, 100, 25, hwnd, (HMENU)ID_REMOVE_WHITE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 320, 420, 100, 30, hwnd, (HMENU)ID_CLOSE_MANAGE, g_hInst, NULL);

            PopulateListBoxes(hwnd);
            break;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_REMOVE_BLACK: {
                    HWND hLb = GetDlgItem(hwnd, ID_LB_BLACK);
                    int sel = (int)SendMessage(hLb, LB_GETCURSEL, 0, 0);
                    if (sel != LB_ERR) {
                        RemoveFromList(sel, &g_blacklist, &g_blacklistCount);
                        SaveLists(g_listsFile, g_blacklist, g_blacklistCount, 
                                g_whitelist, g_whitelistCount);
                        PopulateListBoxes(hwnd);
                    }
                    break;
                }
                case ID_REMOVE_WHITE: {
                    HWND hLb = GetDlgItem(hwnd, ID_LB_WHITE);
                    int sel = (int)SendMessage(hLb, LB_GETCURSEL, 0, 0);
                    if (sel != LB_ERR) {
                        RemoveFromList(sel, &g_whitelist, &g_whitelistCount);
                        SaveLists(g_listsFile, g_blacklist, g_blacklistCount,
                                g_whitelist, g_whitelistCount);
                        PopulateListBoxes(hwnd);
                    }
                    break;
                }
                case ID_CLOSE_MANAGE: {
                    DestroyWindow(hwnd);
                    break;
                }
            }
            break;
        }
        case WM_CLOSE: {
            DestroyWindow(hwnd);
            return 0;
        }
        default:
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void PopulateListBoxes(HWND hwnd) {
    HWND hBlack = GetDlgItem(hwnd, ID_LB_BLACK);
    SendMessage(hBlack, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_blacklistCount; i++) {
        SendMessage(hBlack, LB_ADDSTRING, 0, (LPARAM)g_blacklist[i]);
    }

    HWND hWhite = GetDlgItem(hwnd, ID_LB_WHITE);
    SendMessage(hWhite, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_whitelistCount; i++) {
        SendMessage(hWhite, LB_ADDSTRING, 0, (LPARAM)g_whitelist[i]);
    }
}

void ShowManageDialog(HWND parent) {
    HWND hDlg = CreateWindowExA(0, "ManageListsClass", "Manage Blacklist and Whitelist",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 450, 500,
        parent, NULL, g_hInst, NULL);
    if (hDlg) {
        EnableWindow(parent, FALSE);
        ShowWindow(hDlg, SW_SHOW);
        UpdateWindow(hDlg);

        MSG msg;
        while (GetMessage(&msg, hDlg, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (!IsWindow(hDlg)) break;
        }

        EnableWindow(parent, TRUE);
        SetActiveWindow(parent);
        SetFocus(GetDlgItem(parent, ID_LISTVIEW));
        UpdateUI();
    }
}

void StartUpdateThread(HWND hwnd) {
    if (hUpdateThread) {
        WaitForSingleObject(hUpdateThread, 100);
        CloseHandle(hUpdateThread);
        hUpdateThread = NULL;
    }
    hUpdateThread = CreateThread(NULL, 0, UpdateThreadProc, hwnd, 0, NULL);
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            InitCommonControls();
            InitializeCriticalSection(&csProcessList);
            LoadLists(g_listsFile, &g_blacklist, &g_blacklistCount,
                    &g_whitelist, &g_whitelistCount);
            InitListView(hwnd);
          
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
          
            CreateWindowA("BUTTON", "Refresh",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, rcClient.bottom - 40, 150, 30,
                hwnd, (HMENU)ID_REFRESH, g_hInst, NULL);
          
            CreateWindowA("BUTTON", "Manage Lists",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, rcClient.bottom - 40, 120, 30,
                hwnd, (HMENU)ID_MANAGE, g_hInst, NULL);
          
            SetTimer(hwnd, ID_TIMER, 10000, NULL);
            StartUpdateThread(hwnd);
            break;
        }
      
        case WM_NOTIFY: {
            NMHDR* nmhdr = (NMHDR*)lParam;
            if (nmhdr->hwndFrom == hListView) {
                if (nmhdr->code == LVN_COLUMNCLICK) {
                    NMLISTVIEW* pnmv = (NMLISTVIEW*)lParam;
                    int column = pnmv->iSubItem;
                  
                    if (g_sortColumn == column) {
                        g_sortAscending = !g_sortAscending;
                    } else {
                        g_sortColumn = column;
                        g_sortAscending = TRUE;
                    }
                  
                    SortProcessList();
                    UpdateUI();
                } else if (nmhdr->code == NM_RCLICK) {
                    NMITEMACTIVATE* itemActivate = (NMITEMACTIVATE*)lParam;
                    if (itemActivate->iItem != -1) {
                        char name[MAX_PATH];
                        char fullPath[MAX_PATH];
                        LVITEMA lvitem = {0};
                        lvitem.mask = LVIF_TEXT;
                        lvitem.iItem = itemActivate->iItem;
                        lvitem.iSubItem = 1;
                        lvitem.pszText = name;
                        lvitem.cchTextMax = MAX_PATH;
                        ListView_GetItem(hListView, &lvitem);
                        
                        lvitem.iSubItem = 1;
                        lvitem.pszText = fullPath;
                        lvitem.cchTextMax = MAX_PATH;
                        ListView_GetItem(hListView, &lvitem);
                        
                        HMENU hMenu = CreatePopupMenu();
                        AppendMenuA(hMenu, MF_STRING, 1005, "Add to Blacklist");
                        AppendMenuA(hMenu, MF_STRING, 1006, "Add to Whitelist");
                        AppendMenuA(hMenu, MF_SEPARATOR, 0, "");
                        AppendMenuA(hMenu, MF_STRING, ID_OPEN_PATH, "Open Path");
                        
                        POINT pt = { itemActivate->ptAction.x, itemActivate->ptAction.y };
                        ClientToScreen(hListView, &pt);
                        UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                        DestroyMenu(hMenu);
                        switch (cmd) {
                            case 1005:
                                AddToList(name, &g_blacklist, &g_blacklistCount);
                                SaveLists(g_listsFile, g_blacklist, g_blacklistCount,
                                        g_whitelist, g_whitelistCount);
                                StartUpdateThread(hwnd);
                                break;
                            case 1006:
                                AddToList(name, &g_whitelist, &g_whitelistCount);
                                SaveLists(g_listsFile, g_blacklist, g_blacklistCount,
                                        g_whitelist, g_whitelistCount);
                                StartUpdateThread(hwnd);
                                break;
                            case ID_OPEN_PATH: {
                                int selectedItem = itemActivate->iItem;
                                EnterCriticalSection(&csProcessList);
                                
                                if (g_processList && selectedItem >= 0 && selectedItem < g_processCount) {
                                    char fullPath[MAX_PATH];
                                    strcpy(fullPath, g_processList[selectedItem].fullPath);
                                    LeaveCriticalSection(&csProcessList);
                                    
                                    if (strlen(fullPath) > 0 && 
                                        strcmp(fullPath, "Unknown Path") != 0 && 
                                        strcmp(fullPath, "Access Denied") != 0) {
                                        
                                        char selectParam[MAX_PATH + 16];
                                        snprintf(selectParam, sizeof(selectParam), "/select,\"%s\"", fullPath);
                                        
                                        HINSTANCE result = ShellExecuteA(
                                            NULL,
                                            "open",
                                            "explorer.exe",
                                            selectParam,
                                            NULL,
                                            SW_SHOWNORMAL
                                        );
                                        
                                        if ((intptr_t)result <= 32) {
                                            char errorMsg[512];
                                            snprintf(errorMsg, sizeof(errorMsg), 
                                                "Could not open location.\nError: %lu\nPath: %s", 
                                                GetLastError(), fullPath);
                                            MessageBoxA(NULL, errorMsg, "Error", MB_OK | MB_ICONERROR);
                                        }
                                    } else {
                                        MessageBoxA(NULL, "Path unavailable for this process.", 
                                            "Info", MB_OK | MB_ICONINFORMATION);
                                    }
                                } else {
                                    LeaveCriticalSection(&csProcessList);
                                    MessageBoxA(NULL, "Invalid selection.", "Error", MB_OK | MB_ICONERROR);
                                }
                                break;
                            }
                        } 
                    }
                    return TRUE;
                }
            }
            break;
        }
      
        case WM_UPDATE_LIST:
            UpdateUI();
            break;
      
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_REFRESH:
                    StartUpdateThread(hwnd);
                    break;
                case ID_MANAGE:
                    ShowManageDialog(hwnd);
                    break;
            }
            break;
      
        case WM_TIMER:
            if (wParam == ID_TIMER) {
                StartUpdateThread(hwnd);
            }
            break;
      
        case WM_SIZE: {
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
            if (hListView) {
                SetWindowPos(hListView, NULL, 10, 10,
                    rcClient.right - 20, rcClient.bottom - 60, SWP_NOZORDER);
            }
            HWND hRefresh = GetDlgItem(hwnd, ID_REFRESH);
            if (hRefresh) {
                SetWindowPos(hRefresh, NULL,
                    10, rcClient.bottom - 40, 150, 30, SWP_NOZORDER);
            }
            HWND hManageBtn = GetDlgItem(hwnd, ID_MANAGE);
            if (hManageBtn) {
                SetWindowPos(hManageBtn, NULL,
                    170, rcClient.bottom - 40, 120, 30, SWP_NOZORDER);
            }
            break;
        }
      
        case WM_DESTROY:
            KillTimer(hwnd, ID_TIMER);
            if (hUpdateThread) {
                WaitForSingleObject(hUpdateThread, INFINITE);
                CloseHandle(hUpdateThread);
            }
            if (g_processList) free(g_processList);

            if (g_blacklist) {
                for (int i = 0; i < g_blacklistCount; i++) free(g_blacklist[i]);
                free(g_blacklist);
            }
            if (g_whitelist) {
                for (int i = 0; i < g_whitelistCount; i++) free(g_whitelist[i]);
                free(g_whitelist);
            }
            DeleteCriticalSection(&csProcessList);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    const char CLASS_NAME[] = "WindowsPrivacyMonitor";
   
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    WNDCLASSA wcManage = {0};
    wcManage.lpfnWndProc = ManageWindowProc;
    wcManage.hInstance = hInstance;
    wcManage.lpszClassName = "ManageListsClass";
    wcManage.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcManage.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wcManage);
   
    hMainWindow = CreateWindowExA(
        0, CLASS_NAME, "Windows Privacy Monitor - Enhanced API Detection",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 700,
        NULL, NULL, hInstance, NULL
    );
   
    if (hMainWindow == NULL) return 0;
   
    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);
   
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
   
    return 0;
}
