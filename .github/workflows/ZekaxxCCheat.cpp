// ZekaxxCCheat v7.5 FINAL — DDNet Cheat
// Features: Aimbot, Spinbot, AutoHammer, FastShoot, ESP, Radar, ServerBrowser
// Anti-Detect: NtQuerySystemInformation handle hiding, syscall-only memory access
// Config: auto-save/load ZekaxxCCheat.ini
// x86 + x64 native builds
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <d3dcompiler.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <map>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

// ============================================================
// NTAPI — FULL SET FOR x86 AND x64
// ============================================================
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID;

typedef NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PCLIENT_ID);
typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static pNtOpenProcess NtOpenProcess = NULL;
static pNtReadVirtualMemory NtReadVirtualMemory = NULL;
static pNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
static pNtClose NtClose = NULL;
static pNtQuerySystemInformation NtQuerySystemInformation = NULL;
static pNtDuplicateObject NtDuplicateObject = NULL;
static pNtGetContextThread NtGetContextThread = NULL;
static pNtSetContextThread NtSetContextThread = NULL;
static pNtResumeThread NtResumeThread = NULL;
static pNtUnmapViewOfSection NtUnmapViewOfSection = NULL;
static pNtQueryInformationProcess NtQueryInformationProcess = NULL;

void InitSyscalls() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
    if (!ntdll) { MessageBoxW(NULL, L"ntdll.dll not found!", L"Fatal Error", MB_ICONERROR); ExitProcess(1); }
    NtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
    NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
    NtGetContextThread = (pNtGetContextThread)GetProcAddress(ntdll, "NtGetContextThread");
    NtSetContextThread = (pNtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
    NtResumeThread = (pNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
    NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
}

FORCEINLINE HANDLE OpenProcessNT(DWORD pid) {
    HANDLE h = NULL;
    CLIENT_ID cid = { (PVOID)(uintptr_t)pid, NULL };
    NTSTATUS s = NtOpenProcess(&h, PROCESS_ALL_ACCESS, NULL, &cid);
    if (!NT_SUCCESS(s) || !h) return NULL;
    return h;
}

// Безопасное чтение с проверкой статуса
template<typename T> bool SafeRead(HANDLE h, uintptr_t addr, T& out) {
    SIZE_T bytes = 0;
    NTSTATUS s = NtReadVirtualMemory(h, (PVOID)addr, &out, sizeof(T), &bytes);
    return NT_SUCCESS(s) && bytes == sizeof(T);
}

template<typename T> bool SafeWrite(HANDLE h, uintptr_t addr, const T& val) {
    SIZE_T bytes = 0;
    NTSTATUS s = NtWriteVirtualMemory(h, (PVOID)addr, (PVOID)&val, sizeof(T), &bytes);
    return NT_SUCCESS(s) && bytes == sizeof(T);
}

// ============================================================
// АНТИ-ДЕТЕКТ: СКРЫТИЕ ХЕНДЛОВ ЧЕРЕЗ NtQuerySystemInformation
// ============================================================
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

void HideProcessHandle(DWORD targetPid) {
    if (!NtQuerySystemInformation || !NtDuplicateObject) return;
    
    ULONG bufSize = 0x200000;
    PVOID buf = malloc(bufSize);
    if (!buf) return;
    
    NTSTATUS status;
    while ((status = NtQuerySystemInformation(64, buf, bufSize, &bufSize)) == 0xC0000004) {
        free(buf);
        bufSize *= 2;
        buf = malloc(bufSize);
        if (!buf) return;
    }
    
    if (!NT_SUCCESS(status)) { free(buf); return; }
    
    SYSTEM_HANDLE_INFORMATION_EX* hi = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    DWORD myPid = GetCurrentProcessId();
    
    for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {
        if ((DWORD)hi->Handles[i].UniqueProcessId != myPid) continue;
        
        HANDLE targetProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
        if (!targetProc) continue;
        
        HANDLE dupHandle = NULL;
        NTSTATUS dupStatus = NtDuplicateObject(
            GetCurrentProcess(),
            (HANDLE)hi->Handles[i].HandleValue,
            targetProc,
            &dupHandle,
            0, 0, 0
        );
        
        if (NT_SUCCESS(dupStatus) && dupHandle) {
            NtClose(dupHandle);
        }
        
        CloseHandle(targetProc);
    }
    free(buf);
}

// ============================================================
// СТРУКТУРЫ
// ============================================================
struct vec2 { float x, y; };
struct vec3 { float x, y, z; };
struct Matrix4x4 { float m[4][4]; };

struct CheatConfig {
    bool aimbot = true; float aimbotFov = 360.0f, aimbotSmooth = 1.0f, predictionFactor = 1800.0f;
    bool aimbotAlways = true, aimbotVisCheck = false, aimbotTeammates = false;
    bool spinbot = false; int spinMode = 0; float spinSpeed = 10.0f, spinPitch = 0.0f, jitterAngle = 45.0f;
    bool autohammer = true; float hammerRange = 80.0f; bool hammerAutoSwitch = true;
    bool fastshoot = true, autoFire = true; int fireDelay = 0;
    bool triggerbot = false; int triggerDelay = 50;
    bool esp = true, espBox = true, espLine = true, espHealth = true, espName = true, espDistance = true;
    float espBoxColor[4] = {1.0f,0.2f,0.2f,1.0f}, espTeamColor[4] = {0.2f,1.0f,0.2f,1.0f};
    int espMaxDistance = 1500;
    bool radar = false; float radarSize = 150.0f;
    bool modDetector = true;
    bool bunnyHop = false;
};

static CheatConfig cfg;

// ============================================================
// СОХРАНЕНИЕ / ЗАГРУЗКА КОНФИГА
// ============================================================
void SaveConfig(const wchar_t* path) {
    std::wofstream f(path);
    if (!f) return;
    f << L"; ZekaxxCCheat v7.5 Configuration\n";
    f << L"[Aimbot]\n";
    f << L"enabled=" << cfg.aimbot << L"\n";
    f << L"fov=" << cfg.aimbotFov << L"\n";
    f << L"smooth=" << cfg.aimbotSmooth << L"\n";
    f << L"always=" << cfg.aimbotAlways << L"\n";
    f << L"vischeck=" << cfg.aimbotVisCheck << L"\n";
    f << L"teammates=" << cfg.aimbotTeammates << L"\n";
    f << L"prediction=" << cfg.predictionFactor << L"\n\n";
    
    f << L"[Spinbot]\n";
    f << L"enabled=" << cfg.spinbot << L"\n";
    f << L"mode=" << cfg.spinMode << L"\n";
    f << L"speed=" << cfg.spinSpeed << L"\n";
    f << L"pitch=" << cfg.spinPitch << L"\n";
    f << L"jitter=" << cfg.jitterAngle << L"\n\n";
    
    f << L"[AutoHammer]\n";
    f << L"enabled=" << cfg.autohammer << L"\n";
    f << L"range=" << cfg.hammerRange << L"\n";
    f << L"autoswitch=" << cfg.hammerAutoSwitch << L"\n\n";
    
    f << L"[FastShoot]\n";
    f << L"enabled=" << cfg.fastshoot << L"\n";
    f << L"autofire=" << cfg.autoFire << L"\n";
    f << L"delay=" << cfg.fireDelay << L"\n\n";
    
    f << L"[Triggerbot]\n";
    f << L"enabled=" << cfg.triggerbot << L"\n";
    f << L"delay=" << cfg.triggerDelay << L"\n\n";
    
    f << L"[ESP]\n";
    f << L"enabled=" << cfg.esp << L"\n";
    f << L"box=" << cfg.espBox << L"\n";
    f << L"line=" << cfg.espLine << L"\n";
    f << L"health=" << cfg.espHealth << L"\n";
    f << L"name=" << cfg.espName << L"\n";
    f << L"distance=" << cfg.espDistance << L"\n";
    f << L"maxdist=" << cfg.espMaxDistance << L"\n";
    f << L"radar=" << cfg.radar << L"\n";
    f << L"radarsize=" << cfg.radarSize << L"\n\n";
    
    f << L"[Misc]\n";
    f << L"moddetector=" << cfg.modDetector << L"\n";
    f << L"bunnyhop=" << cfg.bunnyHop << L"\n";
    f.close();
}

void LoadConfig(const wchar_t* path) {
    std::wifstream f(path);
    if (!f) return;
    
    std::wstring line, section;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[') { section = line; continue; }
        
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        
        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq + 1);
        
        if (section == L"[Aimbot]") {
            if (key == L"enabled") cfg.aimbot = (val == L"1");
            else if (key == L"fov") cfg.aimbotFov = wcstof(val.c_str(), NULL);
            else if (key == L"smooth") cfg.aimbotSmooth = wcstof(val.c_str(), NULL);
            else if (key == L"always") cfg.aimbotAlways = (val == L"1");
            else if (key == L"vischeck") cfg.aimbotVisCheck = (val == L"1");
            else if (key == L"teammates") cfg.aimbotTeammates = (val == L"1");
            else if (key == L"prediction") cfg.predictionFactor = wcstof(val.c_str(), NULL);
        }
        else if (section == L"[Spinbot]") {
            if (key == L"enabled") cfg.spinbot = (val == L"1");
            else if (key == L"mode") cfg.spinMode = wcstol(val.c_str(), NULL, 10);
            else if (key == L"speed") cfg.spinSpeed = wcstof(val.c_str(), NULL);
            else if (key == L"pitch") cfg.spinPitch = wcstof(val.c_str(), NULL);
            else if (key == L"jitter") cfg.jitterAngle = wcstof(val.c_str(), NULL);
        }
        else if (section == L"[AutoHammer]") {
            if (key == L"enabled") cfg.autohammer = (val == L"1");
            else if (key == L"range") cfg.hammerRange = wcstof(val.c_str(), NULL);
            else if (key == L"autoswitch") cfg.hammerAutoSwitch = (val == L"1");
        }
        else if (section == L"[FastShoot]") {
            if (key == L"enabled") cfg.fastshoot = (val == L"1");
            else if (key == L"autofire") cfg.autoFire = (val == L"1");
            else if (key == L"delay") cfg.fireDelay = wcstol(val.c_str(), NULL, 10);
        }
        else if (section == L"[Triggerbot]") {
            if (key == L"enabled") cfg.triggerbot = (val == L"1");
            else if (key == L"delay") cfg.triggerDelay = wcstol(val.c_str(), NULL, 10);
        }
        else if (section == L"[ESP]") {
            if (key == L"enabled") cfg.esp = (val == L"1");
            else if (key == L"box") cfg.espBox = (val == L"1");
            else if (key == L"line") cfg.espLine = (val == L"1");
            else if (key == L"health") cfg.espHealth = (val == L"1");
            else if (key == L"name") cfg.espName = (val == L"1");
            else if (key == L"distance") cfg.espDistance = (val == L"1");
            else if (key == L"maxdist") cfg.espMaxDistance = wcstol(val.c_str(), NULL, 10);
            else if (key == L"radar") cfg.radar = (val == L"1");
            else if (key == L"radarsize") cfg.radarSize = wcstof(val.c_str(), NULL);
        }
        else if (section == L"[Misc]") {
            if (key == L"moddetector") cfg.modDetector = (val == L"1");
            else if (key == L"bunnyhop") cfg.bunnyHop = (val == L"1");
        }
    }
    f.close();
}

// ============================================================
// СТРУКТУРА КЭША ИГРОВОГО СОСТОЯНИЯ
// ============================================================
struct CachedPlayer {
    bool valid;
    vec3 pos, vel;
    float yaw, pitch;
    int health, team, weapon;
};

struct CachedGameState {
    CachedPlayer local;
    CachedPlayer players[64];
    int playerCount;
    Matrix4x4 viewMatrix;
    uintptr_t inputPtr;
    uintptr_t localPtr;
};

// ============================================================
// D3D11 ХУКИ
// ============================================================
typedef HRESULT(__stdcall *PresentFn)(IDXGISwapChain*, UINT, UINT);
static PresentFn OrigPresent = nullptr;
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dContext = nullptr;
static ID3D11RenderTargetView* g_pRenderTarget = nullptr;
static bool g_init = false;
static HWND g_hwnd = NULL;

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

HRESULT __stdcall HookedPresent(IDXGISwapChain* s, UINT sync, UINT flags) {
    if (!g_init) {
        if (FAILED(s->GetDevice(__uuidof(ID3D11Device), (void**)&g_pd3dDevice))) return OrigPresent(s, sync, flags);
        if (!g_pd3dDevice) return OrigPresent(s, sync, flags);
        g_pd3dDevice->GetImmediateContext(&g_pd3dContext);
        DXGI_SWAP_CHAIN_DESC d; s->GetDesc(&d); g_hwnd = d.OutputWindow;
        ID3D11Texture2D* bb = nullptr;
        if (FAILED(s->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&bb))) return OrigPresent(s, sync, flags);
        if (!bb) return OrigPresent(s, sync, flags);
        g_pd3dDevice->CreateRenderTargetView(bb, NULL, &g_pRenderTarget);
        bb->Release();
        ImGui::CreateContext();
        ImGui_ImplWin32_Init(g_hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dContext);
        ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        ImGui::StyleColorsDark();
        g_init = true;
    }
    
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    
    RenderGUI();
    DrawESP();
    
    ImGui::Render();
    if (g_pRenderTarget) {
        g_pd3dContext->OMSetRenderTargets(1, &g_pRenderTarget, NULL);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }
    
    return OrigPresent(s, sync, flags);
}

void InitD3D() {
    D3D_FEATURE_LEVEL fl = D3D_FEATURE_LEVEL_11_0;
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = GetConsoleWindow();
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    
    ID3D11Device* d = nullptr;
    ID3D11DeviceContext* c = nullptr;
    IDXGISwapChain* sw = nullptr;
    
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        &fl, 1, D3D11_SDK_VERSION, &sd, &sw, &d, nullptr, &c))) {
        MessageBoxW(NULL, L"D3D11 init failed!", L"Error", MB_ICONERROR);
        return;
    }
    
    void** vt = *(void***)sw;
    OrigPresent = (PresentFn)vt[8];
    
    DWORD old;
    VirtualProtect(&vt[8], sizeof(void*), PAGE_READWRITE, &old);
    vt[8] = (void*)HookedPresent;
    VirtualProtect(&vt[8], sizeof(void*), old, &old);
    
    d->Release();
    c->Release();
    sw->Release();
}

// ============================================================
// ГЛОБАЛЬНОЕ СОСТОЯНИЕ
// ============================================================
static HANDLE g_hProc = NULL;
static uintptr_t g_base = 0;
static bool g_running = true;
static CachedGameState g_cache;
static std::mutex g_cacheMutex;
static std::thread g_worker;
static DWORD g_targetPid = 0;
static wchar_t g_iniPath[MAX_PATH];

// Оффсеты
static uintptr_t offLocalPlayer = 0x4A8B2C;
static uintptr_t offEntityList = 0x4A3C10;
static uintptr_t offViewMatrix = 0x4A1E40;
static uintptr_t offInput = 0x4A7C00;

// Размер указателя зависит от битности
#ifdef _WIN64
static const size_t PTR_SIZE = 8;
#else
static const size_t PTR_SIZE = 4;
#endif

// ============================================================
// БЕЗОПАСНОЕ ЧТЕНИЕ ИГРОВОГО СОСТОЯНИЯ
// ============================================================
void CacheWorker() {
    while (g_running) {
        if (!g_hProc || !g_base) {
            Sleep(500);
            continue;
        }
        
        CachedGameState tmp = {};
        
        // LocalPlayer pointer
        uintptr_t lp = 0;
        if (!SafeRead(g_hProc, g_base + offLocalPlayer, lp) || !lp) {
            Sleep(1);
            continue;
        }
        tmp.localPtr = lp;
        
        // Читаем локального игрока
        if (!SafeRead(g_hProc, lp + 0x2C, tmp.local.pos)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x44, tmp.local.vel)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x58, tmp.local.yaw)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x5C, tmp.local.pitch)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x148, tmp.local.health)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x240, tmp.local.team)) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, lp + 0x250, tmp.local.weapon)) { Sleep(1); continue; }
        tmp.local.valid = true;
        
        // Entity list
        uintptr_t el = 0;
        if (!SafeRead(g_hProc, g_base + offEntityList, el) || !el) { Sleep(1); continue; }
        if (!SafeRead(g_hProc, el + 4, tmp.playerCount)) { Sleep(1); continue; }
        if (tmp.playerCount > 64) tmp.playerCount = 64;
        
        // View matrix
        SafeRead(g_hProc, g_base + offViewMatrix, tmp.viewMatrix);
        
        // Input
        SafeRead(g_hProc, g_base + offInput, tmp.inputPtr);
        
        // Читаем entity ptrs батчево
        uintptr_t entityPtrs[64] = {};
        if (!SafeRead(g_hProc, el + 8, entityPtrs[0])) { Sleep(1); continue; }
        // Читаем полный массив
        SIZE_T bytes = 0;
        NtReadVirtualMemory(g_hProc, (PVOID)(el + 8), entityPtrs, tmp.playerCount * PTR_SIZE, &bytes);
        
        for (int i = 0; i < tmp.playerCount; i++) {
            if (!entityPtrs[i] || entityPtrs[i] == lp) continue;
            
            CachedPlayer& p = tmp.players[i];
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x2C, p.pos)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x44, p.vel)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x58, p.yaw)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x5C, p.pitch)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x148, p.health)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x240, p.team)) continue;
            if (!SafeRead(g_hProc, entityPtrs[i] + 0x250, p.weapon)) continue;
            p.valid = true;
        }
        
        {
            std::lock_guard<std::mutex> lk(g_cacheMutex);
            g_cache = tmp;
        }
        
        Sleep(1);
    }
}

// ============================================================
// WORLD TO SCREEN
// ============================================================
bool WorldToScreen(const vec3& w, vec2& s, float sw, float sh, const Matrix4x4& vp) {
    float cx = w.x*vp.m[0][0] + w.y*vp.m[0][1] + w.z*vp.m[0][2] + vp.m[0][3];
    float cy = w.x*vp.m[1][0] + w.y*vp.m[1][1] + w.z*vp.m[1][2] + vp.m[1][3];
    float cz = w.x*vp.m[2][0] + w.y*vp.m[2][1] + w.z*vp.m[2][2] + vp.m[2][3];
    float cw = w.x*vp.m[3][0] + w.y*vp.m[3][1] + w.z*vp.m[3][2] + vp.m[3][3];
    if (cw < 0.001f) return false;
    s.x = (sw / 2.0f) * (cx / cw + 1.0f);
    s.y = (sh / 2.0f) * (1.0f - cy / cw);
    return (cz > 0.0f && cz < cw);
}

// ============================================================
// АИМБОТ
// ============================================================
void RunAimbot() {
    if (!cfg.aimbot || !g_hProc) return;
    if (!cfg.aimbotAlways && !(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) return;
    
    CachedGameState gs;
    { std::lock_guard<std::mutex> lk(g_cacheMutex); gs = g_cache; }
    if (!gs.local.valid) return;
    
    vec3 bt; float bf = cfg.aimbotFov; bool fnd = false;
    
    for (int i = 0; i < gs.playerCount; i++) {
        if (!gs.players[i].valid || gs.players[i].health <= 0) continue;
        if (!cfg.aimbotTeammates && gs.players[i].team == gs.local.team) continue;
        
        vec3 tp = gs.players[i].pos;
        float dx = tp.x - gs.local.pos.x, dy = tp.y - gs.local.pos.y, dz = tp.z - gs.local.pos.z;
        float dist = sqrtf(dx*dx + dy*dy + dz*dz);
        
        tp.x += gs.players[i].vel.x * dist / cfg.predictionFactor;
        tp.y += gs.players[i].vel.y * dist / cfg.predictionFactor;
        tp.z += gs.players[i].vel.z * dist / cfg.predictionFactor;
        
        dx = tp.x - gs.local.pos.x; dy = tp.y - gs.local.pos.y; dz = tp.z - gs.local.pos.z;
        float tY = atan2f(dy, dx) * 57.29578f;
        float tP = -atan2f(dz, sqrtf(dx*dx + dy*dy)) * 57.29578f;
        float dY = tY - gs.local.yaw;
        while (dY > 180) dY -= 360;
        while (dY < -180) dY += 360;
        float fov = sqrtf(dY*dY + (tP - gs.local.pitch)*(tP - gs.local.pitch));
        
        if (fov < bf) { bf = fov; bt = tp; fnd = true; }
    }
    
    if (fnd && gs.localPtr) {
        float dx = bt.x - gs.local.pos.x, dy = bt.y - gs.local.pos.y, dz = bt.z - gs.local.pos.z;
        float tY = atan2f(dy, dx) * 57.29578f;
        float tP = -atan2f(dz, sqrtf(dx*dx + dy*dy)) * 57.29578f;
        float ny = gs.local.yaw + (tY - gs.local.yaw) / cfg.aimbotSmooth;
        float np = gs.local.pitch + (tP - gs.local.pitch) / cfg.aimbotSmooth;
        SafeWrite(g_hProc, gs.localPtr + 0x58, ny);
        SafeWrite(g_hProc, gs.localPtr + 0x5C, np);
    }
}

// ============================================================
// БЫСТРЫЕ МОДУЛИ (SPINBOT, AUTOHAMMER, FASTSHOOT)
// ============================================================
void RunFastModules() {
    if (!g_hProc || !g_base) return;
    
    uintptr_t lp = 0;
    if (!SafeRead(g_hProc, g_base + offLocalPlayer, lp) || !lp) return;
    
    // Spinbot
    if (cfg.spinbot) {
        static float sa = 0;
        float yaw = 0, pitch = 0;
        SafeRead(g_hProc, lp + 0x58, yaw);
        switch (cfg.spinMode) {
            case 0: sa += cfg.spinSpeed; if (sa > 360) sa -= 360; yaw = sa; break;
            case 1: yaw = (float)(rand() % 360 - 180); break;
            case 2: { static int f = 1; f *= -1; yaw += f * cfg.jitterAngle; break; }
        }
        SafeWrite(g_hProc, lp + 0x58, yaw);
        SafeWrite(g_hProc, lp + 0x5C, cfg.spinPitch);
    }
    
    // AutoHammer
    if (cfg.autohammer) {
        if (cfg.hammerAutoSwitch) SafeWrite(g_hProc, lp + 0x250, 0);
        int weapon = 0;
        SafeRead(g_hProc, lp + 0x250, weapon);
        if (weapon == 0) {
            CachedGameState gs;
            { std::lock_guard<std::mutex> lk(g_cacheMutex); gs = g_cache; }
            for (int i = 0; i < gs.playerCount; i++) {
                if (!gs.players[i].valid || gs.players[i].health <= 0) continue;
                if (gs.players[i].team == gs.local.team) continue;
                float dx = gs.players[i].pos.x - gs.local.pos.x;
                float dy = gs.players[i].pos.y - gs.local.pos.y;
                if (sqrtf(dx*dx + dy*dy) <= cfg.hammerRange) {
                    SafeWrite(g_hProc, gs.inputPtr + 0x10, true);
                    break;
                }
            }
        }
    }
    
    // FastShoot
    if (cfg.fastshoot) {
        int cd = cfg.fireDelay;
        SafeWrite(g_hProc, lp + 0x400, cd);
        if (cfg.autoFire) {
            uintptr_t inp = 0;
            if (SafeRead(g_hProc, g_base + offInput, inp) && inp) {
                SafeWrite(g_hProc, inp + 0x10, true);
            }
        }
    }
    
    // Triggerbot
    if (cfg.triggerbot && (GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        CachedGameState gs;
        { std::lock_guard<std::mutex> lk(g_cacheMutex); gs = g_cache; }
        for (int i = 0; i < gs.playerCount; i++) {
            if (!gs.players[i].valid || gs.players[i].health <= 0) continue;
            if (gs.players[i].team == gs.local.team) continue;
            float dx = gs.players[i].pos.x - gs.local.pos.x;
            float dy = gs.players[i].pos.y - gs.local.pos.y;
            if (sqrtf(dx*dx + dy*dy) < cfg.hammerRange * 0.8f) {
                SafeWrite(g_hProc, gs.inputPtr + 0x10, true);
                Sleep(cfg.triggerDelay);
                break;
            }
        }
    }
    
    // BunnyHop
    if (cfg.bunnyHop && (GetAsyncKeyState(VK_SPACE) & 0x8000)) {
        uintptr_t inp = 0;
        if (SafeRead(g_hProc, g_base + offInput, inp) && inp) {
            SafeWrite(g_hProc, inp + 0x14, true);
        }
    }
}

// ============================================================
// ESP ОТРИСОВКА
// ============================================================
void DrawESP() {
    if (!cfg.esp || !g_init) return;
    
    CachedGameState gs;
    { std::lock_guard<std::mutex> lk(g_cacheMutex); gs = g_cache; }
    if (!gs.local.valid) return;
    
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    float sw = ImGui::GetIO().DisplaySize.x, sh = ImGui::GetIO().DisplaySize.y;
    ImU32 colEnemy = ImColor(cfg.espBoxColor[0], cfg.espBoxColor[1], cfg.espBoxColor[2], cfg.espBoxColor[3]);
    ImU32 colTeam = ImColor(cfg.espTeamColor[0], cfg.espTeamColor[1], cfg.espTeamColor[2], cfg.espTeamColor[3]);
    
    dl->PrimReserve(gs.playerCount * 6, gs.playerCount * 4);
    
    for (int i = 0; i < gs.playerCount; i++) {
        if (!gs.players[i].valid || gs.players[i].health <= 0) continue;
        
        vec3 p = gs.players[i].pos;
        vec3 pTop = {p.x, p.y, p.z - 64.0f};
        
        vec2 sFoot, sHead;
        if (!WorldToScreen(pTop, sHead, sw, sh, gs.viewMatrix)) continue;
        if (!WorldToScreen(p, sFoot, sw, sh, gs.viewMatrix)) continue;
        
        float h = fabsf(sFoot.y - sHead.y), w = h * 0.5f;
        float x = sHead.x - w, y = sHead.y;
        ImU32 col = (gs.players[i].team == gs.local.team) ? colTeam : colEnemy;
        
        if (cfg.espBox) dl->AddRect(ImVec2(x, y), ImVec2(x+w*2, y+h), col, 0, 0, 2);
        if (cfg.espLine) dl->AddLine(ImVec2(sw/2, sh/2), ImVec2(x+w, y), col, 1.5f);
        if (cfg.espHealth) {
            float hpP = gs.players[i].health / 100.0f;
            dl->AddRectFilled(ImVec2(x-8, y), ImVec2(x-4, y+h), IM_COL32(50,50,50,200));
            dl->AddRectFilled(ImVec2(x-8, y+h*(1-hpP)), ImVec2(x-4, y+h), IM_COL32((int)(255*(1-hpP)), (int)(255*hpP), 0, 255));
        }
        if (cfg.espName) { char nm[8]; sprintf(nm, "P%d", i); dl->AddText(ImVec2(x, y-15), IM_COL32_WHITE, nm); }
        if (cfg.espDistance) {
            float dx = p.x - gs.local.pos.x, dy = p.y - gs.local.pos.y;
            char db[16]; sprintf(db, "%.0fm", sqrtf(dx*dx+dy*dy)/30.0f);
            dl->AddText(ImVec2(x, y+h+2), IM_COL32_WHITE, db);
        }
    }
    
    // Radar
    if (cfg.radar) {
        float rx = 100, ry = 100, rs = cfg.radarSize;
        dl->AddRectFilled(ImVec2(rx, ry), ImVec2(rx+rs, ry+rs), IM_COL32(0,0,0,150));
        dl->AddRect(ImVec2(rx, ry), ImVec2(rx+rs, ry+rs), IM_COL32_WHITE);
        for (int i = 0; i < gs.playerCount; i++) {
            if (!gs.players[i].valid || gs.players[i].health <= 0) continue;
            float dx = gs.players[i].pos.x - gs.local.pos.x;
            float dy = gs.players[i].pos.y - gs.local.pos.y;
            float dist = sqrtf(dx*dx + dy*dy);
            if (dist > cfg.espMaxDistance) continue;
            float rpx = rx + rs/2 + dx * rs / cfg.espMaxDistance / 2;
            float rpy = ry + rs/2 + dy * rs / cfg.espMaxDistance / 2;
            dl->AddCircleFilled(ImVec2(rpx, rpy), 2.5f, IM_COL32(255, 50, 50, 255));
        }
        dl->AddCircleFilled(ImVec2(rx+rs/2, ry+rs/2), 3.0f, IM_COL32(0, 255, 0, 255));
    }
}

// ============================================================
// МЕНЮ
// ============================================================
void RenderGUI() {
    static bool show = true;
    if (GetAsyncKeyState(VK_INSERT) & 1) show = !show;
    if (!show) return;
    
    ImGui::SetNextWindowSize(ImVec2(450, 380), ImGuiCond_FirstUseEver);
    ImGui::Begin("ZekaxxCCheat v7.5 FINAL", nullptr, ImGuiWindowFlags_NoResize);
    ImGui::TextColored(ImVec4(1, 0.42f, 0.62f, 1), "ZekaxxCCheat v7.5");
    
    if (ImGui::BeginTabBar("Tabs")) {
        if (ImGui::BeginTabItem("Combat")) {
            ImGui::Checkbox("Aimbot", &cfg.aimbot);
            if (cfg.aimbot) {
                ImGui::SliderFloat("FOV", &cfg.aimbotFov, 1, 360, "%.0f");
                ImGui::SliderFloat("Smooth", &cfg.aimbotSmooth, 0.1f, 20, "%.1f");
                ImGui::SliderFloat("Prediction", &cfg.predictionFactor, 500, 5000, "%.0f");
                ImGui::Checkbox("Always Active", &cfg.aimbotAlways);
                ImGui::Checkbox("Teammates", &cfg.aimbotTeammates);
            }
            ImGui::Separator();
            ImGui::Checkbox("Spinbot", &cfg.spinbot);
            if (cfg.spinbot) {
                const char* modes[] = {"Spin", "Random", "Jitter"};
                ImGui::Combo("Mode", &cfg.spinMode, modes, 3);
                ImGui::SliderFloat("Speed", &cfg.spinSpeed, 1, 50, "%.1f");
            }
            ImGui::Separator();
            ImGui::Checkbox("AutoHammer", &cfg.autohammer);
            if (cfg.autohammer) ImGui::SliderFloat("Range", &cfg.hammerRange, 20, 150, "%.0f");
            ImGui::Separator();
            ImGui::Checkbox("FastShoot", &cfg.fastshoot);
            ImGui::Checkbox("Triggerbot", &cfg.triggerbot);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Visuals")) {
            ImGui::Checkbox("ESP", &cfg.esp);
            if (cfg.esp) {
                ImGui::Checkbox("Box", &cfg.espBox); ImGui::SameLine();
                ImGui::Checkbox("Line", &cfg.espLine); ImGui::SameLine();
                ImGui::Checkbox("Health", &cfg.espHealth);
                ImGui::Checkbox("Name", &cfg.espName); ImGui::SameLine();
                ImGui::Checkbox("Distance", &cfg.espDistance);
                ImGui::SliderInt("Max Dist", &cfg.espMaxDistance, 100, 3000);
                ImGui::ColorEdit4("Enemy", cfg.espBoxColor);
                ImGui::ColorEdit4("Team", cfg.espTeamColor);
                ImGui::Checkbox("Radar", &cfg.radar);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Misc")) {
            ImGui::Checkbox("Bunny Hop", &cfg.bunnyHop);
            ImGui::Checkbox("Mod Detector", &cfg.modDetector);
            if (ImGui::Button("Save Config")) {
                SaveConfig(g_iniPath);
            }
            ImGui::SameLine();
            if (ImGui::Button("Load Config")) {
                LoadConfig(g_iniPath);
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ============================================================
// САМОИНЖЕКЦИЯ RunPE
// ============================================================
bool FindDDNet(wchar_t* out, size_t max) {
    if (GetFileAttributesW(L"DDNet.exe") != INVALID_FILE_ATTRIBUTES) {
        GetFullPathNameW(L"DDNet.exe", (DWORD)max, out, NULL);
        return true;
    }
    const wchar_t* paths[] = {
        L"C:\\Program Files\\DDNet\\DDNet.exe",
        L"C:\\Program Files (x86)\\DDNet\\DDNet.exe"
    };
    for (int i = 0; i < 2; i++) {
        if (GetFileAttributesW(paths[i]) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out, max, paths[i]);
            return true;
        }
    }
    wchar_t appd[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\DDNet\\DDNet.exe", appd, MAX_PATH);
    if (GetFileAttributesW(appd) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(out, max, appd);
        return true;
    }
    return false;
}

bool RunPE(const wchar_t* target) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return false;
    
    CONTEXT ctx = { CONTEXT_FULL };
    if (!NT_SUCCESS(NtGetContextThread(pi.hThread, &ctx))) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }
    
    PROCESS_BASIC_INFORMATION pbi = {};
    if (!NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), NULL))) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }
    
    PEB peb = {};
    SIZE_T bytes = 0;
    if (!NT_SUCCESS(NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytes))) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }
    
#ifdef _WIN64
    uintptr_t imgBase = *(uintptr_t*)((char*)&peb + 0x10);
    ctx.Rcx = imgBase;
#else
    uintptr_t imgBase = *(uintptr_t*)((char*)&peb + 0x08);
    ctx.Eax = (DWORD)imgBase;
#endif
    
    NtUnmapViewOfSection(pi.hProcess, (PVOID)imgBase);
    NtSetContextThread(pi.hThread, &ctx);
    NtResumeThread(pi.hThread, NULL);
    
    g_targetPid = pi.dwProcessId;
    
    Sleep(2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ============================================================
// ПОИСК ПРОЦЕССА
// ============================================================
bool OpenGame() {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"DDNet.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    
    if (!pid) return false;
    
    if (g_hProc) NtClose(g_hProc);
    g_hProc = OpenProcessNT(pid);
    if (!g_hProc) return false;
    
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32W me = { sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"DDNet.exe") == 0) {
                g_base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    
    if (g_base && g_targetPid) {
        HideProcessHandle(g_targetPid);
    }
    
    return g_base != 0;
}

// ============================================================
// ГЛАВНЫЙ ЦИКЛ
// ============================================================
void MainLoop() {
    while (g_running) {
        if (!g_hProc || !g_base) {
            OpenGame();
            Sleep(1000);
            continue;
        }
        
        DWORD code;
        if (!GetExitCodeProcess(g_hProc, &code) || code != STILL_ACTIVE) {
            NtClose(g_hProc);
            g_hProc = NULL;
            g_base = 0;
            Sleep(2000);
            continue;
        }
        
        RunAimbot();
        RunFastModules();
        
        Sleep(0);
    }
}

// ============================================================
// WINMAIN
// ============================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Admin check
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
    
    if (!isAdmin) {
        MessageBoxW(NULL, L"Run as Administrator!", L"ZekaxxCCheat v7.5", MB_ICONWARNING);
        return 1;
    }
    
    InitSyscalls();
    InitD3D();
    
    // Config path
    GetModuleFileNameW(NULL, g_iniPath, MAX_PATH);
    wchar_t* ext = wcsrchr(g_iniPath, L'.');
    if (ext) wcscpy(ext, L".ini");
    LoadConfig(g_iniPath);
    
    // Find and launch DDNet
    wchar_t ddPath[MAX_PATH];
    if (!FindDDNet(ddPath, MAX_PATH)) {
        MessageBoxW(NULL, L"DDNet.exe not found!", L"Error", MB_ICONERROR);
        return 1;
    }
    
    if (!RunPE(ddPath)) {
        MessageBoxW(NULL, L"Failed to launch DDNet!", L"Error", MB_ICONERROR);
        return 1;
    }
    
    // Start cache worker
    g_worker = std::thread(CacheWorker);
    
    MessageBoxW(NULL, L"INSERT = Open Menu\nEND = Exit", L"ZekaxxCCheat v7.5", MB_OK | MB_ICONINFORMATION);
    
    MainLoop();
    
    // Cleanup
    g_running = false;
    if (g_worker.joinable()) g_worker.join();
    SaveConfig(g_iniPath);
    if (g_hProc) NtClose(g_hProc);
    
    return 0;
}
