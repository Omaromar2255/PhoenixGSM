// PhoenixSourceProbe.cpp - مكتبة الاعتراض المستقلة للطبقة L24
#include "PhoenixSourceProbe.h"
#include <psapi.h>
#include <unordered_map>
#include <mutex>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

// جدول محلي لربط رقم المقبض (Handle) بالاسم الحقيقي للمورد (منفذ COM، أنبوب، ملف)
static std::unordered_map<HANDLE, std::wstring> g_HandleMap;
static std::mutex g_MapMutex;
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static std::mutex g_PipeMutex;

// ══════════════════════════════════════════════════════════════
// 1. تحديد مصدر الأمر (أي مكتبة DLL أو منطقة RAM أصدرت الأمر)
// ══════════════════════════════════════════════════════════════
std::wstring ResolveCallerOrigin(void* returnAddress) {
    if (!returnAddress) return L"UnknownOrigin";

    HMODULE hMod = NULL;
    WCHAR modPath[MAX_PATH] = { 0 };
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)returnAddress, &hMod) && hMod != NULL) 
    {
        GetModuleFileNameW(hMod, modPath, MAX_PATH);
        uintptr_t offset = (uintptr_t)returnAddress - (uintptr_t)hMod;
        WCHAR formatted[MAX_PATH + 64];
        swprintf_s(formatted, L"%s + 0x%llX", modPath, (unsigned long long)offset);
        return std::wstring(formatted);
    }

    // إذا لم يكن العنوان تابعاً لملف على القرص، فهذا كود مفكوك بالرام (In-Memory Unpacked)
    WCHAR ramOrigin[128];
    swprintf_s(ramOrigin, L"[RAM_Unpacked_Code @ 0x%p]", returnAddress);
    return std::wstring(ramOrigin);
}

// ══════════════════════════════════════════════════════════════
// 2. إدارة المقابض (Handle Registry)
// ══════════════════════════════════════════════════════════════
void RememberHandle(HANDLE hFile, const std::wstring& path) {
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL) return;
    std::lock_guard<std::mutex> lock(g_MapMutex);
    g_HandleMap[hFile] = path;
}

std::wstring LookupHandle(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL) return L"InvalidHandle";

    {
        std::lock_guard<std::mutex> lock(g_MapMutex);
        auto it = g_HandleMap.find(hFile);
        if (it != g_HandleMap.end()) return it->second;
    }

    WCHAR finalPath[MAX_PATH] = { 0 };
    if (GetFinalPathNameByHandleW(hFile, finalPath, MAX_PATH, FILE_NAME_NORMALIZED) > 0) {
        return std::wstring(finalPath);
    }
    return L"UnknownDeviceHandle";
}

// ══════════════════════════════════════════════════════════════
// 3. كتابة حزم البيانات المتوافقة مع .NET BinaryReader
// ══════════════════════════════════════════════════════════════
static void Write7BitEncodedInt(std::vector<BYTE>& buffer, uint32_t value) {
    while (value >= 0x80) {
        buffer.push_back((BYTE)(value | 0x80));
        value >>= 7;
    }
    buffer.push_back((BYTE)value);
}

static void WriteDotNetString(std::vector<BYTE>& buffer, const std::wstring& str) {
    uint32_t byteCount = (uint32_t)(str.length() * sizeof(wchar_t));
    Write7BitEncodedInt(buffer, byteCount);
    if (byteCount > 0) {
        const BYTE* rawBytes = reinterpret_cast<const BYTE*>(str.c_str());
        buffer.insert(buffer.end(), rawBytes, rawBytes + byteCount);
    }
}

static void WriteInt32(std::vector<BYTE>& buffer, int32_t value) {
    const BYTE* p = reinterpret_cast<const BYTE*>(&value);
    buffer.insert(buffer.end(), p, p + 4);
}

static void WriteUInt32(std::vector<BYTE>& buffer, uint32_t value) {
    const BYTE* p = reinterpret_cast<const BYTE*>(&value);
    buffer.insert(buffer.end(), p, p + 4);
}

// ══════════════════════════════════════════════════════════════
// 4. إرسال الحزم الجنائية عبر Named Pipe
// ══════════════════════════════════════════════════════════════
bool SendTelemetryToPipe(
    DWORD pid,
    DWORD tid,
    ProbeSentinelStage stage,
    DWORD ioctlCode,
    const std::wstring& apiName,
    const std::wstring& callerOrigin,
    const std::wstring& targetResource,
    const void* payload,
    DWORD payloadLen
) {
    std::vector<BYTE> packet;
    packet.reserve(128 + payloadLen);

    WriteInt32(packet, (int32_t)pid);
    WriteInt32(packet, (int32_t)tid);
    WriteInt32(packet, (int32_t)stage);
    WriteUInt32(packet, ioctlCode);
    WriteDotNetString(packet, apiName);
    WriteDotNetString(packet, callerOrigin);
    WriteDotNetString(packet, targetResource);
    WriteInt32(packet, (int32_t)payloadLen);

    if (payload && payloadLen > 0) {
        const BYTE* payloadBytes = reinterpret_cast<const BYTE*>(payload);
        packet.insert(packet.end(), payloadBytes, payloadBytes + payloadLen);
    }

    std::lock_guard<std::mutex> lock(g_PipeMutex);
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        g_hPipe = CreateFileW(
            PHOENIX_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    }

    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(g_hPipe, packet.data(), (DWORD)packet.size(), &bytesWritten, NULL);
    if (!ok) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

// ══════════════════════════════════════════════════════════════
// 5. خطافات الاعتراض (Hook Handlers)
// ══════════════════════════════════════════════════════════════

// خطاف SetupDiGetClassDevsW لرصد البحث عن المنافذ وأجهزة USB
HDEVINFO WINAPI Hook_SetupDiGetClassDevsW(
    const GUID* ClassGuid,
    PCWSTR Enumerator,
    HWND hwndParent,
    DWORD Flags
) {
    WCHAR guidStr[64] = L"{Default_All_Devices}";
    if (ClassGuid) {
        StringFromGUID2(*ClassGuid, guidStr, 64);
    }

    std::wstring caller = ResolveCallerOrigin(_ReturnAddress());
    std::wstring resource = Enumerator ? Enumerator : guidStr;

    SendTelemetryToPipe(
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        STAGE_PORT_AND_DEVICE_RADAR,
        0,
        L"SetupDiGetClassDevsW",
        caller,
        resource,
        NULL,
        0
    );

    // استدعاء الدالة الأصلية
    return SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
}

// محاكاة خطاف كتابة الأوامر (NtWriteFile Hook Helper)
void OnInterceptedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, void* returnAddr) {
    if (!lpBuffer || nNumberOfBytesToWrite == 0) return;

    std::wstring target = LookupHandle(hFile);
    std::wstring caller = ResolveCallerOrigin(returnAddr);

    SendTelemetryToPipe(
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        STAGE_RAW_COMMAND_EXECUTION,
        0,
        L"NtWriteFile",
        caller,
        target,
        lpBuffer,
        nNumberOfBytesToWrite
    );
}

// محاكاة خطاف أوامر التحكم والـ IOCTL (NtDeviceIoControlFile Hook Helper)
void OnInterceptedDeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPCVOID lpInBuffer, DWORD nInBufferSize, void* returnAddr) {
    std::wstring target = LookupHandle(hDevice);
    std::wstring caller = ResolveCallerOrigin(returnAddr);

    SendTelemetryToPipe(
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        STAGE_PORT_CONFIGURATION,
        dwIoControlCode,
        L"NtDeviceIoControlFile",
        caller,
        target,
        lpInBuffer,
        nInBufferSize
    );
}

// ══════════════════════════════════════════════════════════════
// 6. تهيئة المسبار وإغلاقه
// ══════════════════════════════════════════════════════════════
extern "C" {
    BOOL WINAPI PhoenixProbeInit() {
        // إرسال إشعار بدء حقن المسبار بالأداة
        std::wstring origin = ResolveCallerOrigin(_ReturnAddress());
        SendTelemetryToPipe(
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            STAGE_RAM_UNPACK_OR_MODULE_LOAD,
            0,
            L"PhoenixProbeInit",
            origin,
            L"PhoenixSourceProbe.dll",
            NULL,
            0
        );
        return TRUE;
    }

    VOID WINAPI PhoenixProbeShutdown() {
        std::lock_guard<std::mutex> lock(g_PipeMutex);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
        std::lock_guard<std::mutex> lockMap(g_MapMutex);
        g_HandleMap.clear();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        PhoenixProbeInit();
        break;
    case DLL_PROCESS_DETACH:
        PhoenixProbeShutdown();
        break;
    }
    return TRUE;
}
