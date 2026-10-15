#pragma once

#ifndef PHOENIX_SOURCE_PROBE_H
#define PHOENIX_SOURCE_PROBE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <setupapi.h>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// معرفات المراحل الجنائية (تطابق SentinelStage في C#)
enum ProbeSentinelStage {
    STAGE_RAM_UNPACK_OR_MODULE_LOAD = 0,
    STAGE_PORT_AND_DEVICE_RADAR     = 1,
    STAGE_LOCAL_FILE_PREPARATION    = 2,
    STAGE_PORT_CONFIGURATION        = 3,
    STAGE_RAW_COMMAND_EXECUTION     = 4,
    STAGE_NETWORK_PRE_ENCRYPTION    = 5
};

// اسم أنبوب الاتصال فائق السرعة
#define PHOENIX_PIPE_NAME L"\\\\.\\pipe\\PhoenixL24SentinelPipe"

// دالة تصديرية لتهيئة أو إيقاف المسبار
extern "C" {
    __declspec(dllexport) BOOL WINAPI PhoenixProbeInit();
    __declspec(dllexport) VOID WINAPI PhoenixProbeShutdown();
}

// توقيعات الدوال الداخلية
std::wstring ResolveCallerOrigin(void* returnAddress);
void RememberHandle(HANDLE hFile, const std::wstring& path);
std::wstring LookupHandle(HANDLE hFile);
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
);

#endif // PHOENIX_SOURCE_PROBE_H
