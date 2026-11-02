using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// ثوابت وفهارس وحالات فحص الذاكرة الحية (Live RAM Pattern Engine)
/// </summary>
public static partial class LiveHeapPatterns
{
    public static readonly string[] AllowedShellVerbs =
    {
        "cat ", "sh ", "su ", "echo ", "dd ", "chmod ", "mount ", "rm ", "cp ", "mv ", "pm ", "am ", "setprop ", "getprop "
    };

    public static readonly HashSet<string> StaticAtErrorTableEntries = new(StringComparer.OrdinalIgnoreCase)
    {
        "+CPIN: SIM PIN", "+CPIN: SIM PUK", "+CPIN: SIM PIN2", "+CPIN: SIM PUK2",
        "+CPIN: PH-SIM PIN", "+CPIN: PH-NET PIN", "+CPIN: PH-NET PUK", "+CPIN: PH-NETSUB PIN"
    };

    public static readonly HashSet<string> TruncatedAtPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT+CGM", "AT+CIM", "AT+CNM", "AT+CFU", "AT+CSC",
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO",
        "AT+CP", "AT+CH", "AT+CU", "AT+CLI", "AT+CPM", "AT^CU",
        "AT%IA", "AT%LA", "+CPIN:", "+CPIN: SI", "+CPIN: SIM PIN<"
    };

    public static readonly ConcurrentDictionary<string, (ulong BeginAddr, ulong EndAddr, ulong SizeBytes, uint StartLba, uint Sectors)> DiscoveredGptPartitions = new(StringComparer.OrdinalIgnoreCase);

    public static string LastCarvedPreloaderPath { get; set; } = string.Empty;
    public static string LastCarvedGfhPath { get; set; } = string.Empty;
    public static string LastCarvedDaAllInOnePath { get; set; } = string.Empty;
    public static string LastCarvedDaStage1Path { get; set; } = string.Empty;
    public static string LastCarvedDaStage2Path { get; set; } = string.Empty;
    public static string LastCarvedDaVersion { get; set; } = string.Empty;
    public static string LastCarvedScatterPath { get; set; } = string.Empty;
    public static string LastSelectedAuthOrDaName { get; set; } = string.Empty;
}
