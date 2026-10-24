using System;
using System.Collections.Generic;
using System.Linq;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple Lockdown, DiagnosticsRelay (MobileGestalt), MobileActivation, and MobileBackup2 protocols.
/// Extracts both outbound requests AND detailed inbound phone responses (values, activation state, UDID/ECID, model, errors).
/// </summary>
public static class AppleLockdownDecoder
{
    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (!ApplePlistHelper.IsPlist(buffer)) return 0.0;

        var kv = ApplePlistHelper.ExtractKeyValues(buffer);
        if (kv.ContainsKey("Request") || kv.ContainsKey("QueryType") ||
            kv.ContainsKey("Service") || kv.ContainsKey("PairRecord") ||
            kv.ContainsKey("MobileGestaltKeys") || kv.ContainsKey("ActivationInfoXML") ||
            kv.ContainsKey("ActivationState") || kv.ContainsKey("DLMessageProcessMessage"))
        {
            return 0.98;
        }

        if (kv.ContainsKey("DeviceName") || kv.ContainsKey("ProductType") ||
            kv.ContainsKey("UniqueDeviceID") || kv.ContainsKey("Value") ||
            kv.ContainsKey("Result") || kv.ContainsKey("Status") || kv.ContainsKey("Error"))
        {
            return 0.96;
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer, bool isInboundHint = false)
    {
        if (!ApplePlistHelper.IsPlist(buffer)) return null;

        var kv = ApplePlistHelper.ExtractKeyValues(buffer);
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.Normal,
            Category = "lockdown"
        };

        foreach (var pair in kv) cmd.Details[pair.Key] = pair.Value;

        if (kv.TryGetValue("UniqueDeviceID", out var udid)) cmd.Ecid = udid;
        else if (kv.TryGetValue("UniqueChipID", out var ecid)) cmd.Ecid = ecid;
        if (kv.TryGetValue("SerialNumber", out var sn)) cmd.SerialNumber = sn;
        if (kv.TryGetValue("ProductType", out var model)) cmd.Model = model;

        bool hasExplicitRequest = kv.TryGetValue("Request", out var req);
        bool isResponse = isInboundHint ||
                          (!hasExplicitRequest && (kv.ContainsKey("Value") || kv.ContainsKey("Result") || kv.ContainsKey("Error") || kv.ContainsKey("ProductType") || kv.ContainsKey("ActivationState"))) ||
                          (hasExplicitRequest && (kv.ContainsKey("Value") || kv.ContainsKey("Error") || kv.ContainsKey("Port")));

        cmd.Details["IsResponse"] = isResponse.ToString();

        if (!isResponse && hasExplicitRequest && !string.IsNullOrEmpty(req))
        {
            cmd.Operation = $"lockdown:{req}";
            var paramParts = new List<string>();
            if (kv.TryGetValue("Domain", out var dom) && !string.IsNullOrEmpty(dom)) paramParts.Add($"Domain={dom}");
            if (kv.TryGetValue("Key", out var key) && !string.IsNullOrEmpty(key)) paramParts.Add($"Key={key}");
            if (kv.TryGetValue("Service", out var svc) && !string.IsNullOrEmpty(svc)) paramParts.Add($"Service={svc}");

            cmd.Parameters = string.Join(", ", paramParts);
            cmd.Summary = string.IsNullOrEmpty(cmd.Parameters)
                ? $"Lockdown Request [{cmd.Operation}]"
                : $"Lockdown Request [{cmd.Operation}] -> {cmd.Parameters}";
        }
        else if (!isResponse && kv.TryGetValue("QueryType", out var qType))
        {
            cmd.Operation = $"lockdown:{qType}";
            cmd.Summary = $"Lockdown Query [{cmd.Operation}]";
        }
        else
        {
            // Detailed Phone Response Formatting (`PHONE -> HOST`)
            string respOp = hasExplicitRequest ? $"lockdown:Response({req})" : "lockdown:Response";
            cmd.Operation = respOp;

            var summaryPairs = new List<string>();
            string[] priorityResponseKeys =
            [
                "Key", "Value", "Error", "Result", "Status", "Service", "Port",
                "ProductType", "ProductVersion", "BuildVersion", "ActivationState",
                "SerialNumber", "UniqueDeviceID", "UniqueChipID",
                "InternationalMobileEquipmentIdentity", "HardwareModel", "PasswordProtected"
            ];

            foreach (string pk in priorityResponseKeys)
            {
                if (kv.TryGetValue(pk, out var val) && !string.IsNullOrWhiteSpace(val))
                {
                    summaryPairs.Add($"{pk}={val}");
                }
            }

            if (summaryPairs.Count == 0 && kv.Count > 0)
            {
                foreach (var p in kv.Take(5))
                {
                    summaryPairs.Add($"{p.Key}={p.Value}");
                }
            }

            cmd.Parameters = string.Join(", ", summaryPairs);
            cmd.Summary = string.IsNullOrEmpty(cmd.Parameters)
                ? "Lockdown Phone Response (Plist OK)"
                : $"Lockdown Phone Response -> {cmd.Parameters}";
        }

        return cmd;
    }
}
