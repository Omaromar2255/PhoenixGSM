using System;
using System.Collections.Generic;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple Lockdown protocol, handling device property queries,
/// pairing authentication, and service activation (AFC, Diagnostics, InstallationProxy).
/// </summary>
public static class AppleLockdownDecoder
{
    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (!ApplePlistHelper.IsPlist(buffer)) return 0.0;

        var kv = ApplePlistHelper.ExtractKeyValues(buffer);
        if (kv.ContainsKey("Request") || kv.ContainsKey("QueryType") ||
            kv.ContainsKey("Service") || kv.ContainsKey("PairRecord"))
        {
            return 0.98;
        }

        if (kv.ContainsKey("DeviceName") || kv.ContainsKey("ProductType") ||
            kv.ContainsKey("UniqueDeviceID") || kv.ContainsKey("ActivationState"))
        {
            return 0.96;
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer)
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
        if (kv.TryGetValue("SerialNumber", out var sn)) cmd.SerialNumber = sn;
        if (kv.TryGetValue("ProductType", out var model)) cmd.Model = model;

        if (kv.TryGetValue("Request", out var req))
        {
            cmd.Operation = $"lockdown:{req}";
            if (kv.TryGetValue("Key", out var key)) cmd.Parameters = $"Key={key}";
            else if (kv.TryGetValue("Service", out var svc)) cmd.Parameters = $"Service={svc}";
        }
        else if (kv.TryGetValue("QueryType", out var qType))
        {
            cmd.Operation = $"lockdown:{qType}";
        }
        else
        {
            cmd.Operation = "lockdown:Response";
        }

        cmd.Summary = string.IsNullOrEmpty(cmd.Parameters)
            ? $"Lockdown [{cmd.Operation}]"
            : $"Lockdown [{cmd.Operation}] -> {cmd.Parameters}";

        return cmd;
    }
}
