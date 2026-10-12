using System;
using System.Collections.Generic;
using PhoenixGSM.OmniTrace.Apple.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Apple.Detection;

/// <summary>
/// Confidence-based detector for all Apple iOS operating modes and servicing protocols.
/// Evaluates raw stream buffers against usbmuxd, lockdown, iBoot recovery, SecureROM DFU,
/// SSH ramdisk, and Purple diagnostics.
/// </summary>
public static class AppleProtocolDetector
{
    public static void DetectCandidates(
        ReadOnlySpan<byte> buffer,
        SensorType sensor,
        TransportType transport,
        PacketDirection direction,
        List<ProtocolCandidate> candidates)
    {
        if (buffer.Length == 0) return;

        // 1. Check usbmuxd framing (port 27015 or USB multiplexer)
        double muxConfidence = AppleUsbmuxdDecoder.Evaluate(buffer);
        if (muxConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.AppleUsbmuxd,
                muxConfidence,
                $"Apple usbmuxd Protocol (confidence={muxConfidence:P0})"));
        }

        // 2. Check Apple Lockdown protocol
        double lockConfidence = AppleLockdownDecoder.Evaluate(buffer);
        if (lockConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.AppleLockdown,
                lockConfidence,
                $"Apple Lockdown Plist Protocol (confidence={lockConfidence:P0})"));
        }

        // 3. Check Apple Recovery Mode (iBoot / irecovery)
        double recConfidence = AppleRecoveryDecoder.Evaluate(buffer);
        if (recConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.AppleRecovery,
                recConfidence,
                $"Apple Recovery Mode / iBoot (confidence={recConfidence:P0})"));
        }

        // 4. Check Apple DFU Mode (SecureROM / checkm8)
        double dfuConfidence = AppleDfuDecoder.Evaluate(buffer);
        if (dfuConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.AppleDfu,
                dfuConfidence,
                $"Apple DFU / SecureROM Protocol (confidence={dfuConfidence:P0})"));
        }

        // 5. Check Apple Ramdisk SSH & bypass commands
        double rdConfidence = AppleRamdiskSshDecoder.Evaluate(buffer);
        if (rdConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.AppleRamdiskSsh,
                rdConfidence,
                $"Apple Ramdisk SSH Channel (confidence={rdConfidence:P0})"));
        }

        // 6. Check Apple Purple Mode / SysCfg diagnostics
        double purpleConfidence = ApplePurpleDiagDecoder.Evaluate(buffer);
        if (purpleConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(
                KnownProtocol.ApplePurpleDiag,
                purpleConfidence,
                $"Apple Purple Diag SysCfg (confidence={purpleConfidence:P0})"));
        }
    }
}
