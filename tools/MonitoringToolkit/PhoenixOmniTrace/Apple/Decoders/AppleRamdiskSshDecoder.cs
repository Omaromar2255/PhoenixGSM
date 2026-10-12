using System;
using System.Collections.Generic;
using System.Text;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple Ramdisk and SSH communication channels (iproxy, Dropbear, OpenSSH, Plink).
/// Tracks APFS/HFS filesystem mount commands, activation ticket extractions, and bypass scripts.
/// </summary>
public static class AppleRamdiskSshDecoder
{
    private static readonly string[] RamdiskCommands =
    [
        "mount_apfs", "mount_hfs", "mount_filesystems", "fsck_apfs",
        "chflags", "plutil", "launchctl", "nvram", "killall",
        "cat /mnt", "tar -czf", "dd if=", "chmod 755"
    ];

    private static readonly string[] ActivationFiles =
    [
        "com.apple.commcenter", "activation_record", "IC-Info.sisv",
        "FMIPAccounts", "FairPlay", "data_ark.plist", "lockdown"
    ];

    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return 0.0;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]).Trim();

        // 1. Check for SSH Protocol Banner
        if (text.StartsWith("SSH-2.0-", StringComparison.OrdinalIgnoreCase))
        {
            return 0.99;
        }

        // 2. Check for Ramdisk Shell Commands
        foreach (var cmd in RamdiskCommands)
        {
            if (text.Contains(cmd, StringComparison.OrdinalIgnoreCase))
            {
                return 0.95;
            }
        }

        // 3. Check for Activation Ticket Artifacts
        foreach (var act in ActivationFiles)
        {
            if (text.Contains(act, StringComparison.OrdinalIgnoreCase))
            {
                return 0.90;
            }
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length == 0) return null;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 1024)]).Trim();
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.RamdiskSsh,
            Category = "RamdiskSSH"
        };

        // SSH Banner
        if (text.StartsWith("SSH-2.0-", StringComparison.OrdinalIgnoreCase))
        {
            cmd.Operation = "SSH:Banner";
            cmd.Parameters = text;
            cmd.Summary = $"SSH Protocol Handshake: {text}";
            return cmd;
        }

        // Ramdisk filesystem / activation commands
        foreach (var rc in RamdiskCommands)
        {
            if (text.Contains(rc, StringComparison.OrdinalIgnoreCase))
            {
                cmd.Operation = $"Ramdisk:{rc.Split(' ')[0]}";
                cmd.Parameters = text;
                cmd.Summary = $"Ramdisk Shell: {text}";
                return cmd;
            }
        }

        // Activation ticket manipulation
        foreach (var act in ActivationFiles)
        {
            if (text.Contains(act, StringComparison.OrdinalIgnoreCase))
            {
                cmd.Operation = "Ramdisk:TicketOperation";
                cmd.Parameters = act;
                cmd.Summary = $"Ramdisk Activation File: {act}";
                return cmd;
            }
        }

        cmd.Operation = "Ramdisk:Data";
        cmd.Summary = $"Ramdisk SSH Payload ({buffer.Length} bytes)";
        return cmd;
    }
}
