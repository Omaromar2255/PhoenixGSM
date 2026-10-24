using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Aggregates and reconstructs fragmented chunks of `getprop` output into a clean, unified device summary.
/// </summary>
public sealed class AdbGetpropAggregator
{
    private readonly StringBuilder _buffer = new();
    private readonly Dictionary<string, string> _properties = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastAppendTime = DateTime.UtcNow;

    private static readonly string[] ImportantProperties =
    {
        "ro.product.model",
        "gsm.version.baseband",
        "ro.boot.carrierid",
        "ro.boot.debug_level",
        "ro.boot.serialno",
        "ril.product_code",
        "sys.usb.config"
    };

    public bool HasPendingData => _buffer.Length > 0 || _properties.Count > 0;
    public int ExtractedCount => _properties.Count;
    public DateTime LastAppendTime => _lastAppendTime;

    public void IngestChunk(string textFragment)
    {
        if (string.IsNullOrEmpty(textFragment)) return;
        _buffer.Append(textFragment);
        _lastAppendTime = DateTime.UtcNow;
        ParseCompletedLines();
    }

    private void ParseCompletedLines()
    {
        string current = _buffer.ToString();
        var matches = Regex.Matches(current, @"\[([a-zA-Z0-9_\.\-]+)\]:\s*\[([^\]]*)\]");
        foreach (Match m in matches)
        {
            string key = m.Groups[1].Value.Trim();
            string val = m.Groups[2].Value.Trim();
            _properties[key] = val;
        }

        int lastNewline = current.LastIndexOf('\n');
        if (lastNewline >= 0 && lastNewline < current.Length - 1)
        {
            string remainder = current[(lastNewline + 1)..];
            _buffer.Clear();
            _buffer.Append(remainder);
        }
        else if (lastNewline >= 0)
        {
            _buffer.Clear();
        }
    }

    public string BuildUnifiedSummary()
    {
        ParseCompletedLines();

        var parts = new List<string>();
        foreach (var key in ImportantProperties)
        {
            if (_properties.TryGetValue(key, out var val))
            {
                parts.Add($"{key}={val}");
            }
        }

        if (parts.Count == 0 && _properties.Count > 0)
        {
            foreach (var kvp in _properties.Take(7))
            {
                parts.Add($"{kvp.Key}={kvp.Value}");
            }
        }

        string result = parts.Count > 0
            ? string.Join(" | ", parts)
            : (_properties.Count > 0 ? $"{_properties.Count} properties extracted" : "No properties");

        return $"[ADB-GETPROP-SUMMARY] {result}";
    }

    public IReadOnlyDictionary<string, string> GetAllProperties()
    {
        ParseCompletedLines();
        return _properties;
    }

    public void Reset()
    {
        _buffer.Clear();
        _properties.Clear();
    }
}

/// <summary>
/// LAYER 10 — Shell & Interactive PTY Stream Reconstruction Engine
/// Supports classic ADB shell:, modern shell,v2,pty:, shell,v2,TERM=...,pty:, shell,pty:, and pty: sessions.
/// Unpacks 5-byte Shell Protocol v2 frames, decodes interactive keystroke-by-keystroke typing
/// (backspaces, Ctrl+U/Ctrl+W/Ctrl+C, arrow keys, ANSI escape sequences, UTF-8 multi-byte glyphs),
/// and reconstructs complete human-readable commands and clean multi-line terminal output.
/// </summary>
public sealed class ShellStreamReconstructor
{
    private readonly StringBuilder _rawAccumulator = new();
    private readonly List<char> _lineBuffer = [];
    private int _cursorPos = 0;
    private readonly List<string> _reconstructedCommands = [];
    private readonly AdbGetpropAggregator _getpropAggregator = new();

    public AdbGetpropAggregator GetpropAggregator => _getpropAggregator;
    public bool HasPendingInput => _lineBuffer.Count > 0;
    public string CurrentPendingLine => new string(_lineBuffer.ToArray());

    private enum ParserState
    {
        Normal,
        InEscape,
        InCsi,
        InOsc
    }

    private ParserState _state = ParserState.Normal;
    private readonly List<byte> _escapeBuffer = [];
    private readonly List<byte> _utf8Buffer = [];
    private int _expectedUtf8Bytes = 0;

    private readonly List<ulong> _currentCommandSequences = [];
    private readonly List<string> _currentCommandHashes = [];

    // Shell_v2 packet stream IDs
    public const byte ID_STDIN = 0;
    public const byte ID_STDOUT = 1;
    public const byte ID_STDERR = 2;
    public const byte ID_EXIT = 3;
    public const byte ID_CLOSE_STDIN = 4;
    public const byte ID_WINDOW_SIZE_CHANGE = 5;

    private static readonly Regex AnsiEscapeCleanRegex = new(
        @"\x1B(?:\[[0-9;?]*[a-zA-Z~]|\][^\x07\x1B]*(?:\x07|\x1B\\)|[=><A-Z0-9])",
        RegexOptions.Compiled);

    /// <summary>
    /// يفحص ما إذا كان النص يمثل أمر فتح قناة شل أو تيرمنال تفاعلي بنمط PTY
    /// مثل: shell:, shell,v2,pty:, shell,v2,TERM=xterm-256color,pty:, shell,pty:, pty:, exec:
    /// </summary>
    public static bool IsShellOrPtyOpenService(
        string? rawServiceText,
        out string serviceHeader,
        out string initialCommand,
        out bool isPtyMode,
        out bool isShellV2)
    {
        serviceHeader = string.Empty;
        initialCommand = string.Empty;
        isPtyMode = false;
        isShellV2 = false;

        if (string.IsNullOrWhiteSpace(rawServiceText))
            return false;

        string trimmed = rawServiceText.Trim('\0', '\r', '\n', ' ');

        // البحث عن بداية الخدمة إذا كانت مسبوقة بـ OPEN -> أو ما شابه
        if (trimmed.StartsWith("OPEN -> ", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed["OPEN -> ".Length..].Trim();
        else if (trimmed.StartsWith("OPEN ", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed["OPEN ".Length..].Trim();

        int colonIdx = trimmed.IndexOf(':');
        if (colonIdx <= 0)
            return false;

        string prefix = trimmed[..colonIdx].Trim();
        bool isShellPrefix = prefix.Equals("shell", StringComparison.OrdinalIgnoreCase) ||
                             prefix.StartsWith("shell,", StringComparison.OrdinalIgnoreCase);
        bool isPtyPrefix = prefix.Equals("pty", StringComparison.OrdinalIgnoreCase) ||
                           prefix.StartsWith("pty,", StringComparison.OrdinalIgnoreCase);
        bool isExecPrefix = prefix.Equals("exec", StringComparison.OrdinalIgnoreCase);

        if (!isShellPrefix && !isPtyPrefix && !isExecPrefix)
            return false;

        serviceHeader = trimmed[..(colonIdx + 1)];
        initialCommand = colonIdx + 1 < trimmed.Length
            ? trimmed[(colonIdx + 1)..].Split('\0')[0].Trim()
            : string.Empty;

        isShellV2 = prefix.Contains(",v2", StringComparison.OrdinalIgnoreCase);
        isPtyMode = isPtyPrefix ||
                    prefix.Contains(",pty", StringComparison.OrdinalIgnoreCase) ||
                    (isShellPrefix && !prefix.Contains(",raw", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(initialCommand));

        return true;
    }

    /// <summary>
    /// يقتطع بادئة الخدمة (shell: أو shell,v2,TERM=...,pty: أو pty:) ويعيد الأمر الصافي الداخلي
    /// </summary>
    public static string StripShellOrPtyPrefix(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        if (IsShellOrPtyOpenService(text, out _, out string innerCmd, out bool isPty, out _))
        {
            if (!string.IsNullOrWhiteSpace(innerCmd))
                return innerCmd;
            return isPty ? "[Interactive PTY Session Opened]" : "shell:";
        }
        return text.Trim();
    }

    public void ProcessInputBytes(ReadOnlySpan<byte> rawBytes, out string? completedCommand, out string rawTranscriptFragment)
    {
        ProcessInputBytes(rawBytes, null, null, out completedCommand, out rawTranscriptFragment, out _, out _);
    }

    public void ProcessInputBytes(
        ReadOnlySpan<byte> rawBytes,
        ulong? sequenceNumber,
        string? payloadHash,
        out string? completedCommand,
        out string rawTranscriptFragment,
        out List<ulong> evidenceSequences,
        out List<string> evidenceHashes)
    {
        completedCommand = null;

        // إذا كانت الحزمة مغلفة بترويسة Shell v2 (5 بايت)، نقوم بفكها أولاً قبل تجميع الحروف
        ReadOnlySpan<byte> effectiveBytes = rawBytes;
        if (TryUnpackShellV2Frames(rawBytes, out _, out byte[] unpacked, out bool isControlOnly, out _))
        {
            if (isControlOnly)
            {
                rawTranscriptFragment = string.Empty;
                evidenceSequences = [];
                evidenceHashes = [];
                return;
            }
            effectiveBytes = unpacked;
        }

        rawTranscriptFragment = Encoding.UTF8.GetString(effectiveBytes);
        _rawAccumulator.Append(rawTranscriptFragment);

        if (sequenceNumber.HasValue)
        {
            _currentCommandSequences.Add(sequenceNumber.Value);
        }
        if (!string.IsNullOrEmpty(payloadHash))
        {
            _currentCommandHashes.Add(payloadHash);
        }

        evidenceSequences = [];
        evidenceHashes = [];
        var completedLinesInChunk = new List<string>();

        int len = effectiveBytes.Length;
        for (int i = 0; i < len; i++)
        {
            byte b = effectiveBytes[i];

            // 1. Escape state machine (ANSI / VT100 sequences in PTY)
            if (_state == ParserState.InEscape)
            {
                _escapeBuffer.Add(b);
                if (b == (byte)'[')
                {
                    _state = ParserState.InCsi;
                }
                else if (b == (byte)']')
                {
                    _state = ParserState.InOsc;
                }
                else
                {
                    _state = ParserState.Normal;
                    _escapeBuffer.Clear();
                }
                continue;
            }

            if (_state == ParserState.InOsc)
            {
                _escapeBuffer.Add(b);
                if (b == 0x07 || _escapeBuffer.Count > 128) // BEL terminates OSC
                {
                    _state = ParserState.Normal;
                    _escapeBuffer.Clear();
                }
                continue;
            }

            if (_state == ParserState.InCsi)
            {
                _escapeBuffer.Add(b);
                if (b >= 0x20 && b <= 0x3F)
                {
                    if (_escapeBuffer.Count > 32)
                    {
                        _state = ParserState.Normal;
                        _escapeBuffer.Clear();
                    }
                    continue;
                }

                if (b >= 0x40 && b <= 0x7E)
                {
                    char finalChar = (char)b;
                    string fullSeq = Encoding.ASCII.GetString(_escapeBuffer.ToArray());
                    ApplyAnsiEscape(fullSeq, finalChar);
                    _state = ParserState.Normal;
                    _escapeBuffer.Clear();
                    continue;
                }

                _state = ParserState.Normal;
                _escapeBuffer.Clear();
                continue;
            }

            if (b == 0x1B) // ESC
            {
                _state = ParserState.InEscape;
                _escapeBuffer.Clear();
                _escapeBuffer.Add(b);
                continue;
            }

            // 2. Backspace (\x08 or \x7F)
            if (b == 0x08 || b == 0x7F)
            {
                if (_cursorPos > 0 && _cursorPos <= _lineBuffer.Count)
                {
                    _cursorPos--;
                    _lineBuffer.RemoveAt(_cursorPos);
                }
                continue;
            }

            // 3. Ctrl-U (0x15): Clear entire line in PTY
            if (b == 0x15)
            {
                _lineBuffer.Clear();
                _cursorPos = 0;
                continue;
            }

            // 4. Ctrl-W (0x17): Delete previous word in PTY
            if (b == 0x17)
            {
                while (_cursorPos > 0 && _lineBuffer[_cursorPos - 1] == ' ')
                {
                    _cursorPos--;
                    _lineBuffer.RemoveAt(_cursorPos);
                }
                while (_cursorPos > 0 && _lineBuffer[_cursorPos - 1] != ' ')
                {
                    _cursorPos--;
                    _lineBuffer.RemoveAt(_cursorPos);
                }
                continue;
            }

            // 5. Newline or Carriage Return (\n or \r)
            if (b == (byte)'\r' || b == (byte)'\n')
            {
                if (_lineBuffer.Count > 0)
                {
                    string cmd = new string(_lineBuffer.ToArray()).Trim();
                    if (!string.IsNullOrEmpty(cmd))
                    {
                        completedLinesInChunk.Add(cmd);
                        _reconstructedCommands.Add(cmd);
                    }
                    _lineBuffer.Clear();
                    _cursorPos = 0;
                }

                if (b == (byte)'\r' && i + 1 < len && effectiveBytes[i + 1] == (byte)'\n')
                {
                    i++;
                }

                continue;
            }

            // 6. Ctrl-C (0x03) or Ctrl-D (0x04)
            if (b == 0x03)
            {
                _lineBuffer.Clear();
                _cursorPos = 0;
                _currentCommandSequences.Clear();
                _currentCommandHashes.Clear();
                continue;
            }

            // 7. UTF-8 multi-byte decoding
            if (_expectedUtf8Bytes > 0)
            {
                if ((b & 0xC0) == 0x80)
                {
                    _utf8Buffer.Add(b);
                    _expectedUtf8Bytes--;
                    if (_expectedUtf8Bytes == 0)
                    {
                        InsertDecodedUtf8Chars(_utf8Buffer.ToArray());
                        _utf8Buffer.Clear();
                    }
                }
                else
                {
                    _utf8Buffer.Clear();
                    _expectedUtf8Bytes = 0;
                }
                continue;
            }

            // 8. Printable ASCII & Tab
            if ((b >= 0x20 && b < 0x7F) || b == (byte)'\t')
            {
                InsertChar(b == (byte)'\t' ? ' ' : (char)b);
            }
            else if (b >= 0xC2 && b <= 0xF4)
            {
                _utf8Buffer.Clear();
                _utf8Buffer.Add(b);
                if (b <= 0xDF) _expectedUtf8Bytes = 1;
                else if (b <= 0xEF) _expectedUtf8Bytes = 2;
                else _expectedUtf8Bytes = 3;
            }
        }

        if (completedLinesInChunk.Count > 0)
        {
            completedCommand = string.Join(Environment.NewLine, completedLinesInChunk);
            evidenceSequences = new List<ulong>(_currentCommandSequences);
            evidenceHashes = new List<string>(_currentCommandHashes);
            _currentCommandSequences.Clear();
            _currentCommandHashes.Clear();
        }
    }

    /// <summary>
    /// يفرغ أي نص متبقٍ في مخزن السطر التفاعلي (في حال أرسلت الأداة مفتاح مصادقة أو اختياراً بدون \n)
    /// </summary>
    public bool TryFlushPendingLine(out string flushedCommand)
    {
        flushedCommand = string.Empty;
        if (_lineBuffer.Count == 0)
            return false;

        string cmd = new string(_lineBuffer.ToArray()).Trim();
        _lineBuffer.Clear();
        _cursorPos = 0;
        _currentCommandSequences.Clear();
        _currentCommandHashes.Clear();

        if (string.IsNullOrWhiteSpace(cmd))
            return false;

        _reconstructedCommands.Add(cmd);
        flushedCommand = cmd;
        return true;
    }

    private void InsertChar(char c)
    {
        if (_cursorPos < _lineBuffer.Count)
        {
            _lineBuffer.Insert(_cursorPos, c);
        }
        else
        {
            _lineBuffer.Add(c);
        }
        _cursorPos++;
    }

    private void InsertDecodedUtf8Chars(byte[] bytes)
    {
        try
        {
            string s = Encoding.UTF8.GetString(bytes);
            foreach (char c in s)
            {
                InsertChar(c);
            }
        }
        catch { }
    }

    private void ApplyAnsiEscape(string seq, char finalChar)
    {
        switch (finalChar)
        {
            case 'D': // Cursor Left: \x1b[D
                if (_cursorPos > 0) _cursorPos--;
                break;
            case 'C': // Cursor Right: \x1b[C
                if (_cursorPos < _lineBuffer.Count) _cursorPos++;
                break;
            case 'H': // Cursor Home: \x1b[H
                _cursorPos = 0;
                break;
            case 'F': // Cursor End: \x1b[F
                _cursorPos = _lineBuffer.Count;
                break;
            case 'K': // Erase in line from cursor to end
                if (_cursorPos < _lineBuffer.Count)
                {
                    _lineBuffer.RemoveRange(_cursorPos, _lineBuffer.Count - _cursorPos);
                }
                break;
            case '~':
                if (seq.Contains("3~") && _cursorPos < _lineBuffer.Count)
                {
                    _lineBuffer.RemoveAt(_cursorPos);
                }
                else if (seq.Contains("1~"))
                {
                    _cursorPos = 0;
                }
                else if (seq.Contains("4~"))
                {
                    _cursorPos = _lineBuffer.Count;
                }
                break;
        }
    }

    /// <summary>
    /// يفك حزمة أو سلسلة حزم Shell Protocol v2 المتتالية (ترويسة 5 بايت: [StreamID: 1B][Length: 4B LE])
    /// بدقة عالية دون الخلط بينها وبين النصوص العادية.
    /// </summary>
    public static bool TryUnpackShellV2Frames(
        ReadOnlySpan<byte> packet,
        out byte primaryStreamId,
        out byte[] combinedPayload,
        out bool isControlOnly,
        out string? controlSummary)
    {
        primaryStreamId = 0;
        combinedPayload = Array.Empty<byte>();
        isControlOnly = false;
        controlSummary = null;

        if (packet.Length < 5)
            return false;

        int offset = 0;
        int frameCount = 0;
        int controlFrames = 0;
        byte firstDataStreamId = 0xFF;
        var dataBytes = new List<byte>(packet.Length);
        string? lastCtrlDesc = null;

        while (offset + 5 <= packet.Length)
        {
            byte sid = packet[offset];
            if (sid > ID_WINDOW_SIZE_CHANGE)
                return false;

            uint len = BitConverter.ToUInt32(packet.Slice(offset + 1, 4));
            if (len > 256 * 1024 || offset + 5 + (int)len > packet.Length)
                return false;

            ReadOnlySpan<byte> slice = packet.Slice(offset + 5, (int)len);
            frameCount++;

            if (sid is ID_STDIN or ID_STDOUT or ID_STDERR)
            {
                if (firstDataStreamId == 0xFF)
                    firstDataStreamId = sid;
                for (int i = 0; i < slice.Length; i++)
                    dataBytes.Add(slice[i]);
            }
            else if (sid == ID_WINDOW_SIZE_CHANGE)
            {
                controlFrames++;
                string winSpec = Encoding.ASCII.GetString(slice).Trim('\0', '\r', '\n');
                lastCtrlDesc = $"[PTY-WINDOW-RESIZE] {winSpec}";
            }
            else if (sid == ID_CLOSE_STDIN)
            {
                controlFrames++;
                lastCtrlDesc = "[PTY-CLOSE-STDIN]";
            }
            else if (sid == ID_EXIT)
            {
                controlFrames++;
                int exitCode = slice.Length > 0 ? slice[0] : 0;
                lastCtrlDesc = $"[PTY-EXIT] Code={exitCode}";
            }

            offset += 5 + (int)len;
        }

        // يجب أن تستهلك إطارات Shell v2 الحزمة بالكامل لضمان عدم التطابق العشوائي مع أي بيانات أخرى
        if (frameCount == 0 || offset != packet.Length)
            return false;

        primaryStreamId = firstDataStreamId != 0xFF ? firstDataStreamId : packet[0];
        combinedPayload = dataBytes.ToArray();
        isControlOnly = dataBytes.Count == 0 && controlFrames > 0;
        controlSummary = lastCtrlDesc;
        return true;
    }

    public static bool TryUnpackShellV2(ReadOnlySpan<byte> packet, out byte streamId, out byte[] payload)
    {
        if (TryUnpackShellV2Frames(packet, out streamId, out payload, out _, out _))
            return true;

        streamId = 0;
        payload = Array.Empty<byte>();
        if (packet.Length < 5) return false;

        streamId = packet[0];
        if (streamId > ID_WINDOW_SIZE_CHANGE) return false;
        uint length = BitConverter.ToUInt32(packet[1..5]);

        if (length <= 256 * 1024 && packet.Length >= 5 + length)
        {
            payload = new byte[length];
            packet.Slice(5, (int)length).CopyTo(payload);
            return true;
        }

        return false;
    }

    public static string CleanTerminalOutput(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        return AnsiEscapeCleanRegex.Replace(raw, "");
    }

    public string GetFullRawTranscript() => _rawAccumulator.ToString();

    public IReadOnlyList<string> ReconstructedCommands => _reconstructedCommands;

    public void Reset()
    {
        _rawAccumulator.Clear();
        _lineBuffer.Clear();
        _cursorPos = 0;
        _reconstructedCommands.Clear();
        _state = ParserState.Normal;
        _escapeBuffer.Clear();
        _utf8Buffer.Clear();
        _expectedUtf8Bytes = 0;
        _currentCommandSequences.Clear();
        _currentCommandHashes.Clear();
        _getpropAggregator.Reset();
    }
}
