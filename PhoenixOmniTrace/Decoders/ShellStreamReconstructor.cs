using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// LAYER 10 — Shell Stream Reconstruction Engine
/// Distinguishes stdin/stdout/stderr/exit, decodes interactive line editing
/// (backspaces, arrow keys, ANSI escape sequences, UTF-8 multi-byte glyphs),
/// handles chunk-fragmented escape sequences, and maintains dual streams:
/// 1. Byte-exact Raw Stream (for forensic evidence)
/// 2. Reconstructed Human Command (for analytical clarity)
/// </summary>
public sealed class ShellStreamReconstructor
{
    private readonly StringBuilder _rawAccumulator = new();
    private readonly List<char> _lineBuffer = [];
    private int _cursorPos = 0;
    private readonly List<string> _reconstructedCommands = [];

    // State machine for chunk-spanning escape sequences
    private enum ParserState
    {
        Normal,
        InEscape,
        InCsi
    }

    private ParserState _state = ParserState.Normal;
    private readonly List<byte> _escapeBuffer = [];
    private readonly List<byte> _utf8Buffer = [];
    private int _expectedUtf8Bytes = 0;

    // Track contributing evidence
    private readonly List<ulong> _currentCommandSequences = [];
    private readonly List<string> _currentCommandHashes = [];

    // Shell_v2 packet IDs
    public const byte ID_STDIN = 0;
    public const byte ID_STDOUT = 1;
    public const byte ID_STDERR = 2;
    public const byte ID_EXIT = 3;
    public const byte ID_CLOSE_STDIN = 4;
    public const byte ID_WINDOW_SIZE_CHANGE = 5;

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
        rawTranscriptFragment = Encoding.UTF8.GetString(rawBytes);
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

        int len = rawBytes.Length;
        for (int i = 0; i < len; i++)
        {
            byte b = rawBytes[i];

            // 1. Handling escape state machine
            if (_state == ParserState.InEscape)
            {
                _escapeBuffer.Add(b);
                if (b == (byte)'[')
                {
                    _state = ParserState.InCsi;
                }
                else
                {
                    // Non-CSI escape sequence (single-byte follower)
                    _state = ParserState.Normal;
                    _escapeBuffer.Clear();
                }
                continue;
            }

            if (_state == ParserState.InCsi)
            {
                _escapeBuffer.Add(b);
                // CSI parameter/intermediate bytes: 0x20..0x3F
                if (b >= 0x20 && b <= 0x3F)
                {
                    if (_escapeBuffer.Count > 32)
                    {
                        // Escape sequence safety abort
                        _state = ParserState.Normal;
                        _escapeBuffer.Clear();
                    }
                    continue;
                }

                // CSI final bytes: 0x40..0x7E
                if (b >= 0x40 && b <= 0x7E)
                {
                    char finalChar = (char)b;
                    string fullSeq = Encoding.ASCII.GetString(_escapeBuffer.ToArray());
                    ApplyAnsiEscape(fullSeq, finalChar);
                    _state = ParserState.Normal;
                    _escapeBuffer.Clear();
                    continue;
                }

                // Unexpected byte in CSI
                _state = ParserState.Normal;
                _escapeBuffer.Clear();
                continue;
            }

            // Normal state
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

            // 3. Newline or Carriage Return (\n or \r)
            if (b == (byte)'\r' || b == (byte)'\n')
            {
                if (_lineBuffer.Count > 0)
                {
                    string cmd = new string(_lineBuffer.ToArray()).Trim();
                    if (!string.IsNullOrEmpty(cmd))
                    {
                        completedCommand = cmd;
                        _reconstructedCommands.Add(cmd);
                        evidenceSequences = new List<ulong>(_currentCommandSequences);
                        evidenceHashes = new List<string>(_currentCommandHashes);
                        _currentCommandSequences.Clear();
                        _currentCommandHashes.Clear();
                    }
                    _lineBuffer.Clear();
                    _cursorPos = 0;
                }

                // If \r\n, check if next byte is \n and skip it
                if (b == (byte)'\r' && i + 1 < len && rawBytes[i + 1] == (byte)'\n')
                {
                    i++;
                }

                continue;
            }

            // 4. Ctrl-C (0x03) or Ctrl-D (0x04)
            if (b == 0x03)
            {
                _lineBuffer.Clear();
                _cursorPos = 0;
                _currentCommandSequences.Clear();
                _currentCommandHashes.Clear();
                continue;
            }

            // 5. UTF-8 multi-byte decoding
            if (_expectedUtf8Bytes > 0)
            {
                if ((b & 0xC0) == 0x80) // Continuation byte
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
                    // Invalid continuation byte, reset
                    _utf8Buffer.Clear();
                    _expectedUtf8Bytes = 0;
                }
                continue;
            }

            // ASCII printable
            if (b >= 0x20 && b < 0x80)
            {
                char c = (char)b;
                InsertChar(c);
            }
            // UTF-8 lead byte
            else if (b >= 0xC2 && b <= 0xF4)
            {
                _utf8Buffer.Clear();
                _utf8Buffer.Add(b);
                if (b <= 0xDF) _expectedUtf8Bytes = 1;
                else if (b <= 0xEF) _expectedUtf8Bytes = 2;
                else _expectedUtf8Bytes = 3;
            }
        }
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
            case '~': // Keypad / Extended functions
                if (seq.Contains("3~") && _cursorPos < _lineBuffer.Count) // Delete key: \x1b[3~
                {
                    _lineBuffer.RemoveAt(_cursorPos);
                }
                else if (seq.Contains("1~")) // Home key
                {
                    _cursorPos = 0;
                }
                else if (seq.Contains("4~")) // End key
                {
                    _cursorPos = _lineBuffer.Count;
                }
                break;
        }
    }

    public static bool TryUnpackShellV2(ReadOnlySpan<byte> packet, out byte streamId, out byte[] payload)
    {
        streamId = 0;
        payload = Array.Empty<byte>();

        // Shell_v2 packet layout:
        // [0]: stream_id (1 byte)
        // [1..4]: length (4 bytes uint little endian)
        // [5..5+length]: payload
        if (packet.Length < 5) return false;

        streamId = packet[0];
        uint length = BitConverter.ToUInt32(packet[1..5]);

        if (packet.Length >= 5 + length)
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
        // Strip common ANSI escape codes from output
        return Regex.Replace(raw, @"\x1B\[[0-9;]*[a-zA-Z~]", "");
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
    }
}
