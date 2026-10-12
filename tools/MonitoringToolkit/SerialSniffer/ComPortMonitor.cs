namespace PhoenixGSM.SerialSniffer;

using System.IO.Ports;
using System.Text;
using System.Text.Json;
using PhoenixGSM.SerialSniffer.Models;

/// <summary>
/// Serial port monitor — captures sent and received data
/// </summary>
public class ComPortMonitor : IDisposable
{
    private SerialPort? _port;
    private readonly string _logDirectory;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly List<SerialPacket> _capturedPackets = [];
    private bool _isMonitoring;
    public bool IsMonitoring => _isMonitoring;
    private CancellationTokenSource? _cts;

    // Statistics
    private long _totalBytesReceived;
    public long TotalBytesSent { get; set; }
    public long TotalBytesReceived => _totalBytesReceived;
    private int _totalPackets;
    private readonly Dictionary<string, int> _protocolCounts = [];
    private readonly List<byte> _streamAccumulator = [];
    private readonly object _streamLock = new();

    public event Action<SerialPacket>? OnPacketCaptured;

    public ComPortMonitor(string logDirectory)
    {
        _logDirectory = logDirectory;
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        Directory.CreateDirectory(_logDirectory);
    }

    /// <summary>
    /// List all available ports with details
    /// </summary>
    public static void ListPorts()
    {
        var ports = SerialPort.GetPortNames();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("+======================================+");
        Console.WriteLine("|       Available Serial Ports         |");
        Console.WriteLine("+======================================+");
        Console.ResetColor();

        if (ports.Length == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  [!] No COM ports detected.");
            Console.ResetColor();
            return;
        }

        foreach (var port in ports.OrderBy(p => p))
        {
            Console.Write("  * ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(port);
            Console.ResetColor();

            try
            {
                using var sp = new SerialPort(port);
                sp.Open();
                sp.Close();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" - Ready / Available");
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" - In Use / Busy");
            }
            Console.ResetColor();
        }
    }

    /// <summary>
    /// Start monitoring a specific port
    /// </summary>
    public async Task StartMonitoringAsync(string portName, int baudRate = 115200)
    {
        _cts = new CancellationTokenSource();

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                _port?.Dispose();
                _port = new SerialPort(portName)
                {
                    BaudRate = baudRate,
                    DataBits = 8,
                    StopBits = StopBits.One,
                    Parity = Parity.None,
                    ReadTimeout = 1000,
                    WriteTimeout = 1000,
                    ReadBufferSize = 65536,
                    DtrEnable = true,
                    RtsEnable = true,
                    Handshake = Handshake.None
                };

                _port.DataReceived += OnDataReceived;
                _port.Open();
                _isMonitoring = true;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] Started monitoring {portName} @ {baudRate} baud (DTR/RTS Enabled)");
                Console.WriteLine("    Listening for AT commands and modem traffic... (Press Ctrl+C to stop)\n");
                Console.ResetColor();

                PrintHeader();

                try
                {
                    await Task.Delay(Timeout.Infinite, _cts.Token);
                }
                catch (TaskCanceledException) { }
                break;
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] Port {portName} is currently busy/in-use by another GSM tool. Monitoring in fail-open standby (retrying)...");
                Console.ResetColor();
                try { await Task.Delay(1500, _cts.Token); } catch (TaskCanceledException) { break; }
            }
            catch (TaskCanceledException) { break; }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Error: {ex.Message}. Retrying...");
                Console.ResetColor();
                try { await Task.Delay(2000, _cts.Token); } catch (TaskCanceledException) { break; }
            }
        }
    }

    /// <summary>
    /// Passive monitoring - watches for newly connected ports
    /// </summary>
    public async Task WatchForNewPortsAsync()
    {
        _cts = new CancellationTokenSource();
        var knownPorts = new HashSet<string>(SerialPort.GetPortNames());

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("[*] Watching for new ports... (Connect your device)");
        Console.ResetColor();

        while (!_cts.Token.IsCancellationRequested)
        {
            var currentPorts = new HashSet<string>(SerialPort.GetPortNames());

            foreach (var port in currentPorts.Except(knownPorts))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] New port attached: {port}");
                Console.ResetColor();
                Console.WriteLine("    -> Could be Download Mode, Recovery, or EDL mode.");
            }

            foreach (var port in knownPorts.Except(currentPorts))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n[-] Port disconnected: {port}");
                Console.ResetColor();
            }

            knownPorts = currentPorts;

            try { await Task.Delay(1000, _cts.Token); }
            catch (TaskCanceledException) { break; }
        }
    }

    private void OnDataReceived(object sender, SerialDataReceivedEventArgs e)
    {
        if (_port == null || !_port.IsOpen) return;

        try
        {
            var bytesToRead = _port.BytesToRead;
            if (bytesToRead == 0) return;

            var buffer = new byte[bytesToRead];
            _port.Read(buffer, 0, bytesToRead);

            bool isAt = IsAtCommand(buffer);
            string proto = ProtocolTypes.Detect(buffer);
            string commandAscii = ConvertToSafeAscii(buffer);

            // Also check accumulated stream for fragmented multi-byte arrivals
            lock (_streamLock)
            {
                _streamAccumulator.AddRange(buffer);
                if (_streamAccumulator.Count > 4096)
                {
                    _streamAccumulator.RemoveRange(0, _streamAccumulator.Count - 2048);
                }

                if (_streamAccumulator.Contains((byte)'\r') || _streamAccumulator.Contains((byte)'\n'))
                {
                    byte[] accArray = _streamAccumulator.ToArray();
                    if (!isAt && IsAtCommand(accArray))
                    {
                        isAt = true;
                        proto = ProtocolTypes.AtCommand;
                        commandAscii = ConvertToSafeAscii(accArray);
                    }
                    int lastTerm = Math.Max(_streamAccumulator.LastIndexOf((byte)'\r'), _streamAccumulator.LastIndexOf((byte)'\n'));
                    if (lastTerm >= 0 && lastTerm < _streamAccumulator.Count - 1)
                        _streamAccumulator.RemoveRange(0, lastTerm + 1);
                    else
                        _streamAccumulator.Clear();
                }
            }

            var packet = new SerialPacket
            {
                Timestamp = DateTime.Now,
                Direction = "RX",
                Port = _port.PortName,
                HexData = BitConverter.ToString(buffer).Replace("-", " "),
                AsciiData = commandAscii,
                Size = buffer.Length,
                BaudRate = _port.BaudRate,
                IsAtCommand = isAt,
                Protocol = proto
            };

            _capturedPackets.Add(packet);
            _totalBytesReceived += buffer.Length;
            _totalPackets++;
            _protocolCounts[packet.Protocol] = _protocolCounts.GetValueOrDefault(packet.Protocol) + 1;

            PrintPacket(packet, buffer);
            SavePacketAsync(packet).ConfigureAwait(false);
            OnPacketCaptured?.Invoke(packet);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"\n[!] Read Error: {ex.Message}");
            Console.ResetColor();
        }
    }

    private void PrintPacket(SerialPacket packet, byte[] rawData)
    {
        var color = packet.Direction == "TX" ? ConsoleColor.Yellow : ConsoleColor.Cyan;
        var arrow = packet.Direction == "TX" ? ">>" : "<<";
        var protocolColor = packet.Protocol switch
        {
            ProtocolTypes.AtCommand => ConsoleColor.Green,
            ProtocolTypes.Odin => ConsoleColor.Magenta,
            ProtocolTypes.Qualcomm => ConsoleColor.Blue,
            _ => ConsoleColor.Gray
        };

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  {packet.Timestamp:HH:mm:ss.fff} ");
        Console.ForegroundColor = color;
        Console.Write($"{arrow} {packet.Direction} ");
        Console.ForegroundColor = protocolColor;
        Console.Write($"[{packet.Protocol}] ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"({packet.Size} bytes)");

        for (int i = 0; i < rawData.Length; i += 16)
        {
            var chunk = rawData.Skip(i).Take(16).ToArray();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {i:X4}: ");

            Console.ForegroundColor = ConsoleColor.White;
            for (int j = 0; j < 16; j++)
            {
                if (j < chunk.Length)
                    Console.Write($"{chunk[j]:X2} ");
                else
                    Console.Write("   ");

                if (j == 7) Console.Write(" ");
            }

            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            foreach (var b in chunk)
            {
                Console.Write(b >= 32 && b < 127 ? (char)b : '.');
            }

            Console.WriteLine();
        }

        if (packet.IsAtCommand)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("  [Info] ");
            Console.WriteLine(InterpretAtCommand(packet.AsciiData));
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private static string InterpretAtCommand(string command)
    {
        var upper = command.Trim().ToUpperInvariant();
        return upper switch
        {
            _ when upper.StartsWith("AT+CLCK") => "Network Lock Query/Status",
            _ when upper.StartsWith("AT+CPIN") => "PIN / PUK Check/Entry",
            _ when upper.StartsWith("AT+EGMR") => "IMEI Read/Write Operation",
            _ when upper.StartsWith("AT+CFUN") => "Phone Functionality / Radio Mode",
            _ when upper.StartsWith("AT+CGSN") => "Serial Number / IMEI Request",
            _ when upper.StartsWith("AT+CGMM") => "Device Model Identification",
            _ when upper.StartsWith("AT+CGMI") => "Manufacturer Identification",
            _ when upper.StartsWith("AT+CGMR") => "Firmware / Software Version",
            _ when upper.StartsWith("AT+CSQ") => "Signal Quality Report",
            _ when upper.StartsWith("AT+COPS") => "Operator Selection / Registration",
            _ when upper.StartsWith("AT+CREG") => "Network Registration Status",
            _ when upper.StartsWith("AT+CIMI") => "SIM IMSI Request",
            _ when upper.StartsWith("AT+DEVINFO") => "Samsung Device / Modem Info Query",
            _ when upper.StartsWith("ATI") => "Device General Info",
            _ when upper.StartsWith("AT+CMGS") => "Send SMS Message",
            _ when upper.StartsWith("AT+CMGL") => "List SMS Messages",
            _ when upper == "AT" => "AT Ping / Handshake",
            _ when upper.StartsWith("AT") => $"AT Command: {upper[..Math.Min(upper.Length, 35)]}",
            _ when upper.StartsWith("A/") => "Repeat Previous AT Command",
            _ when upper.StartsWith("+DEVINFO") => "Modem Device Information Response",
            _ when upper.StartsWith("+CPIN") => "SIM Card PIN/PUK Status Response",
            _ when upper.StartsWith("+CSQ") => "Radio Signal Strength Response",
            _ when upper.StartsWith("+CREG") => "Network Registration Status Response",
            _ when upper.StartsWith("+COPS") => "Network Operator Response",
            _ when upper.StartsWith("+CGSN") => "Device IMEI / Serial Response",
            _ when upper.StartsWith("+CGMM") => "Device Model Response",
            _ when upper.StartsWith("+CGMI") => "Device Manufacturer Response",
            _ when upper.StartsWith("+CGMR") => "Firmware Version Response",
            _ when upper.StartsWith("+CIMI") => "SIM IMSI Response",
            _ when upper.StartsWith("+CLCK") => "Network Lock Status Response",
            _ when upper.StartsWith("+EGMR") => "IMEI Operation Response",
            _ when upper.StartsWith("+CME ERROR") => "Equipment Extended Error Response",
            _ when upper.StartsWith("+CMS ERROR") => "Message Service Error Response",
            _ when upper.StartsWith("^BOOT") => "Device Boot Notification",
            _ when upper.StartsWith("^RSSI") => "Radio Signal Strength Indication",
            _ when upper.StartsWith("^MODE") => "Network Mode Notification",
            _ when upper.StartsWith("^DSFLOWRPT") => "Data Flow Report Notification",
            _ when upper.StartsWith("AT+GCAP") => "Request Capabilities List",
            _ when upper.StartsWith("ATE0") => "Disable Command Echo (Echo Off)",
            _ when upper.StartsWith("ATE1") => "Enable Command Echo (Echo On)",
            _ when upper.StartsWith("ATZ") => "Reset Modem Configuration",
            _ when upper.StartsWith("ATH") => "Hook Control / Disconnect Active Call",
            _ when upper.StartsWith("ATO") => "Return to Online Data State",
            _ when upper.StartsWith("AT&F") => "Restore Factory Default Configuration",
            _ when upper.StartsWith("AT&W") => "Store Configuration to NV Profile",
            _ when upper.StartsWith("ATD") => "Dial / Data Connection Setup",
            _ when upper.StartsWith("+++") => "Escape Sequence (Return to Command Mode)",
            _ when upper.StartsWith("RDY") => "Modem Subsystem Ready",
            _ when upper.StartsWith("SIM PIN") => "SIM PIN Required",
            _ when upper.StartsWith("SIM PUK") => "SIM PUK Required",
            _ when upper.StartsWith("READY") => "Modem Initialization Ready",
            _ when upper.StartsWith("CALL READY") => "Voice/Call Subsystem Ready",
            _ when upper.StartsWith("SMS READY") => "SMS Subsystem Ready",
            _ when upper.StartsWith("SMS DONE") => "SMS Service Initialized",
            _ when upper.StartsWith("PB DONE") => "Phonebook Initialized",
            _ when upper == "OK" || upper.StartsWith("OK") => "Command Acknowledged / Success (OK)",
            _ when upper == "ERROR" || upper.StartsWith("ERROR") => "Command Failed / Syntax Error",
            _ when upper.StartsWith("RING") => "Incoming Call / Ring Indication",
            _ when upper.StartsWith("NO CARRIER") => "Carrier Dropped / Disconnected",
            _ when upper.StartsWith("CONNECT") => "Modem Data Carrier Connected",
            _ when upper.StartsWith("+") => $"Extended Response: {upper[..Math.Min(upper.Length, 35)]}",
            _ when upper == "0" => "Command Acknowledged / Success (Numeric OK: 0)",
            _ when upper == "1" => "Modem Carrier Connected (Numeric: 1)",
            _ when upper == "2" => "Ring Indication (Numeric: 2)",
            _ when upper == "3" => "No Carrier (Numeric: 3)",
            _ when upper == "4" => "Command Failed / Error (Numeric: 4)",
            _ when upper.StartsWith(">") => "SMS Input Prompt (Ready for PDU / Text)",
            _ when upper.Length >= 14 && upper.Length <= 16 && upper.All(char.IsDigit) => $"IMEI/IMSI Number: {upper}",
            _ when upper.StartsWith("%") || upper.StartsWith("$") || upper.StartsWith("#") || upper.StartsWith("*") || upper.StartsWith("@") => $"Vendor Modem Notification: {upper[..Math.Min(upper.Length, 35)]}",
            _ when upper.StartsWith("SAMSUNG") || upper.StartsWith("QUALCOMM") || upper.StartsWith("MEDIATEK") || upper.StartsWith("SPREADTRUM") || upper.StartsWith("HUAWEI") => $"Modem Identification / Info: {upper[..Math.Min(upper.Length, 35)]}",
            _ => command
        };
    }

    private static bool IsAtCommand(byte[] data)
    {
        if (data == null || data.Length == 0) return false;

        // Skip leading whitespace / CR / LF / null bytes
        int start = 0;
        while (start < data.Length && (data[start] == '\r' || data[start] == '\n' || data[start] == ' ' || data[start] == '\t' || data[start] == 0))
        {
            start++;
        }
        if (start >= data.Length) return false;

        var text = Encoding.ASCII.GetString(data, start, data.Length - start).Trim();
        if (text.Length == 0) return false;

        var upper = text.ToUpperInvariant();

        // 1. AT command starters & escape
        if (upper.StartsWith("AT") || upper.StartsWith("A/") || upper.StartsWith("+++")) return true;

        // 2. Standard modem response codes
        if (upper.StartsWith("OK") ||
            upper.StartsWith("ERROR") ||
            upper.Contains("+CME") ||
            upper.Contains("+CMS") ||
            upper.StartsWith("RING") ||
            upper.StartsWith("NO CARRIER") ||
            upper.StartsWith("CONNECT") ||
            upper.StartsWith("BUSY") ||
            upper.StartsWith("NO DIALTONE") ||
            upper.StartsWith("NO ANSWER"))
        {
            return true;
        }

        // 3. Operational indications
        if (upper.StartsWith("RDY") ||
            upper.StartsWith("NORMAL POWER DOWN") ||
            upper.StartsWith("UNDER_VOLTAGE") ||
            upper.StartsWith("SIM PIN") ||
            upper.StartsWith("SIM PUK") ||
            upper.StartsWith("READY") ||
            upper.StartsWith("CALL READY") ||
            upper.StartsWith("SMS READY") ||
            upper.StartsWith("SMS DONE") ||
            upper.StartsWith("PB DONE"))
        {
            return true;
        }

        // 4. Single digit result codes in ATV0 mode (0, 1, 2, 3, 4, 6, 7, 8)
        if (text.Length == 1 && "01234678".Contains(text[0])) return true;

        // 5. Extended response tags: +, ^, %, $, #, *, @
        if (text.Length >= 2 && (text[0] == '+' || text[0] == '^' || text[0] == '%' || text[0] == '$' || text[0] == '#' || text[0] == '*' || text[0] == '@'))
        {
            if (char.IsLetter(text[1]) || (text.Length >= 3 && char.IsLetter(text[2])))
                return true;
        }

        // 6. SMS prompt
        if (text.StartsWith(">")) return true;

        // 7. Numeric IMEI / IMSI (14-16 digits)
        if (text.Length >= 14 && text.Length <= 16 && text.All(char.IsDigit)) return true;

        // 8. Known manufacturer / chip responses
        if (upper.StartsWith("SAMSUNG") || upper.StartsWith("QUALCOMM") || upper.StartsWith("MEDIATEK") || upper.StartsWith("SPREADTRUM") || upper.StartsWith("HUAWEI") ||
            upper.StartsWith("QUECTEL") || upper.StartsWith("SIMCOM") || upper.StartsWith("FIBOCOM") || upper.StartsWith("TELIT") || upper.StartsWith("ZTE"))
            return true;

        return false;
    }

    private static string ConvertToSafeAscii(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (var b in data)
            sb.Append(b >= 32 && b < 127 ? (char)b : '.');
        return sb.ToString();
    }

    private static void PrintHeader()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  -------------------------------------------------------------");
        Console.WriteLine("  Timestamp       Dir Protocol        Size");
        Console.WriteLine("  -------------------------------------------------------------");
        Console.ResetColor();
    }

    private async Task SavePacketAsync(SerialPacket packet)
    {
        var fileName = $"serial_log_{packet.Port}_{DateTime.Now:yyyy-MM-dd}.jsonl";
        var filePath = Path.Combine(_logDirectory, fileName);
        var jsonLine = JsonSerializer.Serialize(packet, _jsonOptions) + Environment.NewLine;
        await File.AppendAllTextAsync(filePath, jsonLine, Encoding.UTF8);
    }

    public void PrintStats()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n+======================================+");
        Console.WriteLine("|       Monitoring Statistics          |");
        Console.WriteLine("+======================================+");
        Console.ResetColor();
        Console.WriteLine($"  Packets Total : {_totalPackets}");
        Console.WriteLine($"  Bytes Received: {_totalBytesReceived:N0}");
        Console.WriteLine($"  Bytes Sent    : {TotalBytesSent:N0}");
        Console.WriteLine("\n  Protocols Breakdown:");
        foreach (var (protocol, count) in _protocolCounts.OrderByDescending(x => x.Value))
            Console.WriteLine($"    {protocol,-20} {count,5} packets");
    }

    public void Stop()
    {
        _isMonitoring = false;
        _cts?.Cancel();
        PrintStats();
    }

    public void Dispose()
    {
        Stop();
        _port?.Close();
        _port?.Dispose();
        _cts?.Dispose();
    }
}
