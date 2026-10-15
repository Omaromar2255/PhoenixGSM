using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.NetworkInterception;

public class DataLeakFinding
{
    public string DataType { get; set; } = string.Empty;
    public string Match { get; set; } = string.Empty;
}

public class DataLeakDetector : IDisposable
{
    private static readonly Regex E164PhoneRegex = new Regex(@"^\+?[1-9]\d{1,14}$", RegexOptions.Compiled);
    private static readonly Regex ImeiRegex = new Regex(@"^\d{15}$", RegexOptions.Compiled);
    private static readonly Regex ImsiRegex = new Regex(@"^\d{15}$", RegexOptions.Compiled);

    /// <summary>
    /// فحص تسرب البيانات / Scan for data leaks
    /// </summary>
    public List<DataLeakFinding> ScanForLeaks(ReadOnlySpan<byte> payload)
    {
        var findings = new List<DataLeakFinding>();
        try
        {
            string text = Encoding.ASCII.GetString(payload);

            // 1. IMEI Matching (15 digits, could validate Luhn)
            var imeiMatches = ImeiRegex.Matches(text);
            foreach (Match m in imeiMatches)
            {
                if (IsValidLuhn(m.Value))
                {
                    findings.Add(new DataLeakFinding { DataType = "IMEI", Match = m.Value });
                }
            }

            // 2. Phone numbers
            var phoneMatches = E164PhoneRegex.Matches(text);
            foreach (Match m in phoneMatches)
            {
                findings.Add(new DataLeakFinding { DataType = "PhoneNumber", Match = m.Value });
            }

            // 3. Contact list patterns
            if (text.Contains("BEGIN:VCARD") || text.Contains("\"contacts\":"))
            {
                findings.Add(new DataLeakFinding { DataType = "ContactList", Match = "vCard or JSON contacts detected" });
            }

            // 4. SMS Database
            if (text.Contains("SQLite format 3") && text.Contains("sms"))
            {
                findings.Add(new DataLeakFinding { DataType = "SMS_Database", Match = "SQLite SMS DB header detected" });
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[DataLeakDetector] ScanForLeaks Error: {ex.Message}");
        }
        return findings;
    }

    private bool IsValidLuhn(string number)
    {
        int sum = 0;
        bool alternate = false;
        for (int i = number.Length - 1; i >= 0; i--)
        {
            int n = number[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n = (n % 10) + 1;
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }

    public void Dispose()
    {
        // Cleanup
    }
}
