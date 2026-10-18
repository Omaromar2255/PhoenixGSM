namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Dedicated classifier to isolate pure Host-to-Device commands directed to a connected phone,
/// classify their exact command type (ADB-SHELL, ADB-AT-RIL, MODEM-AT, MTK-BROM, etc.),
/// filter out binary ELF transfer chunks and host OS background noise, and pair clean device responses.
/// </summary>
public static partial class PhoneCommandClassifier
{
    public static bool IsPhoneInteraction(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "",
        bool includeResponses = false)
    {
        if (IsPhoneDirectedCommand(command, summary, direction, protocol, categoryName, additionalDetails))
            return true;

        if (includeResponses && IsPhoneDeviceResponse(command, summary, direction, protocol, categoryName, additionalDetails))
            return true;

        return false;
    }
}
