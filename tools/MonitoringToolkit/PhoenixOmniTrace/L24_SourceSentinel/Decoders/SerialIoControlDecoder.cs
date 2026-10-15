using System;
using System.Text;

namespace PhoenixOmniTrace.L24_SourceSentinel.Decoders;

public static class SerialIoControlDecoder
{
    // Serial Device IOCTL Constants
    public const uint IOCTL_SERIAL_SET_BAUD_RATE = 0x001B0004;
    public const uint IOCTL_SERIAL_SET_LINE_CONTROL = 0x001B000C;
    public const uint IOCTL_SERIAL_SET_TIMEOUTS = 0x001B001C;
    public const uint IOCTL_SERIAL_GET_BAUD_RATE = 0x001B0050;
    public const uint IOCTL_SERIAL_SET_CHARS = 0x001B0054;
    public const uint IOCTL_SERIAL_SET_HANDFLOW = 0x001B0060;
    public const uint IOCTL_SERIAL_PURGE = 0x001B004C;
    public const uint IOCTL_SERIAL_RESET_DEVICE = 0x001B002C;
    public const uint IOCTL_SERIAL_SET_RTS = 0x001B0030;
    public const uint IOCTL_SERIAL_CLR_RTS = 0x001B0034;
    public const uint IOCTL_SERIAL_SET_DTR = 0x001B0024;
    public const uint IOCTL_SERIAL_CLR_DTR = 0x001B0028;

    // USB / WinUSB IOCTL Constants
    public const uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX = 0x00220448;
    public const uint IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION = 0x00220410;
    public const uint IOCTL_WINUSB_GET_DESCRIPTOR = 0x00220008;

    public static bool IsKnownIoControl(uint ioctlCode)
    {
        return ioctlCode switch
        {
            IOCTL_SERIAL_SET_BAUD_RATE => true,
            IOCTL_SERIAL_SET_LINE_CONTROL => true,
            IOCTL_SERIAL_SET_TIMEOUTS => true,
            IOCTL_SERIAL_GET_BAUD_RATE => true,
            IOCTL_SERIAL_SET_CHARS => true,
            IOCTL_SERIAL_SET_HANDFLOW => true,
            IOCTL_SERIAL_PURGE => true,
            IOCTL_SERIAL_RESET_DEVICE => true,
            IOCTL_SERIAL_SET_RTS => true,
            IOCTL_SERIAL_CLR_RTS => true,
            IOCTL_SERIAL_SET_DTR => true,
            IOCTL_SERIAL_CLR_DTR => true,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX => true,
            IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION => true,
            IOCTL_WINUSB_GET_DESCRIPTOR => true,
            _ => false
        };
    }

    public static (string Category, string Description) Decode(uint ioctlCode, ReadOnlySpan<byte> payload, string targetResource)
    {
        switch (ioctlCode)
        {
            case IOCTL_SERIAL_SET_BAUD_RATE:
                if (payload.Length >= 4)
                {
                    int baud = BitConverter.ToInt32(payload);
                    return ("Port Config (BaudRate)", $"تهيئة سرعة المنفذ [{targetResource}] على BaudRate = {baud} bps");
                }
                return ("Port Config (BaudRate)", $"طلب ضبط سرعة المنفذ [{targetResource}]");

            case IOCTL_SERIAL_SET_LINE_CONTROL:
                if (payload.Length >= 3)
                {
                    byte stopBits = payload[0];
                    byte parity = payload[1];
                    byte dataBits = payload[2];
                    string parityStr = parity switch { 0 => "None", 1 => "Odd", 2 => "Even", 3 => "Mark", 4 => "Space", _ => parity.ToString() };
                    string stopStr = stopBits switch { 0 => "1 StopBit", 1 => "1.5 StopBits", 2 => "2 StopBits", _ => stopBits.ToString() };
                    return ("Port Config (LineControl)", $"ضبط خصائص الإشارة للمنفذ [{targetResource}]: DataBits={dataBits}, Parity={parityStr}, StopBits={stopStr}");
                }
                return ("Port Config (LineControl)", $"تهيئة خصائص خط الاتصال للمنفذ [{targetResource}]");

            case IOCTL_SERIAL_SET_TIMEOUTS:
                return ("Port Config (Timeouts)", $"ضبط مهلات الانتظار (Timeouts) للمنفذ [{targetResource}]");

            case IOCTL_SERIAL_SET_HANDFLOW:
                return ("Port Config (HandFlow)", $"تهيئة التحكم في تدفق البيانات (Hardware/Software Flow Control) على [{targetResource}]");

            case IOCTL_SERIAL_PURGE:
                return ("Port Control (Purge)", $"تفريغ ومسح ذاكرة التخزين المؤقت (Purge TX/RX Buffers) للمنفذ [{targetResource}]");

            case IOCTL_SERIAL_SET_DTR:
                return ("Modem Line Signal", $"تفعيل إشارة DTR (Data Terminal Ready) على المنفذ [{targetResource}]");

            case IOCTL_SERIAL_SET_RTS:
                return ("Modem Line Signal", $"تفعيل إشارة RTS (Request To Send) على المنفذ [{targetResource}]");

            case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
            case IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION:
                return ("USB Hardware Query", $"استعلام واصفات جهاز USB (Get USB Descriptor) للمورد [{targetResource}]");

            case IOCTL_WINUSB_GET_DESCRIPTOR:
                return ("WinUSB Driver Init", $"تهيئة واستعلام واجهة WinUSB المباشرة للمورد [{targetResource}]");

            default:
                return ("DeviceIoControl", $"استدعاء IOCTL: 0x{ioctlCode:X8} على المورد [{targetResource}]");
        }
    }
}
