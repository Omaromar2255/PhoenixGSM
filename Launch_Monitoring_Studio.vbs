Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strBuildDir = "C:\Users\pc5\Documents\GitHub\PhoenixGSMtools\Debug\net8.0-windows"
strExe = strBuildDir & "\DevConfigStudio.exe"
If Not fso.FileExists(strExe) Then
    strExe = strBuildDir & "\MonitoringStudio.exe"
End If
WshShell.Run """" & strExe & """", 1, False
