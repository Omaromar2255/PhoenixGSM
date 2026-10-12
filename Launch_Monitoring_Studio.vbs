Set WshShell = CreateObject("WScript.Shell")
strCurrentDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
Set fso = CreateObject("Scripting.FileSystemObject")
strExe = strCurrentDir & "\tools\MonitoringToolkit\MonitoringStudio\bin\Debug\net8.0-windows\DevConfigStudio.exe"
If Not fso.FileExists(strExe) Then
    strExe = strCurrentDir & "\tools\MonitoringToolkit\MonitoringStudio\bin\Debug\net8.0-windows\MonitoringStudio.exe"
End If
WshShell.Run """" & strExe & """", 1, False
