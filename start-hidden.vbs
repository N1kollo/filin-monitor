' Launches the monitor with no console window (used by the scheduled task).
Dim dir, shell
dir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = dir
shell.Run "pythonw.exe " & Chr(34) & dir & "\monitor.py" & Chr(34), 0, False
