Option Explicit

' Inicia a interface do Atlhas1x sem exibir uma janela de CMD.
Dim shell, files, scriptsDir, appDir, command
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
scriptsDir = files.GetParentFolderName(WScript.ScriptFullName)
appDir = files.GetParentFolderName(scriptsDir)
command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " & Quote(scriptsDir & "\Executar_Com_Progresso.ps1") & " -AppDir " & Quote(appDir)
shell.Run command, 0, False

Function Quote(value)
    Quote = Chr(34) & value & Chr(34)
End Function
