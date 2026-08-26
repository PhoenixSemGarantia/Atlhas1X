@echo off
setlocal EnableExtensions

REM Lancador diario: entrega a interface grafica ao VBS e fecha o CMD logo em seguida.
set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"
set "GUI_LAUNCHER=%APP_DIR%\scripts\Abrir_Atlhas1x.vbs"

if not exist "%GUI_LAUNCHER%" (
    powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Arquivos da interface nao foram encontrados.' + [Environment]::NewLine + [Environment]::NewLine + 'Execute instalar_atlhas1x.bat novamente para atualizar o Atlhas1x.', 'Atlhas1x - Arquivos ausentes', 'OK', 'Error') | Out-Null"
    exit /b 1
)

REM wscript executa a interface sem deixar um terminal aberto em segundo plano.
start "" wscript.exe //B "%GUI_LAUNCHER%"
exit /b 0
