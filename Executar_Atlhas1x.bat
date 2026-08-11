@echo off
setlocal EnableExtensions
title Atlhas1x - Auditoria de Seguranca

REM Este e o atalho de uso diario do Atlhas1x no Windows.
REM Ele usa o Python portatil preparado pelo instalador e nao altera o Windows.
set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"
set "PYTHON=%APP_DIR%\runtime\python\python.exe"

REM Se o Python portatil ainda nao existir, orienta a usar o instalador primeiro.
if not exist "%PYTHON%" goto :not_installed

REM Todos os relatorios ficam na pasta reports dentro deste mesmo projeto.
if not exist "%APP_DIR%\reports" mkdir "%APP_DIR%\reports"

REM Move relatorios de versoes antigas para a pasta correta, sem apagar dados.
for %%R in ("%APP_DIR%\scan_*.txt") do if exist "%%~fR" move /y "%%~fR" "%APP_DIR%\reports\" >nul

REM Abre a janela de escolha e recebe o modo selecionado pelo usuario.
set "MODE="
for /f "usebackq delims=" %%M in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%APP_DIR%\Selecionar_Modo_Atlhas1x.ps1"`) do set "MODE=%%M"
if not defined MODE exit /b 0

REM Executa a auditoria a partir da pasta do aplicativo.
pushd "%APP_DIR%"
"%PYTHON%" atlhas1x.py --mode %MODE%
set "SCAN_RESULT=%ERRORLEVEL%"
popd

if not "%SCAN_RESULT%"=="0" goto :scan_error

REM Mostra a conclusao e abre diretamente a pasta que contem o relatorio.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = 'Auditoria concluida com sucesso.' + $line + $line + 'O relatorio foi salvo na pasta reports.'; [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Auditoria de Seguranca', 'OK', 'Information') | Out-Null"
start "" explorer "%APP_DIR%\reports"
exit /b 0

:not_installed
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('O Atlhas1x ainda nao foi preparado neste computador.' + [Environment]::NewLine + [Environment]::NewLine + 'Abra instalar_atlhas1x.bat primeiro.', 'Atlhas1x - Auditoria de Seguranca', 'OK', 'Warning') | Out-Null"
exit /b 1

:scan_error
echo.
echo [ERRO] A auditoria terminou com um erro. Veja as mensagens acima.
pause
exit /b %SCAN_RESULT%
