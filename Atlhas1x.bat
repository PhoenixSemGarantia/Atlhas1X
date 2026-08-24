@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"

REM ======= VERIFICA SE A PASTA É SOMENTE LEITURA =======
set "TEST_FILE=%APP_DIR%\.writable_test"
echo test > "%TEST_FILE%" 2>nul
if errorlevel 1 (
    echo [AVISO] O Atlhas1x esta sendo executado de uma midia somente leitura ^(ex: CD, Rede ou Pasta Compartilhada^).
    echo Para funcionar corretamente e baixar dependencias, ele sera copiado para o disco C:.
    echo.
    set "NEW_APP_DIR=%USERPROFILE%\Atlhas1x"
    
    echo Copiando arquivos para !NEW_APP_DIR!...
    mkdir "!NEW_APP_DIR!" 2>nul
    xcopy /E /I /H /Y "%APP_DIR%\*" "!NEW_APP_DIR!\" >nul
    
    echo Criando atalho na Area de Trabalho...
    set "SHORTCUT_PATH=%USERPROFILE%\Desktop\Atlhas1x.lnk"
    set "VBS_SCRIPT=%TEMP%\criar_atalho.vbs"
    echo Set oWS = WScript.CreateObject^("WScript.Shell"^) > "!VBS_SCRIPT!"
    echo sLinkFile = "!SHORTCUT_PATH!" >> "!VBS_SCRIPT!"
    echo Set oLink = oWS.CreateShortcut^(sLinkFile^) >> "!VBS_SCRIPT!"
    echo oLink.TargetPath = "!NEW_APP_DIR!\Atlhas1x.bat" >> "!VBS_SCRIPT!"
    echo oLink.WorkingDirectory = "!NEW_APP_DIR!" >> "!VBS_SCRIPT!"
    echo oLink.IconLocation = "%SystemRoot%\system32\SHELL32.dll, 24" >> "!VBS_SCRIPT!"
    echo oLink.Save >> "!VBS_SCRIPT!"
    cscript //nologo "!VBS_SCRIPT!"
    del "!VBS_SCRIPT!"
    
    echo.
    echo Copia concluida! Iniciando a partir do disco local...
    start "" "!NEW_APP_DIR!\Atlhas1x.bat"
    exit /b 0
) else (
    del "%TEST_FILE%" 2>nul
)
REM ======================================================

set "PYTHON="

REM Check locally embedded first
if exist "%APP_DIR%\runtime\python\python.exe" (
    set "PYTHON="%APP_DIR%\runtime\python\python.exe""
    goto :python_ready
)

REM Check globally
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON=python"
    goto :python_ready
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON=py -3"
    goto :python_ready
)

echo Python 3.x nao foi encontrado neste sistema.
echo O Atlhas1x precisa do Python para executar as auditorias.
echo.
set /p "INSTALL_PY=Deseja baixar o Python portatil e configurar o Atlhas1x automaticamente? [S/N]: "
if /i not "%INSTALL_PY%"=="S" (
    echo.
    echo Instalacao cancelada. Leia o README.md para instrucoes.
    pause
    exit /b 1
)

echo.
echo Baixando Python portatil oficial. Isso pode levar alguns minutos...
set "RUNTIME_DIR=%APP_DIR%\runtime\python"
set "PYTHON_VERSION=3.13.15"
REM Windows 7 compatibility fallback
ver | find "6.1" >nul && set "PYTHON_VERSION=3.8.10"
set "PYTHON_ZIP=%TEMP%\atlhas1x-python-%PYTHON_VERSION%-embed-amd64.zip"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"

powershell -NoProfile -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_ZIP%'"
if errorlevel 1 (
    echo Erro ao baixar o Python. Verifique sua conexao.
    pause
    exit /b 1
)

echo Extraindo arquivos...
if not exist "%RUNTIME_DIR%" mkdir "%RUNTIME_DIR%"
powershell -NoProfile -Command "Expand-Archive -Path '%PYTHON_ZIP%' -DestinationPath '%RUNTIME_DIR%' -Force"

if not exist "%RUNTIME_DIR%\python.exe" (
    echo Erro ao extrair o Python portatil.
    pause
    exit /b 1
)

set "PYTHON="%RUNTIME_DIR%\python.exe""
echo Python preparado com sucesso!
echo.
echo Preparando pacote YARA (opcional para analises avancadas)...

REM Ensure pip works in the embedded runtime
for %%F in ("%RUNTIME_DIR%\python*._pth") do (
    if exist "%%~fF" powershell -NoProfile -Command "$p='%%~fF'; $t=Get-Content -LiteralPath $p -Raw; $t=$t -replace '(?m)^\s*#\s*import\s+site\s*\r?$','import site'; Set-Content -LiteralPath $p -Value $t -NoNewline -Encoding ASCII"
)

set "GET_PIP=%TEMP%\atlhas1x-get-pip.py"
powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%GET_PIP%'" >nul 2>&1
if exist "%GET_PIP%" (
    call %PYTHON% "%GET_PIP%" --disable-pip-version-check --no-warn-script-location >nul 2>&1
    call %PYTHON% -m pip install --disable-pip-version-check --only-binary=:all: -r "%APP_DIR%\requirements.txt" >nul 2>&1
    echo Dependencias do YARA instaladas com sucesso!
) else (
    echo Aviso: Falha ao configurar YARA. A auditoria continuara com heuristicas basicas.
)

echo.
echo Tudo pronto! Iniciando o Atlhas1x...
echo.

:python_ready

REM Verify Integrity
if exist "%APP_DIR%\repair.py" (
    call %PYTHON% "%APP_DIR%\repair.py" --check-integrity
    if errorlevel 1 (
        exit /b 1
    )
)

REM Run Updater
call %PYTHON% "%APP_DIR%\updater.py"

REM Run Atlhas1x
call %PYTHON% "%APP_DIR%\atlhas1x.py" %*

exit /b %ERRORLEVEL%
