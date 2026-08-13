@echo off
setlocal EnableExtensions
title Instalador do Atlhas1x

REM Este arquivo prepara o Atlhas1x no Windows.
REM Ele nao altera nenhuma configuracao de seguranca do Windows.

echo ============================================================
echo                 Instalador do Atlhas1x v0.1
echo ============================================================
echo.
echo Este assistente vai copiar o Atlhas1x para a Area de Trabalho
echo deste computador Windows, verificar o Python e iniciar a auditoria.
echo Nenhuma configuracao de seguranca sera modificada.
echo.

REM %~dp0 e a pasta onde este arquivo .bat foi aberto.
set "SOURCE=%~dp0"
REM Remove a barra final para que o ROBOCOPY leia corretamente o caminho entre aspas.
set "SOURCE=%SOURCE:~0,-1%"

REM Pergunta ao Windows qual e a Area de Trabalho real deste usuario.
REM Isso funciona mesmo quando a Area de Trabalho foi movida para o OneDrive.
set "DESKTOP_DIR=%USERPROFILE%\Desktop"
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')" 2^>nul`) do set "DESKTOP_DIR=%%D"

REM A auditoria sera executada em uma pasta local e gravavel.
set "DESTINATION=%DESKTOP_DIR%\Atlhas1x"

echo [1/4] Preparando a pasta local do Atlhas1x...
echo       Area de Trabalho detectada: %DESKTOP_DIR%

REM Identifica uma instalacao ja existente antes de procurar atualizacoes.
if exist "%DESTINATION%\atlhas1x.py" (
    echo       Atlhas1x ja esta instalado. Verificando atualizacoes...
) else (
    echo       Primeira instalacao detectada. Copiando os arquivos...
)

REM Se o arquivo ja estiver na Area de Trabalho, nao copie a pasta nela mesma.
if /I "%SOURCE:~0,-1%"=="%DESTINATION%" goto :check_python

REM Cria a pasta de destino caso ela ainda nao exista.
if not exist "%DESTINATION%" mkdir "%DESTINATION%"
if not exist "%DESTINATION%" goto :folder_error

REM ROBOCOPY copia todos os arquivos. As pastas abaixo nao fazem parte da instalacao.
robocopy "%SOURCE%" "%DESTINATION%" /E /XD .git __pycache__ reports /R:1 /W:1
set "COPY_RESULT=%ERRORLEVEL%"

REM Para o ROBOCOPY, codigos de 0 a 7 significam que a copia foi bem-sucedida.
if %COPY_RESULT% GEQ 8 goto :copy_error

echo       Arquivos copiados para: %DESTINATION%
echo.

:check_python
echo [2/4] Verificando se o Python esta instalado...

REM Esta rotina valida que o Python pode executar, ignorando o atalho da Store.
call :find_python
if defined PYTHON goto :python_found

echo       Python 3 nao foi encontrado. Vou baixar uma copia portatil oficial.
echo       Ela ficara apenas dentro da pasta do Atlhas1x neste computador.
echo.

REM Baixa o pacote portatil oficial e nao instala programas no Windows.
set "RUNTIME_DIR=%DESTINATION%\runtime\python"
set "PYTHON_VERSION=3.13.15"
REM Windows 7 uses the last compatible portable Python release.
ver | find "6.1" >nul && set "PYTHON_VERSION=3.8.10"
set "PYTHON_ZIP=%TEMP%\atlhas1x-python-%PYTHON_VERSION%-embed-amd64.zip"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"
echo       Baixando Python portatil oficial. Isso pode levar alguns minutos...

REM Baixa o arquivo e interrompe com uma mensagem clara se a internet falhar.
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_ZIP%'"
if errorlevel 1 goto :python_install_error

REM Extrai o Python apenas dentro da pasta local do Atlhas1x.
if not exist "%RUNTIME_DIR%" mkdir "%RUNTIME_DIR%"
powershell -NoProfile -Command "Expand-Archive -Path '%PYTHON_ZIP%' -DestinationPath '%RUNTIME_DIR%' -Force"
if errorlevel 1 goto :python_install_error
if not exist "%RUNTIME_DIR%\python.exe" goto :python_install_error
set "PYTHON="%RUNTIME_DIR%\python.exe""
echo       Python portatil preparado com sucesso.
goto :python_found

:python_found
%PYTHON% --version
echo       Python encontrado.
echo.

echo [3/4] Preparando a pasta de relatorios...
REM Esta pasta fica dentro do Atlhas1x local, nunca na pasta compartilhada.
if not exist "%DESTINATION%\reports" mkdir "%DESTINATION%\reports"
REM Move relatorios de versoes anteriores para a pasta correta, sem apagar dados.
for %%R in ("%DESTINATION%\scan_*.txt") do if exist "%%~fR" move /y "%%~fR" "%DESTINATION%\reports\" >nul
echo       Os arquivos scan_AAAA-MM-DD_HHMM.txt ficarao em: %DESTINATION%\reports

echo [4/4] Iniciando a auditoria de seguranca...
echo.
echo O Atlhas1x apenas le configuracoes e gera um relatorio.
echo Nenhuma configuracao sera alterada.
echo.

REM Pergunta em uma janela grafica se a auditoria deve comecar agora.
REM [Environment]::NewLine cria quebras de linha corretas na janela do Windows.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = 'Atlhas1x esta pronto para uso.' + $line + $line + 'Deseja iniciar a auditoria de seguranca agora?' + $line + $line + 'A analise e somente leitura. Nenhuma configuracao do Windows sera alterada.'; $choice = [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Auditoria de Seguranca', 'YesNo', 'Question'); if ($choice -eq 'Yes') { exit 0 } else { exit 1 }"
if errorlevel 1 goto :user_cancelled

REM Chama o lancador, que permite escolher o nivel do relatorio e abre reports.
call "%DESTINATION%\Executar_Atlhas1x.bat"
exit /b %ERRORLEVEL%

:user_cancelled
REM A instalacao ja foi preparada; esta janela confirma que a auditoria foi adiada.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = 'Atlhas1x instalado e pronto para uso.' + $line + $line + 'Voce pode executar a auditoria mais tarde pelo instalador.'; [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Auditoria de Seguranca', 'OK', 'Information') | Out-Null"
REM Abre a pasta onde o aplicativo foi instalado.
start "" explorer "%DESTINATION%"
exit /b 0

:copy_error
echo.
echo [ERRO] Nao foi possivel copiar os arquivos para a Area de Trabalho.
echo Verifique se voce tem permissao para gravar em: %DESTINATION%
pause
exit /b %COPY_RESULT%

:folder_error
echo.
echo [ERRO] Nao foi possivel criar a pasta local do Atlhas1x.
echo Caminho identificado: %DESTINATION%
echo Tente executar este arquivo com o usuario atual do Windows.
pause
exit /b 1

:find_python
REM Tenta primeiro o iniciador oficial py.exe.
set "PYTHON="

REM Tambem aceita a copia portatil baixada pelo proprio instalador.
if exist "%DESTINATION%\runtime\python\python.exe" set "PYTHON="%DESTINATION%\runtime\python\python.exe""
if defined PYTHON exit /b 0

where py >nul 2>&1
if errorlevel 1 goto :try_python_command
py -3 --version >nul 2>&1
if not errorlevel 1 set "PYTHON=py -3"
if defined PYTHON exit /b 0

:try_python_command
REM Tenta python.exe e confirma que ele executa de verdade.
where python >nul 2>&1
if not errorlevel 1 (
    python --version >nul 2>&1
    if not errorlevel 1 set "PYTHON=python"
)
if defined PYTHON exit /b 0

REM A instalacao pode nao atualizar o PATH desta janela. Procura os locais
REM padrao do instalador oficial, tanto para todos os usuarios quanto localmente.
for /d %%P in ("%ProgramFiles%\Python3*") do if exist "%%~fP\python.exe" set "PYTHON="%%~fP\python.exe""
if defined PYTHON exit /b 0
for /d %%P in ("%LocalAppData%\Programs\Python\Python3*") do if exist "%%~fP\python.exe" set "PYTHON="%%~fP\python.exe""
exit /b 0

:python_install_error
echo.
echo [ERRO] Nao foi possivel preparar o Python portatil.
echo Verifique a conexao com a internet e execute este arquivo novamente.
pause
exit /b 1
