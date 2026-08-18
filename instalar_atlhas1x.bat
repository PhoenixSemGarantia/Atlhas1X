@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Instalador do Atlhas1x
color 1F

REM Este arquivo prepara o Atlhas1x no Windows.
REM Ele nao altera nenhuma configuracao de seguranca do Windows.

echo ============================================================
echo                 Instalador do Atlhas1x v1.2
echo ============================================================
echo.
echo Este assistente prepara o Atlhas1x para uso neste computador.
echo.
echo O que sera feito:
echo   1. Copiar ou atualizar os arquivos na Area de Trabalho.
echo   2. Verificar uma versao compativel do Python.
echo   3. Preparar a pasta onde os relatorios HTML serao salvos.
echo   4. Perguntar se voce deseja executar a primeira auditoria.
echo.
echo Importante: o Atlhas1x apenas le configuracoes. Ele nao altera
echo Firewall, Defender, UAC, usuarios, servicos ou politicas do Windows.
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
echo       Area de Trabalho: %DESKTOP_DIR%
echo       Pasta do aplicativo: %DESTINATION%

REM Se o arquivo ja estiver na Area de Trabalho, nao copie a pasta nela mesma.
if /I "%SOURCE%"=="%DESTINATION%" (
    set "INSTALL_RESULT=Atlhas1x ja esta instalado nesta pasta."
    echo       Esta e a instalacao local do Atlhas1x. Nenhuma copia adicional sera criada.
    goto :check_python
)

REM Quando existe uma copia local, compara as versoes e atualiza somente arquivos
REM diferentes. Relatorios e o Python portatil existente sao preservados.
if exist "%DESTINATION%\atlhas1x.py" (
    set "EXISTING_INSTALL=1"
    call :read_version "%DESTINATION%\atlhas1x.py" INSTALLED_VERSION
    call :read_version "%SOURCE%\atlhas1x.py" AVAILABLE_VERSION
    echo       Instalacao existente encontrada.
    echo       Versao instalada: !INSTALLED_VERSION!
    echo       Versao disponivel: !AVAILABLE_VERSION!
    if /I "!INSTALLED_VERSION!"=="!AVAILABLE_VERSION!" (
        echo       Verificando arquivos alterados nesta mesma versao...
    ) else (
        echo       Uma nova versao esta disponivel.
        call :confirm_update "!INSTALLED_VERSION!" "!AVAILABLE_VERSION!"
        if errorlevel 1 goto :update_cancelled
        echo       Atualizando arquivos do projeto. Seus relatorios serao preservados...
    )
) else (
    set "EXISTING_INSTALL=0"
    echo       Primeira instalacao. Copiando os arquivos necessarios...
)

REM Cria a pasta de destino caso ela ainda nao exista.
if not exist "%DESTINATION%" mkdir "%DESTINATION%"
if not exist "%DESTINATION%" goto :folder_error

REM ROBOCOPY copia todos os arquivos. As pastas abaixo nao fazem parte da instalacao.
robocopy "%SOURCE%" "%DESTINATION%" /E /XD .git __pycache__ reports /R:1 /W:1 >nul
set "COPY_RESULT=%ERRORLEVEL%"

REM Para o ROBOCOPY, codigos de 0 a 7 significam que a copia foi bem-sucedida.
if %COPY_RESULT% GEQ 8 goto :copy_error

if %COPY_RESULT% EQU 0 (
    echo       [OK] Os arquivos ja estavam atualizados.
    if "!EXISTING_INSTALL!"=="1" (set "INSTALL_RESULT=Atlhas1x ja estava atualizado.") else (set "INSTALL_RESULT=Instalacao concluida.")
) else (
    echo       [OK] Arquivos preparados com sucesso.
    if "!EXISTING_INSTALL!"=="1" (set "INSTALL_RESULT=Atualizacao concluida.") else (set "INSTALL_RESULT=Instalacao concluida.")
)
echo.

:check_python
REM A v1.2 depende destes modulos locais. Esta validacao evita abrir o scanner
REM com uma copia incompleta e apresentar um relatorio antigo/confuso ao usuario.
if not exist "%DESTINATION%\threat_analysis.py" goto :application_files_error
if not exist "%DESTINATION%\yara_engine.py" goto :application_files_error
if not exist "%DESTINATION%\rules\local\atlhas_test_only.yar" goto :application_files_error

echo [2/4] Verificando se o Python esta instalado...

REM Esta rotina valida que o Python pode executar, ignorando o atalho da Store.
call :find_python
if defined PYTHON goto :python_found

echo       Python 3 nao foi encontrado. Vou baixar uma copia portatil oficial.
echo       Ela ficara apenas dentro da pasta do Atlhas1x neste computador.
echo       Nenhum programa sera instalado para todos os usuarios.
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
call %PYTHON% --version
if errorlevel 1 goto :python_install_error
echo       [OK] Python compativel encontrado e pronto para uso.
call :prepare_yara
echo.

echo [3/4] Preparando a pasta de relatorios...
REM Esta pasta fica dentro da instalacao local do Atlhas1x.
if not exist "%DESTINATION%\reports" mkdir "%DESTINATION%\reports"
REM Move relatorios de versoes anteriores para a pasta correta, sem apagar dados.
for %%R in ("%DESTINATION%\scan_*.txt") do if exist "%%~fR" move /y "%%~fR" "%DESTINATION%\reports\" >nul
echo       [OK] Os relatorios HTML serao salvos em:
echo       %DESTINATION%\reports
echo       Esta pasta pertence ao Atlhas1x e pode ser aberta quando o scan terminar.
echo.

echo [4/4] Instalacao concluida. Escolhendo o proximo passo...
echo.
echo       [OK] Atlhas1x esta pronto para uso.
echo       Nenhuma configuracao de seguranca foi alterada.
echo.

REM Pergunta em uma janela grafica se a auditoria deve comecar agora.
REM [Environment]::NewLine cria quebras de linha corretas na janela do Windows.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = '!INSTALL_RESULT!' + $line + $line + 'O Atlhas1x esta pronto para uso.' + $line + $line + 'Deseja iniciar uma auditoria agora?' + $line + $line + 'A analise e somente leitura. Nenhuma configuracao do Windows sera alterada.'; $choice = [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Pronto para uso', 'YesNo', 'Question'); if ($choice -eq 'Yes') { exit 0 } else { exit 1 }"
if errorlevel 1 goto :user_cancelled

REM Entrega a execucao para a interface grafica e fecha o instalador.
REM Assim a tela de instalacao nao fica aberta durante a auditoria.
if not exist "%DESTINATION%\scripts\Abrir_Atlhas1x.vbs" goto :launcher_error
start "" wscript.exe //B "%DESTINATION%\scripts\Abrir_Atlhas1x.vbs"
exit /b 0

:user_cancelled
REM A instalacao ja foi preparada; esta janela confirma que a auditoria foi adiada.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = 'Atlhas1x instalado e pronto para uso.' + $line + $line + 'Voce pode executar a auditoria mais tarde por Executar_Atlhas1x.bat.'; [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Auditoria de Seguranca', 'OK', 'Information') | Out-Null"
REM Abre a pasta onde o aplicativo foi instalado.
start "" explorer "%DESTINATION%"
exit /b 0

:copy_error
echo.
echo [ERRO] Nao foi possivel copiar os arquivos para a Area de Trabalho.
echo Destino: %DESTINATION%
echo.
echo Feche arquivos abertos nessa pasta e confirme que este usuario pode gravar nela.
echo Depois, execute o instalador novamente.
pause
exit /b %COPY_RESULT%

:folder_error
echo.
echo [ERRO] Nao foi possivel criar a pasta local do Atlhas1x.
echo Caminho identificado: %DESTINATION%
echo Verifique se existe espaco em disco e se este usuario pode gravar na Area de Trabalho.
pause
exit /b 1

:launcher_error
echo.
echo [ERRO] A interface do Atlhas1x nao foi encontrada apos a instalacao.
echo Execute o instalador novamente a partir da pasta completa do projeto.
pause
exit /b 1

:application_files_error
echo.
echo [ERRO] A copia local do Atlhas1x esta incompleta.
echo Os modulos da analise de ameacas nao foram encontrados em:
echo %DESTINATION%
echo.
echo Execute este instalador novamente a partir da pasta compartilhada completa.
pause
exit /b 1

:update_cancelled
echo.
echo A atualizacao foi cancelada. A instalacao atual foi mantida sem alteracoes.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('A atualizacao foi cancelada.' + [Environment]::NewLine + [Environment]::NewLine + 'A versao atual do Atlhas1x foi mantida sem alteracoes.', 'Atlhas1x - Atualizacao cancelada', 'OK', 'Information') | Out-Null"
exit /b 0

:find_python
REM Tenta primeiro o iniciador oficial py.exe.
set "PYTHON="

REM Tambem aceita a copia portatil baixada pelo proprio instalador.
if exist "%DESTINATION%\runtime\python\python.exe" set "PYTHON="%DESTINATION%\runtime\python\python.exe""
if defined PYTHON exit /b 0

where py >nul 2>&1
if errorlevel 1 goto :try_python_command
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)" >nul 2>&1
if not errorlevel 1 set "PYTHON=py -3"
if defined PYTHON exit /b 0

:try_python_command
REM Tenta python.exe e confirma que ele executa de verdade.
where python >nul 2>&1
if not errorlevel 1 (
    REM O Atlhas1x precisa de Python 3.6 ou superior (Python 2 nao e compativel).
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)" >nul 2>&1
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
echo Verifique a conexao com a internet e tente novamente.
echo Se a rede usar proxy ou bloquear python.org, use um Python 3.6 ou superior
echo ja instalado e execute o instalador novamente.
pause
exit /b 1

:prepare_yara
REM YARA e opcional: tentamos preparar a biblioteca local, mas uma falha de
REM rede, pip ou compilacao nunca impede a instalacao nem a auditoria base.
REM O log fica em TEMP para nao misturar arquivos tecnicos com os relatorios.
set "YARA_LOG=%TEMP%\Atlhas1x-yara-install.log"
>"%YARA_LOG%" echo Atlhas1x YARA installation log
>>"%YARA_LOG%" echo Started: %DATE% %TIME%
echo       Verificando o suporte opcional YARA...
call %PYTHON% -c "import yara" >nul 2>&1
if not errorlevel 1 (
    echo       [OK] YARA ja esta disponivel e pronto para uso.
    exit /b 0
)
call %PYTHON% -m pip --version >nul 2>&1
if errorlevel 1 (
    echo       Preparando pip para tentar habilitar YARA automaticamente...
    call :prepare_pip
    call %PYTHON% -m pip --version >nul 2>&1
)
if errorlevel 1 (
    echo       [AVISO] Nao foi possivel preparar pip para este Python.
    echo       Detalhes tecnicos: %YARA_LOG%
    call :show_yara_log
    echo       A auditoria continuara com as heuristicas locais. O relatorio tambem mostrara
    echo       como instalar o YARA manualmente, se necessario.
    exit /b 0
)
echo       Instalando o suporte YARA local. Sera baixado apenas o pacote necessario...
call %PYTHON% -m pip install --disable-pip-version-check --upgrade --only-binary=:all: --retries 2 --timeout 30 -r "%DESTINATION%\requirements.txt" >>"%YARA_LOG%" 2>&1
if errorlevel 1 (
    echo       [AVISO] Nao foi possivel instalar yara-python agora.
    echo       Detalhes tecnicos: %YARA_LOG%
    call :show_yara_log
    echo       A auditoria continuara com as heuristicas locais e o relatorio mostrara o status do YARA.
) else (
    call %PYTHON% -c "import yara" >nul 2>&1
    if errorlevel 1 (
        echo       [AVISO] O instalador terminou, mas o modulo YARA nao pode ser aberto.
        echo       Detalhes tecnicos: %YARA_LOG%
        call :show_yara_log
    ) else (
        echo       [OK] Suporte YARA preparado e pronto para uso.
    )
)
exit /b 0

:prepare_pip
REM O Python portatil do Atlhas1x pode vir sem pip. Quando ele for usado,
REM habilitamos somente o diretorio local da propria aplicacao e baixamos o
REM bootstrap oficial do pip. Isso nao altera configuracoes de seguranca do Windows.
set "LOCAL_RUNTIME=%DESTINATION%\runtime\python"
if not exist "%LOCAL_RUNTIME%\python.exe" exit /b 0
REM O Python embutido usa um arquivo ._pth que pode desativar o modulo site.
REM Habilitamos somente esse runtime local para que o pip possa ser instalado nele.
for %%F in ("%LOCAL_RUNTIME%\python*._pth") do (
    REM O \r no fim da linha precisa ser aceito: arquivos ._pth do Windows usam CRLF.
    if exist "%%~fF" powershell -NoProfile -Command "$p='%%~fF'; $t=Get-Content -LiteralPath $p -Raw; $t=$t -replace '(?m)^\s*#\s*import\s+site\s*\r?$','import site'; Set-Content -LiteralPath $p -Value $t -NoNewline -Encoding ASCII" >>"%YARA_LOG%" 2>&1
)
REM Alguns pacotes oficiais incluem ensurepip. Tentamos antes do bootstrap remoto.
call %PYTHON% -m ensurepip --upgrade >>"%YARA_LOG%" 2>&1
call %PYTHON% -m pip --version >nul 2>&1
if not errorlevel 1 exit /b 0
set "GET_PIP=%TEMP%\atlhas1x-get-pip.py"
powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%GET_PIP%'" >>"%YARA_LOG%" 2>&1
if not exist "%GET_PIP%" exit /b 0
call %PYTHON% "%GET_PIP%" --disable-pip-version-check --no-warn-script-location >>"%YARA_LOG%" 2>&1
exit /b 0

:show_yara_log
REM Mostra apenas as ultimas linhas; o arquivo completo permanece disponivel se precisar diagnosticar a rede.
if exist "%YARA_LOG%" powershell -NoProfile -Command "Get-Content -LiteralPath '%YARA_LOG%' -Tail 10" 2>nul
exit /b 0

:read_version
REM Le a linha VERSION do Python. Se ela nao existir, identifica como desconhecida.
set "%~2=UNKNOWN"
for /f "tokens=3" %%V in ('findstr /b /c:"VERSION =" "%~1" 2^>nul') do set "%~2=%%~V"
exit /b 0

:confirm_update
REM Pergunta antes de atualizar. Apenas arquivos do projeto sao copiados;
REM reports e runtime existentes nao fazem parte da atualizacao.
powershell -NoProfile -Command "Add-Type -AssemblyName PresentationFramework; $line = [Environment]::NewLine; $message = 'Uma nova versao do Atlhas1x foi encontrada.' + $line + $line + 'Versao instalada: %~1' + $line + 'Versao disponivel: %~2' + $line + $line + 'Deseja atualizar agora?' + $line + $line + 'A atualizacao preserva seus relatorios e o Python portatil.'; $choice = [System.Windows.MessageBox]::Show($message, 'Atlhas1x - Atualizacao disponivel', 'YesNo', 'Question'); if ($choice -eq 'Yes') { exit 0 } else { exit 1 }"
exit /b %ERRORLEVEL%
