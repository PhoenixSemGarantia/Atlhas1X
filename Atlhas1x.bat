@echo off
setlocal EnableExtensions

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found.
    echo.
    echo Atlhas1x requires Python 3.x.
    echo See README.md for installation instructions.
    pause
    exit /b 1
)

set "APP_DIR=%~dp0"
set "APP_DIR=%APP_DIR:~0,-1%"

REM Verify Integrity
if exist "%APP_DIR%\repair.py" (
    python "%APP_DIR%\repair.py" --check-integrity
    if errorlevel 1 (
        exit /b 1
    )
)

REM Run Updater
python "%APP_DIR%\updater.py"

REM Run Atlhas1x
python "%APP_DIR%\atlhas1x.py" %*

exit /b %ERRORLEVEL%
