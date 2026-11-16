@echo off
setlocal
title Kyty PS5 Boot
py -3 "%~dp0scripts\start_kyty_ps5.py" %*
set "kyty_exit_code=%errorlevel%"
echo.
if "%kyty_exit_code%"=="0" (
    echo Kyty finished normally.
) else if "%kyty_exit_code%"=="130" (
    echo Kyty stopped by user.
) else (
    powershell -NoProfile -Command "Write-Host 'Kyty finished with exit code %kyty_exit_code%.' -ForegroundColor Red"
)
pause
exit /b %kyty_exit_code%
