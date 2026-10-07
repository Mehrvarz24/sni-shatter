@echo off
chcp 65001 >nul
title sni-shatter - install python
echo This helper installs Python 3 automatically (needs internet).
echo.
where winget >nul 2>nul
if errorlevel 1 goto manual
winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
echo.
echo Python installed. Now run run.bat again.
pause
goto end

:manual
echo winget not found. Please download and install Python from:
echo   https://www.python.org/downloads/
echo IMPORTANT: tick "Add python.exe to PATH" on the first screen.
echo After installing, run run.bat again.
pause

:end
