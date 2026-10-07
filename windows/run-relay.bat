@echo off
chcp 65001 >nul
title sni-shatter (relay mode)
pushd "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 goto nopython

echo ============================================
echo   sni-shatter - RELAY MODE
echo   Forwards everything to the CDN edge IP in config.relay.json
echo   Point your v2rayN config address at 127.0.0.1 : 40443
echo ============================================
echo.

python -m shatter -c config.relay.json %*
goto end

:nopython
echo Python 3 is required. Install from https://www.python.org/downloads/
echo Tick "Add python.exe to PATH" during the install, then run this file again.
pause

:end
popd
pause
