@echo off
chcp 65001 >nul
title sni-shatter
pushd "%~dp0\.."

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto havepy
where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto havepy
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined PY goto havepy
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto havepy
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if defined PY goto havepy
if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if defined PY goto havepy
if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe"
if defined PY goto havepy
goto nopython

:havepy
echo ============================================
echo   sni-shatter - DPI desync proxy
echo ============================================
echo.
echo   1. Browser proxy mode  (HTTP + SOCKS5 on 127.0.0.1:40443)
echo   2. Relay mode          (v2rayN: config address = 127.0.0.1:40443)
echo   3. Check strategies    (which technique works on your ISP)
echo.
set /p MODE=Choose 1/2/3 (Enter = 1): 
if "%MODE%"=="2" goto relay
if "%MODE%"=="3" goto check
echo.
echo Detected python: %PY%
echo Listening on 127.0.0.1:40443 - set browser proxy there. Ctrl+C to stop.
echo.
%PY% -m shatter %*
goto end

:relay
echo.
echo Detected python: %PY%
echo Relay target is in config.relay.json. v2rayN address = 127.0.0.1:40443
echo.
%PY% -m shatter -c config.relay.json %*
goto end

:check
echo.
%PY% -m shatter --check cloudflare.com
echo.
pause
goto end

:nopython
echo Python 3 was not found. Double-click install-python.bat first.
pause

:end
popd
