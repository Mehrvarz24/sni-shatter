@echo off
chcp 65001 >nul
title sni-shatter - install service
pushd "%~dp0\.."

for /f "delims=" %%P in ('where python') do set "PYEXE=%%P"
if not defined PYEXE goto nopython

echo Installing sni-shatter as a Windows service (starts automatically at boot)...
sc stop snishatter >nul 2>nul
sc delete snishatter >nul 2>nul
sc create snishatter binPath= "\"%PYEXE%\" \"%~dp0service_launcher.py\"" start= auto DisplayName= "sni-shatter proxy"
sc description snishatter "Local DPI-desync proxy (HTTP+SOCKS5 on 127.0.0.1:40443)"
sc failure snishatter reset= 0 actions= restart/60000
net start snishatter
echo.
echo Done. Your browser proxy is 127.0.0.1:40443
pause
goto end

:nopython
echo Python not found. Install Python 3 first.
pause

:end
popd
