@echo off
chcp 65001 >nul
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
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if defined PY goto havepy
if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if defined PY goto havepy
if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe"
if defined PY goto havepy
if exist "C:\Python311\python.exe" set "PY=C:\Python311\python.exe"
if defined PY goto havepy
if exist "C:\Python310\python.exe" set "PY=C:\Python310\python.exe"
if defined PY goto havepy
goto nopython

:havepy

sc stop snishatter >nul 2>nul
sc delete snishatter >nul 2>nul
sc create snishatter binPath= "\"%PY%\" \"%~dp0service_launcher.py\"" start= auto DisplayName= "sni-shatter proxy"
sc description snishatter "Local DPI-desync proxy (HTTP+SOCKS5 on 127.0.0.1:40443)"
sc failure snishatter reset= 0 actions= restart/60000
net start snishatter
echo.
echo Done. Browser proxy: 127.0.0.1:40443
pause
goto end

:nopython
echo Python 3 was not found. Run install-python.bat first.
pause

:end
popd
