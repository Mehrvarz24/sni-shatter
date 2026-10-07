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
echo ============================================
echo   sni-shatter - DPI desync proxy
echo   Listens on 127.0.0.1:40443   (HTTP + SOCKS5)
echo   No admin rights needed.
echo ============================================
echo.
echo Detected python: %PY%
echo.
echo.
echo Set your browser/app proxy to  127.0.0.1 : 40443
echo Press Ctrl+C to stop.
echo.
%PY% -m shatter %*
goto end


:nopython
echo ============================================
echo   Python 3 was not found on this PC.
echo ============================================
echo.
echo Option 1: double-click  install-python.bat  (installs it for you)
echo Option 2: get it from https://www.python.org/downloads/
echo           and TICK the box "Add python.exe to PATH" during setup.
echo.
pause

:end
popd
pause
