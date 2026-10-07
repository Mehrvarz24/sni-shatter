@echo off
chcp 65001 >nul
title sni-shatter - strategy check
pushd "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 goto nopython

echo Testing which desync strategies work on your connection...
echo (takes about 10 seconds)
echo.
python -m shatter --check cloudflare.com
echo.
echo Write the working strategy name into config.json  -^>  "strategy"
pause
goto end

:nopython
echo Python 3 is required. Install from https://www.python.org/downloads/
pause

:end
popd
