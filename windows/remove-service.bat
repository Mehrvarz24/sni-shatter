@echo off
echo Stopping and removing the sni-shatter service...
sc stop snishatter >nul 2>nul
sc delete snishatter >nul 2>nul
echo Removed.
pause
