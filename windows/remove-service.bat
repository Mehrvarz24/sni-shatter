@ECHO OFF
ECHO Stopping and removing sni-shatter service...
sc stop snishatter >NUL 2>&1
sc delete snishatter >NUL 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq sni-shatter*" >NUL 2>&1
ECHO Removed.
PAUSE
