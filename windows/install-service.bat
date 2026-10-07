@ECHO OFF
CHCP 65001 >NUL
PUSHD "%~dp0.."

ECHO Installing sni-shatter as a Windows service (auto-start at boot)...
ECHO.

sc stop snishatter >NUL 2>&1
sc delete snishatter >NUL 2>&1

FOR /F "delims=" %%P IN ('where python') DO SET "PYEXE=%%P"
IF NOT DEFINED PYEXE (
  ECHO Python not found. Install Python 3 first.
  PAUSE & POPD & EXIT /B 1
)

sc create snishatter binPath= "\"%PYEXE%\" \"%~dp0service_launcher.py\"" start= auto DisplayName= "sni-shatter proxy"
sc description snishatter "Local DPI-desync proxy (HTTP+SOCKS5 on 127.0.0.1:40443)"
sc failure snishatter reset= 0 actions= restart/60000
net start snishatter

ECHO.
ECHO Done. Point your browser proxy at 127.0.0.1:40443
ECHO Remove later with remove-service.bat
PAUSE
POPD
