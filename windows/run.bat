@ECHO OFF
CHCP 65001 >NUL
TITLE sni-shatter
PUSHD "%~dp0"

WHERE python >NUL 2>NUL
IF ERRORLEVEL 1 (
  ECHO Python 3 is required. Install from https://www.python.org/downloads/
  ECHO Be sure to check "Add python.exe to PATH" during install.
  PAUSE
  POPD
  EXIT /B 1
)

ECHO ============================================
ECHO   sni-shatter — DPI desync proxy
ECHO   Listens on 127.0.0.1:40443  (HTTP + SOCKS5)
ECHO   No admin rights needed.
ECHO ============================================
ECHO.
ECHO Browser proxy settings  -^>  127.0.0.1 : 40443
ECHO Press Ctrl+C to stop.
ECHO.

python -m shatter %*
POPD
PAUSE
