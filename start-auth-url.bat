@echo off
setlocal disabledelayedexpansion

REM Stub for Windows to launch the user's default browser with the encoded URL.
REM Refer to open_browser_url comment block in bearer-new.pl.

set /p URL=<./auth-url.txt
start "" "%URL%"
