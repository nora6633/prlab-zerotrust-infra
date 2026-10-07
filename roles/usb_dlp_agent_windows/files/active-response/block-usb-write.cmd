@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0block-usb-write.ps1"
exit /b %ERRORLEVEL%
