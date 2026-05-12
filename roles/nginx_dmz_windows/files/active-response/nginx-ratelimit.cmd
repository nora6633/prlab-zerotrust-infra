@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nginx-ratelimit.ps1"
exit /b %ERRORLEVEL%
