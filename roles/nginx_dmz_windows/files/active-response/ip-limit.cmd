@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ip-limit.ps1"
exit /b %ERRORLEVEL%
