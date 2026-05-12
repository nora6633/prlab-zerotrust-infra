@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0firewall-block.ps1"
exit /b %ERRORLEVEL%
