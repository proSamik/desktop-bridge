@echo off
rem Scheduled-task entry: run desktop-bridge from its install directory so .env is picked up.
cd /d "%~dp0\..\.."
:loop
node dist\server.js
rem restart on crash after 5 seconds
timeout /t 5 /nobreak >nul
goto loop
