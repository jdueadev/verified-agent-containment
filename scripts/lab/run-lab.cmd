@echo off
rem Double-click to run the containment lab: a throwaway WSL2 distro, a local
rem model on llama.cpp, both test suites and the red team. See README.md here.
rem Options are passed through, for example:  run-lab.cmd -Keep
rem Everything PowerShell prints, including a failure to start, goes to launch.log.
echo Containment lab running; progress: "%~dp0logs\status.txt", output: "%~dp0launch.log"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lab.ps1" %* > "%~dp0launch.log" 2>&1
set LABEXIT=%ERRORLEVEL%
type "%~dp0launch.log"
echo.
echo Finished with exit code %LABEXIT%. Logs and results are in "%~dp0logs" and "%~dp0results".
pause
exit /b %LABEXIT%
