@echo off
rem Double-click to run the containment lab: a throwaway WSL2 distro, a local
rem model on llama.cpp, both test suites and the red team. See README.md here.
rem Options are passed through, for example:  run-lab.cmd -Keep
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lab.ps1" %*
echo.
echo Finished with exit code %ERRORLEVEL%. Logs and results are in "%~dp0logs" and "%~dp0results".
pause
