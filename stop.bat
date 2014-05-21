cd %~dp0
set /p pid=<RUNNING_PID
taskkill /PID %pid% /F
del RUNNING_PID