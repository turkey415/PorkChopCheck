@echo off
rem Starts PortCheck without a console window. The app asks for admin itself (one UAC prompt).
cd /d "%~dp0"
where pyw >nul 2>&1 && (start "" pyw "%~dp0portcheck.py" %* & exit /b)
where pythonw >nul 2>&1 && (start "" pythonw "%~dp0portcheck.py" %* & exit /b)
start "" py "%~dp0portcheck.py" %*
