@echo off
REM Post-installation script for Infiniservice
REM Run this manually after Windows installation completes

echo ===============================================
echo    INFINISERVICE POST-INSTALLATION SCRIPT
echo ===============================================
echo.

REM Create log directory
echo Creating log directory...
mkdir C:\Temp 2>nul

REM Start logging
echo [%DATE% %TIME%] Starting Infiniservice installation > C:\Temp\infiniservice_install.log

REM List all drives
echo.
echo Searching for installation media...
echo Available drives: >> C:\Temp\infiniservice_install.log
wmic logicaldisk get name,description >> C:\Temp\infiniservice_install.log

REM Check common CD-ROM drive letters
echo.
echo Checking for installer on CD-ROM drives...

if exist D:\infiniservice-windows\install-windows.ps1 (
    echo Found installer on D: drive
    echo [%DATE% %TIME%] Found installer on D: >> C:\Temp\infiniservice_install.log
    cd /d D:\infiniservice-windows
    echo Running installer...
    powershell -ExecutionPolicy Bypass -File install-windows.ps1
    goto :check_service
)

if exist E:\infiniservice-windows\install-windows.ps1 (
    echo Found installer on E: drive
    echo [%DATE% %TIME%] Found installer on E: >> C:\Temp\infiniservice_install.log
    cd /d E:\infiniservice-windows
    echo Running installer...
    powershell -ExecutionPolicy Bypass -File install-windows.ps1
    goto :check_service
)

if exist F:\infiniservice-windows\install-windows.ps1 (
    echo Found installer on F: drive
    echo [%DATE% %TIME%] Found installer on F: >> C:\Temp\infiniservice_install.log
    cd /d F:\infiniservice-windows
    echo Running installer...
    powershell -ExecutionPolicy Bypass -File install-windows.ps1
    goto :check_service
)

REM Alternative paths
if exist D:\autorun-windows.ps1 (
    echo Found autorun installer on D: drive
    echo [%DATE% %TIME%] Found autorun on D: >> C:\Temp\infiniservice_install.log
    cd /d D:\
    echo Running autorun installer...
    powershell -ExecutionPolicy Bypass -File autorun-windows.ps1
    goto :check_service
)

echo.
echo ERROR: Could not find Infiniservice installer on any CD-ROM drive
echo [%DATE% %TIME%] ERROR: Installer not found >> C:\Temp\infiniservice_install.log
echo.
echo Please ensure the Infiniservice ISO is mounted and try again.
goto :end

:check_service
echo.
echo Checking service status...
sc query Infiniservice >> C:\Temp\infiniservice_install.log 2>&1
sc query Infiniservice

echo.
echo [%DATE% %TIME%] Installation script completed >> C:\Temp\infiniservice_install.log

:end
echo.
echo ===============================================
echo Installation log saved to: C:\Temp\infiniservice_install.log
echo.
pause