# Enhanced Infiniservice Installation Script with Comprehensive Logging
# This script can be used standalone or during Windows unattended installation

param(
    [string]$LogFile = "C:\Temp\infiniservice_install.log",
    [string]$ServiceMode = "normal",
    [string]$BackendUrl = "http://192.168.1.100:4000"
)

# Ensure log directory exists
$LogDir = Split-Path -Path $LogFile -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

# Function to write detailed logs
function Write-DetailedLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$NoConsole
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if (-not $NoConsole) {
        $Color = switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            "DEBUG" { "Gray" }
            default { "White" }
        }
        Write-Host $LogEntry -ForegroundColor $Color
    }
    
    Add-Content -Path $LogFile -Value $LogEntry -Force
}

# Function to log system information
function Write-SystemInfo {
    Write-DetailedLog "=== SYSTEM INFORMATION ===" "INFO"
    
    # Windows version
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    Write-DetailedLog "OS: $($OS.Caption) $($OS.Version)" "INFO"
    Write-DetailedLog "Architecture: $($OS.OSArchitecture)" "INFO"
    Write-DetailedLog "Computer Name: $env:COMPUTERNAME" "INFO"
    Write-DetailedLog "User: $env:USERNAME" "INFO"
    
    # PowerShell version
    Write-DetailedLog "PowerShell Version: $($PSVersionTable.PSVersion)" "INFO"
    
    # Available memory
    $Memory = Get-WmiObject -Class Win32_ComputerSystem
    $MemoryGB = [math]::Round($Memory.TotalPhysicalMemory / 1GB, 2)
    Write-DetailedLog "Total Memory: $MemoryGB GB" "INFO"
    
    # Disk space
    $SystemDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
    Write-DetailedLog "Free Space on C: $FreeSpaceGB GB" "INFO"
    
    # Network adapters
    Write-DetailedLog "Network Adapters:" "INFO"
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
        Write-DetailedLog "  - $($_.Description): $($_.IPAddress -join ', ')" "INFO"
    }
}

# Function to find installation media
function Find-InstallationMedia {
    Write-DetailedLog "=== SEARCHING FOR INSTALLATION MEDIA ===" "INFO"
    
    # Check all drives
    $AllDrives = Get-WmiObject -Class Win32_LogicalDisk
    Write-DetailedLog "Available drives:" "INFO"
    foreach ($Drive in $AllDrives) {
        $DriveType = switch ($Drive.DriveType) {
            2 { "Removable" }
            3 { "Fixed" }
            4 { "Network" }
            5 { "CD-ROM" }
            default { "Unknown" }
        }
        Write-DetailedLog "  - $($Drive.DeviceID) [$DriveType] $($Drive.VolumeName)" "INFO"
    }
    
    # Check CD-ROM drives for installer
    $CdRomDrives = $AllDrives | Where-Object { $_.DriveType -eq 5 }
    
    foreach ($Drive in $CdRomDrives) {
        $DriveLetter = $Drive.DeviceID
        Write-DetailedLog "Checking CD-ROM drive $DriveLetter..." "DEBUG"
        
        # Check various possible paths
        $PossiblePaths = @(
            "infiniservice-windows\install-windows.ps1",
            "autorun-windows.ps1",
            "infiniservice\install\install-infiniservice-firstlogon.ps1",
            "install-infiniservice.ps1"
        )
        
        foreach ($RelPath in $PossiblePaths) {
            $FullPath = Join-Path $DriveLetter $RelPath
            Write-DetailedLog "  Checking: $FullPath" "DEBUG"
            
            if (Test-Path $FullPath) {
                Write-DetailedLog "Found installer at: $FullPath" "SUCCESS"
                $FileInfo = Get-Item $FullPath
                Write-DetailedLog "  File size: $($FileInfo.Length) bytes" "INFO"
                Write-DetailedLog "  Last modified: $($FileInfo.LastWriteTime)" "INFO"
                return @{
                    Found = $true
                    Path = $FullPath
                    Drive = $DriveLetter
                }
            }
        }
    }
    
    Write-DetailedLog "No installer found on CD-ROM drives" "WARN"
    return @{ Found = $false }
}

# Function to download installer
function Download-Installer {
    param([string]$Url, [string]$Destination)
    
    Write-DetailedLog "=== DOWNLOADING INSTALLER ===" "INFO"
    Write-DetailedLog "URL: $Url" "INFO"
    Write-DetailedLog "Destination: $Destination" "INFO"
    
    try {
        # Create destination directory
        $DestDir = Split-Path -Path $Destination -Parent
        if (-not (Test-Path $DestDir)) {
            New-Item -Path $DestDir -ItemType Directory -Force | Out-Null
            Write-DetailedLog "Created directory: $DestDir" "INFO"
        }
        
        # Test connectivity
        Write-DetailedLog "Testing connectivity to backend..." "DEBUG"
        $TestUrl = $BackendUrl.TrimEnd('/') + "/health"
        
        try {
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadString($TestUrl) | Out-Null
            Write-DetailedLog "Backend is reachable" "SUCCESS"
        } catch {
            Write-DetailedLog "Cannot reach backend at $TestUrl: $_" "WARN"
        }
        
        # Download file
        Write-DetailedLog "Starting download..." "INFO"
        $StartTime = Get-Date
        
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($Url, $Destination)
        
        $EndTime = Get-Date
        $Duration = ($EndTime - $StartTime).TotalSeconds
        
        if (Test-Path $Destination) {
            $FileInfo = Get-Item $Destination
            Write-DetailedLog "Download completed in $Duration seconds" "SUCCESS"
            Write-DetailedLog "Downloaded file size: $($FileInfo.Length) bytes" "INFO"
            return $true
        } else {
            Write-DetailedLog "Download completed but file not found at destination" "ERROR"
            return $false
        }
        
    } catch {
        Write-DetailedLog "Download failed: $_" "ERROR"
        Write-DetailedLog "Exception type: $($_.Exception.GetType().FullName)" "DEBUG"
        Write-DetailedLog "Stack trace: $($_.Exception.StackTrace)" "DEBUG"
        return $false
    }
}

# Function to install Infiniservice
function Install-Infiniservice {
    param([string]$InstallerPath)
    
    Write-DetailedLog "=== INSTALLING INFINISERVICE ===" "INFO"
    Write-DetailedLog "Installer path: $InstallerPath" "INFO"
    Write-DetailedLog "Service mode: $ServiceMode" "INFO"
    
    try {
        # Check if installer exists
        if (-not (Test-Path $InstallerPath)) {
            Write-DetailedLog "Installer not found at: $InstallerPath" "ERROR"
            return $false
        }
        
        # Get installer directory
        $InstallerDir = Split-Path -Path $InstallerPath -Parent
        Write-DetailedLog "Changing to installer directory: $InstallerDir" "DEBUG"
        Push-Location $InstallerDir
        
        # Execute installer
        Write-DetailedLog "Executing installer script..." "INFO"
        $ScriptName = Split-Path -Path $InstallerPath -Leaf
        
        # Capture output
        $Output = & ".\$ScriptName" -ServiceMode $ServiceMode 2>&1
        
        foreach ($Line in $Output) {
            Write-DetailedLog "  [INSTALLER] $Line" "INFO"
        }
        
        Pop-Location
        
        Write-DetailedLog "Installer script completed" "SUCCESS"
        return $true
        
    } catch {
        Write-DetailedLog "Installation failed: $_" "ERROR"
        Write-DetailedLog "Exception type: $($_.Exception.GetType().FullName)" "DEBUG"
        Write-DetailedLog "Stack trace: $($_.Exception.StackTrace)" "DEBUG"
        Pop-Location
        return $false
    }
}

# Function to verify service installation
function Verify-ServiceInstallation {
    Write-DetailedLog "=== VERIFYING SERVICE INSTALLATION ===" "INFO"
    
    # Check if service exists
    $Service = Get-Service -Name "Infiniservice" -ErrorAction SilentlyContinue
    
    if ($Service) {
        Write-DetailedLog "Service found: Infiniservice" "SUCCESS"
        Write-DetailedLog "  Status: $($Service.Status)" "INFO"
        Write-DetailedLog "  Start Type: $($Service.StartType)" "INFO"
        
        # Get service details
        $ServiceWMI = Get-WmiObject -Class Win32_Service -Filter "Name='Infiniservice'"
        if ($ServiceWMI) {
            Write-DetailedLog "  Path: $($ServiceWMI.PathName)" "INFO"
            Write-DetailedLog "  Start Mode: $($ServiceWMI.StartMode)" "INFO"
            Write-DetailedLog "  Process ID: $($ServiceWMI.ProcessId)" "INFO"
        }
        
        # Check if service is running
        if ($Service.Status -eq "Running") {
            Write-DetailedLog "Service is running successfully" "SUCCESS"
            
            # Check process
            $Process = Get-Process -Id $ServiceWMI.ProcessId -ErrorAction SilentlyContinue
            if ($Process) {
                Write-DetailedLog "  Process Name: $($Process.ProcessName)" "INFO"
                Write-DetailedLog "  Memory Usage: $([math]::Round($Process.WorkingSet64 / 1MB, 2)) MB" "INFO"
                Write-DetailedLog "  CPU Time: $($Process.TotalProcessorTime)" "INFO"
            }
        } else {
            Write-DetailedLog "Service is not running. Attempting to start..." "WARN"
            
            try {
                Start-Service -Name "Infiniservice"
                Start-Sleep -Seconds 3
                
                $Service = Get-Service -Name "Infiniservice"
                if ($Service.Status -eq "Running") {
                    Write-DetailedLog "Service started successfully" "SUCCESS"
                } else {
                    Write-DetailedLog "Failed to start service. Status: $($Service.Status)" "ERROR"
                }
            } catch {
                Write-DetailedLog "Error starting service: $_" "ERROR"
            }
        }
        
        return $true
    } else {
        Write-DetailedLog "Service 'Infiniservice' not found" "ERROR"
        
        # Check for related processes
        Write-DetailedLog "Checking for related processes..." "DEBUG"
        $RelatedProcesses = Get-Process | Where-Object { $_.ProcessName -like "*infini*" }
        
        if ($RelatedProcesses) {
            Write-DetailedLog "Found related processes:" "INFO"
            foreach ($Proc in $RelatedProcesses) {
                Write-DetailedLog "  - $($Proc.ProcessName) (PID: $($Proc.Id))" "INFO"
            }
        } else {
            Write-DetailedLog "No related processes found" "INFO"
        }
        
        return $false
    }
}

# Function to check event logs
function Check-EventLogs {
    Write-DetailedLog "=== CHECKING EVENT LOGS ===" "INFO"
    
    try {
        # Check Application log for Infiniservice events
        $Events = Get-EventLog -LogName Application -Source "Infiniservice" -Newest 10 -ErrorAction SilentlyContinue
        
        if ($Events) {
            Write-DetailedLog "Recent Infiniservice events:" "INFO"
            foreach ($Event in $Events) {
                $LogLevel = switch ($Event.EntryType) {
                    "Error" { "ERROR" }
                    "Warning" { "WARN" }
                    default { "INFO" }
                }
                Write-DetailedLog "  [$($Event.TimeGenerated)] [$LogLevel] $($Event.Message)" "INFO"
            }
        } else {
            Write-DetailedLog "No Infiniservice events found in Application log" "INFO"
        }
        
        # Check System log for service-related events
        $ServiceEvents = Get-EventLog -LogName System -Source "Service Control Manager" -Newest 20 | 
                        Where-Object { $_.Message -like "*Infiniservice*" }
        
        if ($ServiceEvents) {
            Write-DetailedLog "Recent service control events:" "INFO"
            foreach ($Event in $ServiceEvents) {
                Write-DetailedLog "  [$($Event.TimeGenerated)] $($Event.Message)" "INFO"
            }
        }
        
    } catch {
        Write-DetailedLog "Error checking event logs: $_" "WARN"
    }
}

# Main installation process
try {
    Write-DetailedLog "========================================" "INFO"
    Write-DetailedLog "INFINISERVICE INSTALLATION STARTED" "INFO"
    Write-DetailedLog "========================================" "INFO"
    Write-DetailedLog "Log file: $LogFile" "INFO"
    Write-DetailedLog "Installation started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    
    # Log system information
    Write-SystemInfo
    
    # Wait for system to stabilize
    Write-DetailedLog "Waiting for system to stabilize..." "INFO"
    Start-Sleep -Seconds 5
    
    # Try to find installer on media
    $MediaResult = Find-InstallationMedia
    
    $InstallSuccess = $false
    
    if ($MediaResult.Found) {
        # Install from media
        Write-DetailedLog "Installing from media..." "INFO"
        $InstallSuccess = Install-Infiniservice -InstallerPath $MediaResult.Path
    } else {
        # Try to download installer
        Write-DetailedLog "Attempting to download installer from backend..." "INFO"
        
        $DownloadUrl = "$BackendUrl/api/infiniservice/installer"
        $LocalInstaller = "C:\Windows\Temp\install-infiniservice.ps1"
        
        if (Download-Installer -Url $DownloadUrl -Destination $LocalInstaller) {
            $InstallSuccess = Install-Infiniservice -InstallerPath $LocalInstaller
        } else {
            Write-DetailedLog "Failed to download installer" "ERROR"
        }
    }
    
    # Verify installation
    if ($InstallSuccess) {
        Start-Sleep -Seconds 3
        $ServiceVerified = Verify-ServiceInstallation
        
        if ($ServiceVerified) {
            Write-DetailedLog "INSTALLATION COMPLETED SUCCESSFULLY" "SUCCESS"
            
            # Check event logs
            Check-EventLogs
            
            # Create desktop shortcut
            try {
                $WshShell = New-Object -comObject WScript.Shell
                $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Infiniservice Logs.lnk")
                $Shortcut.TargetPath = "notepad.exe"
                $Shortcut.Arguments = $LogFile
                $Shortcut.Description = "View Infiniservice Installation Logs"
                $Shortcut.Save()
                Write-DetailedLog "Created desktop shortcut for logs" "SUCCESS"
            } catch {
                Write-DetailedLog "Failed to create desktop shortcut: $_" "WARN"
            }
        } else {
            Write-DetailedLog "INSTALLATION COMPLETED BUT SERVICE VERIFICATION FAILED" "ERROR"
        }
    } else {
        Write-DetailedLog "INSTALLATION FAILED" "ERROR"
    }
    
    # Final summary
    Write-DetailedLog "========================================" "INFO"
    Write-DetailedLog "INSTALLATION SUMMARY" "INFO"
    Write-DetailedLog "========================================" "INFO"
    Write-DetailedLog "Installation completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-DetailedLog "Installation result: $(if ($InstallSuccess) { 'SUCCESS' } else { 'FAILED' })" "INFO"
    Write-DetailedLog "Service status: $(try { (Get-Service -Name 'Infiniservice').Status } catch { 'Not found' })" "INFO"
    Write-DetailedLog "Service mode: $ServiceMode" "INFO"
    Write-DetailedLog "Log file location: $LogFile" "INFO"
    
} catch {
    Write-DetailedLog "CRITICAL ERROR: $_" "ERROR"
    Write-DetailedLog "Exception type: $($_.Exception.GetType().FullName)" "ERROR"
    Write-DetailedLog "Stack trace: $($_.Exception.StackTrace)" "ERROR"
} finally {
    Write-DetailedLog "========================================" "INFO"
    Write-DetailedLog "END OF LOG" "INFO"
    Write-DetailedLog "========================================" "INFO"
}