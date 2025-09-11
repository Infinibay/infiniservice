# Infiniservice Windows Installation Script
# This script installs and configures the Infiniservice on Windows VMs

param(
    [string]$ServiceMode = "normal",
    [string]$VmId = $null,
    [string]$InstallPath = "C:\Program Files\Infiniservice"
)

# Initialize logging
$LogDir = "C:\Temp"
$LogFile = Join-Path $LogDir "infiniservice_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogFile = Join-Path $LogDir "infiniservice_install_error_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$DebugLogFile = Join-Path $LogDir "infiniservice_install_debug_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Create log directory if it doesn't exist
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $LogMessage = "[$CurrentTime] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    
    # Also write to console based on level
    switch ($Level) {
        "ERROR" { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $ErrorLogFile -Value $LogMessage
        }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor Cyan }
        "DEBUG" { 
            Write-Host $Message -ForegroundColor Gray
            Add-Content -Path $DebugLogFile -Value $LogMessage
        }
        default { Write-Host $Message }
    }
}

# Start logging
Write-Log "=== INFINISERVICE INSTALLATION STARTED ===" "INFO"
Write-Log "Installation timestamp: $Timestamp" "INFO"
Write-Log "Script location: $PSScriptRoot" "INFO"
Write-Log "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
Write-Log "Operating System: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)" "INFO"
Write-Log "Computer name: $env:COMPUTERNAME" "INFO"
Write-Log "User: $env:USERNAME" "INFO"

Write-Log "🚀 Starting Infiniservice installation..." "SUCCESS"
Write-Log "📁 Installation path: $InstallPath" "INFO"
Write-Log "🔧 Service mode: $ServiceMode" "INFO"
Write-Log "VM ID: $(if ($VmId) { $VmId } else { 'Not specified' })" "INFO"

# Check if running as administrator
Write-Log "Checking administrator privileges..." "INFO"
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "❌ This script must be run as Administrator!" "ERROR"
    Write-Log "Current user: $env:USERNAME" "ERROR"
    Write-Log "Installation FAILED - Administrator privileges required" "ERROR"
    exit 1
}
Write-Log "✅ Administrator privileges confirmed" "SUCCESS"

# Create installation directory
Write-Log "Checking installation directory: $InstallPath" "INFO"
if (!(Test-Path $InstallPath)) {
    try {
        Write-Log "Creating installation directory: $InstallPath" "INFO"
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-Log "✅ Created installation directory: $InstallPath" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to create installation directory: $_" "ERROR"
        exit 1
    }
} else {
    Write-Log "Installation directory already exists: $InstallPath" "INFO"
}

# Copy executable
# Try multiple locations for the executable
$PossibleLocations = @(
    (Join-Path $PSScriptRoot "infiniservice.exe"),
    "C:\Temp\InfiniService\infiniservice.exe",
    "C:\Temp\infiniservice.exe",
    (Join-Path (Split-Path $PSScriptRoot -Parent) "infiniservice.exe")
)

$SourceExe = $null
$DestExe = Join-Path $InstallPath "infiniservice.exe"

# Log all possible locations
Write-Log "Searching for infiniservice.exe in multiple locations:" "INFO"
foreach ($Location in $PossibleLocations) {
    Write-Log "  Checking: $Location" "INFO"
    if (Test-Path $Location) {
        $FileInfo = Get-Item $Location
        Write-Log "    FOUND! Size: $($FileInfo.Length) bytes" "SUCCESS"
        $SourceExe = $Location
        break
    } else {
        Write-Log "    Not found" "DEBUG"
    }
}

Write-Log "Source executable: $(if ($SourceExe) { $SourceExe } else { 'NOT FOUND' })" "INFO"
Write-Log "Destination executable: $DestExe" "INFO"

# Log current directory contents for debugging
Write-Log "Current directory ($PSScriptRoot) contents:" "DEBUG"
Get-ChildItem $PSScriptRoot -ErrorAction SilentlyContinue | ForEach-Object { 
    Write-Log "  - $($_.Name) (Size: $(if ($_.PSIsContainer) { 'Directory' } else { "$($_.Length) bytes" }), Type: $($_.Mode))" "DEBUG" 
}

# Also check parent directory
$ParentDir = Split-Path $PSScriptRoot -Parent
if ($ParentDir) {
    Write-Log "Parent directory ($ParentDir) contents:" "DEBUG"
    Get-ChildItem $ParentDir -ErrorAction SilentlyContinue | ForEach-Object { 
        Write-Log "  - $($_.Name) (Size: $(if ($_.PSIsContainer) { 'Directory' } else { "$($_.Length) bytes" }), Type: $($_.Mode))" "DEBUG" 
    }
}

# Check C:\Temp\InfiniService if different from PSScriptRoot
if ($PSScriptRoot -ne "C:\Temp\InfiniService") {
    Write-Log "Checking C:\Temp\InfiniService directory:" "DEBUG"
    if (Test-Path "C:\Temp\InfiniService") {
        Get-ChildItem "C:\Temp\InfiniService" -ErrorAction SilentlyContinue | ForEach-Object { 
            Write-Log "  - $($_.Name) (Size: $(if ($_.PSIsContainer) { 'Directory' } else { "$($_.Length) bytes" }))" "DEBUG" 
        }
    } else {
        Write-Log "  Directory C:\Temp\InfiniService does not exist" "DEBUG"
    }
}

# Check C:\Temp as well
Write-Log "Checking C:\Temp directory for infiniservice files:" "DEBUG"
Get-ChildItem "C:\Temp" -Filter "infini*" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "  - $($_.Name) (Size: $(if ($_.PSIsContainer) { 'Directory' } else { "$($_.Length) bytes" }))" "DEBUG"
}

if ($SourceExe -and (Test-Path $SourceExe)) {
    try {
        $SourceSize = (Get-Item $SourceExe).Length
        Write-Log "Source file size: $SourceSize bytes" "INFO"
        
        # Validate source file size (should be at least 1MB for a valid executable)
        if ($SourceSize -lt 1048576) {
            Write-Log "⚠️ Source file seems too small ($SourceSize bytes). May be corrupted or incomplete." "WARNING"
        }
        
        Write-Log "Copying executable from $SourceExe to $DestExe" "INFO"
        
        # Ensure destination directory exists
        $DestDir = Split-Path $DestExe -Parent
        if (!(Test-Path $DestDir)) {
            New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
            Write-Log "Created destination directory: $DestDir" "INFO"
        }
        
        Copy-Item $SourceExe $DestExe -Force
        
        # Verify the copy
        if (Test-Path $DestExe) {
            $DestSize = (Get-Item $DestExe).Length
            Write-Log "Destination file size: $DestSize bytes" "INFO"
            
            if ($SourceSize -eq $DestSize) {
                Write-Log "✅ Successfully copied infiniservice.exe to $DestExe" "SUCCESS"
            } else {
                Write-Log "⚠️ File sizes don't match - Source: $SourceSize, Dest: $DestSize" "WARNING"
            }
        } else {
            Write-Log "❌ Failed to verify copied executable" "ERROR"
            exit 1
        }
    } catch {
        Write-Log "❌ Failed to copy executable: $_" "ERROR"
        Write-Log "Exception details: $($_.Exception.Message)" "ERROR"
        exit 1
    }
} else {
    Write-Log "❌ Source executable not found in any of the expected locations" "ERROR"
    Write-Log "Searched locations:" "ERROR"
    foreach ($Location in $PossibleLocations) {
        Write-Log "  - $Location" "ERROR"
    }
    Write-Log "Current directory ($PSScriptRoot) contents:" "ERROR"
    Get-ChildItem $PSScriptRoot -ErrorAction SilentlyContinue | ForEach-Object { 
        Write-Log "  - $($_.Name) ($(if ($_.PSIsContainer) { 'Dir' } else { "$($_.Length) bytes" }))" "ERROR" 
    }
    Write-Log "" "ERROR"
    Write-Log "TROUBLESHOOTING STEPS:" "ERROR"
    Write-Log "1. Ensure infiniservice.exe was downloaded successfully" "ERROR"
    Write-Log "2. Check if the file is in C:\Temp\InfiniService\" "ERROR"
    Write-Log "3. Verify the download wasn't blocked by antivirus" "ERROR"
    Write-Log "4. Check network connectivity to the backend server" "ERROR"
    exit 1
}

# Create configuration file
$ConfigPath = Join-Path $InstallPath "config.toml"
Write-Log "Creating configuration file: $ConfigPath" "INFO"

$ConfigContent = @"
collection_interval = 30
log_level = "info"
service_name = "infiniservice"

# Windows virtio-serial device path will be auto-detected
virtio_serial_path = ""
"@

try {
    Set-Content -Path $ConfigPath -Value $ConfigContent
    Write-Log "Configuration content written:" "INFO"
    $ConfigContent -split "`n" | ForEach-Object { Write-Log "  $_" "INFO" }
    Write-Log "✅ Created configuration file: $ConfigPath" "SUCCESS"
} catch {
    Write-Log "❌ Failed to create configuration file: $_" "ERROR"
    exit 1
}

# Set environment variables
Write-Log "Setting environment variables..." "INFO"

if ($VmId) {
    try {
        Write-Log "Setting INFINIBAY_VM_ID to: $VmId" "INFO"
        [Environment]::SetEnvironmentVariable("INFINIBAY_VM_ID", $VmId, "Machine")
        Write-Log "✅ Set VM ID environment variable: $VmId" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to set VM ID environment variable: $_" "ERROR"
    }
} else {
    Write-Log "No VM ID specified, skipping environment variable" "INFO"
}

if ($ServiceMode -eq "ping-pong") {
    try {
        Write-Log "Setting INFINISERVICE_MODE to: ping-pong" "INFO"
        [Environment]::SetEnvironmentVariable("INFINISERVICE_MODE", "ping-pong", "Machine")
        Write-Log "✅ Set service mode to ping-pong" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to set service mode environment variable: $_" "ERROR"
    }
} else {
    Write-Log "Service mode is: $ServiceMode" "INFO"
}

# Create Windows service
$ServiceName = "Infiniservice"
$ServiceDisplayName = "Infinibay Service"
$ServiceDescription = "Infinibay VM monitoring and communication service"

# Remove existing service if it exists
Write-Log "Checking for existing service: $ServiceName" "INFO"
$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($ExistingService) {
    Write-Log "🔄 Found existing service - Status: $($ExistingService.Status)" "WARNING"
    Write-Log "Stopping existing service..." "INFO"
    
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Log "Service stopped" "INFO"
    } catch {
        Write-Log "Failed to stop service: $_" "WARNING"
    }
    
    Write-Log "Deleting existing service..." "INFO"
    $DeleteResult = sc.exe delete $ServiceName 2>&1
    Write-Log "Delete result: $DeleteResult" "INFO"
    
    Start-Sleep -Seconds 2
    Write-Log "Existing service removed" "SUCCESS"
} else {
    Write-Log "No existing service found" "INFO"
}

# Create new service
$ServiceArgs = if ($ServiceMode -eq "ping-pong") { "--ping-pong" } else { "" }
$ServiceCommand = "`"$DestExe`" $ServiceArgs"

Write-Log "🔧 Creating Windows service..." "INFO"
Write-Log "Service name: $ServiceName" "INFO"
Write-Log "Display name: $ServiceDisplayName" "INFO"
Write-Log "Binary path: $ServiceCommand" "INFO"
Write-Log "Start type: auto" "INFO"

$CreateResult = sc.exe create $ServiceName binPath= $ServiceCommand DisplayName= $ServiceDisplayName start= auto 2>&1
Write-Log "SC.exe output: $CreateResult" "INFO"
Write-Log "SC.exe exit code: $LASTEXITCODE" "INFO"

if ($LASTEXITCODE -eq 0) {
    Write-Log "✅ Service created successfully" "SUCCESS"
    
    # Verify service creation
    $VerifyService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($VerifyService) {
        Write-Log "Service verification: Found service '$ServiceName'" "SUCCESS"
        Write-Log "Service status after creation: $($VerifyService.Status)" "INFO"
    } else {
        Write-Log "⚠️ Service created but verification failed" "WARNING"
    }
} else {
    Write-Log "❌ Failed to create service: $CreateResult" "ERROR"
    Write-Log "Common issues:" "ERROR"
    Write-Log "  - Service name already exists" "ERROR"
    Write-Log "  - Invalid binary path" "ERROR"
    Write-Log "  - Insufficient permissions" "ERROR"
    exit 1
}

# Set service description
Write-Log "Setting service description..." "INFO"
$DescResult = sc.exe description $ServiceName $ServiceDescription 2>&1
Write-Log "Description result: $DescResult" "INFO"

# Configure service recovery options
Write-Log "Configuring service recovery options..." "INFO"
$RecoveryResult = sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1
Write-Log "Recovery configuration result: $RecoveryResult" "INFO"

# Start the service
Write-Log "🚀 Attempting to start Infiniservice..." "INFO"

try {
    # First check if the executable can run
    Write-Log "Verifying executable before starting service..." "INFO"
    if (Test-Path $DestExe) {
        $ExeInfo = Get-Item $DestExe
        Write-Log "Executable exists - Size: $($ExeInfo.Length) bytes, LastWriteTime: $($ExeInfo.LastWriteTime)" "INFO"
        
        # Test if executable can run directly (for debugging)
        Write-Log "Testing executable directly (non-service mode)..." "DEBUG"
        try {
            $TestProcess = Start-Process -FilePath $DestExe -ArgumentList "--version" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "C:\Temp\infiniservice_test_output.txt" -RedirectStandardError "C:\Temp\infiniservice_test_error.txt"
            Write-Log "Test execution exit code: $($TestProcess.ExitCode)" "DEBUG"
            
            if (Test-Path "C:\Temp\infiniservice_test_output.txt") {
                $TestOutput = Get-Content "C:\Temp\infiniservice_test_output.txt"
                Write-Log "Test output: $TestOutput" "DEBUG"
            }
            if (Test-Path "C:\Temp\infiniservice_test_error.txt") {
                $TestError = Get-Content "C:\Temp\infiniservice_test_error.txt"
                if ($TestError) {
                    Write-Log "Test error output: $TestError" "WARNING"
                }
            }
        } catch {
            Write-Log "Could not test executable directly: $_" "WARNING"
        }
    }
    
    $StartResult = Start-Service -Name $ServiceName -PassThru -ErrorAction Stop
    
    # Wait a moment for the service to stabilize
    Start-Sleep -Seconds 3
    
    # Check service status again
    $ServiceStatus = Get-Service -Name $ServiceName
    Write-Log "Service status after start attempt: $($ServiceStatus.Status)" "INFO"
    
    if ($ServiceStatus.Status -eq "Running") {
        Write-Log "✅ Infiniservice started successfully!" "SUCCESS"
        
        # Get process information
        $ServiceProcess = Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $ServiceName}
        if ($ServiceProcess) {
            Write-Log "Service process ID: $($ServiceProcess.ProcessId)" "INFO"
            Write-Log "Service state: $($ServiceProcess.State)" "INFO"
        }
    } else {
        Write-Log "⚠️ Service created but not running. Status: $($ServiceStatus.Status)" "WARNING"
        Write-Log "Checking Windows Event Log for errors..." "WARNING"
        
        # Try to get recent event log entries
        try {
            $Events = Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 | Where-Object {$_.Message -like "*$ServiceName*"}
            foreach ($Event in $Events) {
                Write-Log "Event Log: $($Event.TimeGenerated) - $($Event.Message)" "WARNING"
            }
        } catch {
            Write-Log "Could not retrieve event log entries: $_" "WARNING"
        }
    }
} catch {
    Write-Log "❌ Failed to start service: $_" "ERROR"
    Write-Log "Error details: $($_.Exception.Message)" "ERROR"
    
    # Try to get more diagnostic information
    Write-Log "Attempting to gather diagnostic information..." "INFO"
    
    # Check if service exists
    $ServiceCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($ServiceCheck) {
        Write-Log "Service exists with status: $($ServiceCheck.Status)" "INFO"
    } else {
        Write-Log "Service does not exist in service list" "ERROR"
    }
    
    # Check Windows Event Log
    try {
        $RecentErrors = Get-EventLog -LogName Application -EntryType Error -Newest 5
        foreach ($Error in $RecentErrors) {
            Write-Log "Recent Application Error: $($Error.TimeGenerated) - $($Error.Message.Substring(0, [Math]::Min(200, $Error.Message.Length)))..." "INFO"
        }
    } catch {
        Write-Log "Could not retrieve application event log" "WARNING"
    }
}

# Create uninstall script
$UninstallScript = Join-Path $InstallPath "uninstall.ps1"
Write-Log "Creating uninstall script: $UninstallScript" "INFO"

$UninstallContent = @"
# Infiniservice Uninstall Script
`$LogFile = "C:\Temp\infiniservice_uninstall.log"
`$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-UninstallLog {
    param([string]`$Message, [string]`$Level = "INFO")
    `$LogMessage = "[`$Timestamp] [`$Level] `$Message"
    Add-Content -Path `$LogFile -Value `$LogMessage
    
    switch (`$Level) {
        "ERROR" { Write-Host `$Message -ForegroundColor Red }
        "WARNING" { Write-Host `$Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host `$Message -ForegroundColor Green }
        default { Write-Host `$Message -ForegroundColor Cyan }
    }
}

Write-UninstallLog "=== INFINISERVICE UNINSTALLATION STARTED ===" "INFO"
Write-UninstallLog "🛑 Uninstalling Infiniservice..." "WARNING"

# Stop and remove service
Write-UninstallLog "Stopping service: $ServiceName" "INFO"
Stop-Service -Name "$ServiceName" -Force -ErrorAction SilentlyContinue
Write-UninstallLog "Deleting service..." "INFO"
`$DeleteResult = sc.exe delete "$ServiceName" 2>&1
Write-UninstallLog "Delete result: `$DeleteResult" "INFO"

# Remove environment variables
Write-UninstallLog "Removing environment variables..." "INFO"
[Environment]::SetEnvironmentVariable("INFINIBAY_VM_ID", `$null, "Machine")
[Environment]::SetEnvironmentVariable("INFINISERVICE_MODE", `$null, "Machine")

# Remove installation directory
Write-UninstallLog "Removing installation directory: $InstallPath" "INFO"
Remove-Item -Path "$InstallPath" -Recurse -Force -ErrorAction SilentlyContinue

Write-UninstallLog "✅ Infiniservice uninstalled successfully!" "SUCCESS"
Write-UninstallLog "=== UNINSTALLATION COMPLETED ===" "INFO"
"@

try {
    Set-Content -Path $UninstallScript -Value $UninstallContent
    Write-Log "✅ Created uninstall script: $UninstallScript" "SUCCESS"
} catch {
    Write-Log "⚠️ Failed to create uninstall script: $_" "WARNING"
}

# Display service status
Write-Log "`n📊 Final Service Status:" "INFO"
$FinalService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($FinalService) {
    Write-Log "Service Name: $($FinalService.Name)" "INFO"
    Write-Log "Display Name: $($FinalService.DisplayName)" "INFO"
    Write-Log "Status: $($FinalService.Status)" "INFO"
    Write-Log "Start Type: $($FinalService.StartType)" "INFO"
    
    Get-Service -Name $ServiceName | Format-Table -AutoSize
} else {
    Write-Log "❌ Could not retrieve final service status" "ERROR"
}

# Installation summary
Write-Log "" "INFO"
Write-Log "=== INSTALLATION SUMMARY ===" "INFO"
Write-Log "Installation path: $InstallPath" "INFO"
Write-Log "Configuration file: $ConfigPath" "INFO"
Write-Log "Uninstall script: $UninstallScript" "INFO"
Write-Log "Main log file: $LogFile" "INFO"
Write-Log "Error log file: $ErrorLogFile" "INFO"
Write-Log "Debug log file: $DebugLogFile" "INFO"

# Log system information for debugging
Write-Log "" "DEBUG"
Write-Log "=== SYSTEM INFORMATION ===" "DEBUG"
Write-Log "Windows Version: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version)" "DEBUG"
Write-Log "Architecture: $env:PROCESSOR_ARCHITECTURE" "DEBUG"
Write-Log "Available Memory: $((Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory) / 1024) MB" "DEBUG"
Write-Log "System Drive Free Space: $((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace) / 1GB) GB" "DEBUG"

# Check for VirtIO Serial driver
Write-Log "" "DEBUG"
Write-Log "=== VIRTIO SERIAL CHECK ===" "DEBUG"
$VirtioDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.Name -like "*VirtIO*" -or $_.Name -like "*virtio*"}
if ($VirtioDevices) {
    foreach ($Device in $VirtioDevices) {
        Write-Log "Found VirtIO device: $($Device.Name) - Status: $($Device.Status)" "DEBUG"
    }
} else {
    Write-Log "No VirtIO devices found - this may cause communication issues" "WARNING"
}

# Check COM ports
$ComPorts = Get-WmiObject -Class Win32_SerialPort
if ($ComPorts) {
    foreach ($Port in $ComPorts) {
        Write-Log "COM Port: $($Port.DeviceID) - $($Port.Name)" "DEBUG"
    }
} else {
    Write-Log "No COM ports detected" "DEBUG"
}

if ($FinalService -and $FinalService.Status -eq "Running") {
    Write-Log "🎉 Infiniservice installation completed successfully!" "SUCCESS"
} else {
    Write-Log "⚠️ Installation completed but service is not running" "WARNING"
    Write-Log "Please check the log files in C:\Temp for details" "WARNING"
}

Write-Log "📝 Configuration file: $ConfigPath" "INFO"
Write-Log "🗑️ To uninstall, run: $UninstallScript" "INFO"

if ($ServiceMode -eq "ping-pong") {
    Write-Log "🏓 Service is running in PING-PONG test mode" "WARNING"
    Write-Log "   Check the backend logs to see ping-pong communication" "WARNING"
}

Write-Log "=== INSTALLATION SCRIPT COMPLETED ===" "INFO"
Write-Log "Installation end time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
