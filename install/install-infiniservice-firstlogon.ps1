# Infiniservice First Logon Installation Script for Windows
# This script runs during the first logon to automatically install Infiniservice

param(
    [string]$LogFile = "C:\Windows\Temp\infiniservice-install.log"
)

# Function to write to log file and console
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage -Force
}

Write-Log "🚀 Starting Infiniservice auto-installation during first logon..." "INFO"

try {
    # Wait for system to stabilize
    Write-Log "⏳ Waiting for system to stabilize..." "INFO"
    Start-Sleep -Seconds 10

    # Find CD-ROM drives
    Write-Log "🔍 Searching for CD-ROM drives..." "INFO"
    $CdRomDrives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 5 }
    
    if ($CdRomDrives.Count -eq 0) {
        Write-Log "⚠️ No CD-ROM drives found" "WARN"
        Write-Log "Manual installation required after VM setup" "WARN"
        return
    }

    # Look for Infiniservice installer on CD-ROM drives
    $InstallerFound = $false
    $InstallerPath = $null
    
    foreach ($Drive in $CdRomDrives) {
        $DriveLetter = $Drive.DeviceID
        Write-Log "🔍 Checking drive $DriveLetter for Infiniservice installer..." "INFO"
        
        # Check for installer structure
        $WindowsInstallerPath = Join-Path $DriveLetter "infiniservice-windows\install-windows.ps1"
        $AutorunPath = Join-Path $DriveLetter "autorun-windows.ps1"
        
        if (Test-Path $WindowsInstallerPath) {
            Write-Log "✅ Found Infiniservice installer at $DriveLetter" "INFO"
            $InstallerFound = $true
            $InstallerPath = $DriveLetter
            break
        } elseif (Test-Path $AutorunPath) {
            Write-Log "✅ Found Infiniservice autorun at $DriveLetter" "INFO"
            $InstallerFound = $true
            $InstallerPath = $DriveLetter
            break
        }
    }

    if (-not $InstallerFound) {
        Write-Log "⚠️ Infiniservice installer not found on any CD-ROM drive" "WARN"
        Write-Log "Available drives: $($CdRomDrives.DeviceID -join ', ')" "INFO"
        Write-Log "Manual installation required" "WARN"
        return
    }

    # Determine installation mode
    $ServiceMode = "normal"
    if ($env:INFINISERVICE_MODE -eq "ping-pong") {
        $ServiceMode = "ping-pong"
        Write-Log "🏓 Installing in ping-pong test mode" "INFO"
    } else {
        Write-Log "📊 Installing in normal mode" "INFO"
    }

    # Change to installer directory
    Set-Location $InstallerPath
    Write-Log "📁 Changed to installer directory: $InstallerPath" "INFO"

    # Run the appropriate installer
    if (Test-Path "autorun-windows.ps1") {
        Write-Log "🚀 Running autorun installer..." "INFO"
        & ".\autorun-windows.ps1" $ServiceMode
    } elseif (Test-Path "infiniservice-windows\install-windows.ps1") {
        Write-Log "🚀 Running manual installer..." "INFO"
        Set-Location "infiniservice-windows"
        & ".\install-windows.ps1" -ServiceMode $ServiceMode
    } else {
        Write-Log "❌ No valid installer script found" "ERROR"
        return
    }

    Write-Log "✅ Infiniservice installation completed successfully!" "INFO"

    # Verify service installation
    $Service = Get-Service -Name "Infiniservice" -ErrorAction SilentlyContinue
    if ($Service) {
        Write-Log "✅ Infiniservice service found: $($Service.Status)" "INFO"
        
        if ($Service.Status -eq "Running") {
            Write-Log "✅ Infiniservice is running successfully" "INFO"
        } else {
            Write-Log "⚠️ Infiniservice service exists but is not running" "WARN"
        }
    } else {
        Write-Log "⚠️ Infiniservice service not found after installation" "WARN"
    }

    # Create desktop shortcut for logs
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Infiniservice Logs.lnk")
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-Command `"Get-EventLog -LogName Application -Source Infiniservice -Newest 50 | Format-Table -AutoSize`""
    $Shortcut.Description = "View Infiniservice Logs"
    $Shortcut.Save()
    Write-Log "✅ Created desktop shortcut for viewing logs" "INFO"

    # Display final status
    Write-Log "🎉 First logon setup completed!" "INFO"
    Write-Log "📝 Installation log: $LogFile" "INFO"
    
    if ($ServiceMode -eq "ping-pong") {
        Write-Log "🏓 Service is running in PING-PONG test mode" "INFO"
        Write-Log "   Check the backend logs to see ping-pong communication" "INFO"
    }

} catch {
    Write-Log "❌ Error during installation: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.Exception.StackTrace)" "ERROR"
} finally {
    # Clean up
    Write-Log "🧹 Cleaning up..." "INFO"
    
    # Return to system directory
    Set-Location "C:\Windows\System32"
    
    Write-Log "📋 Installation summary:" "INFO"
    Write-Log "  - Log file: $LogFile" "INFO"
    Write-Log "  - Service status: $(try { (Get-Service -Name 'Infiniservice').Status } catch { 'Not found' })" "INFO"
    Write-Log "  - Installation mode: $ServiceMode" "INFO"
    
    # Show a message box with results
    Add-Type -AssemblyName System.Windows.Forms
    $Result = if (Get-Service -Name "Infiniservice" -ErrorAction SilentlyContinue) { "SUCCESS" } else { "FAILED" }
    $Message = "Infiniservice installation: $Result`n`nCheck log file: $LogFile`n`nService mode: $ServiceMode"
    [System.Windows.Forms.MessageBox]::Show($Message, "Infiniservice Installation", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
