# InfiniService VirtIO Diagnostic Script
# This script diagnoses VirtIO connectivity issues on Windows VMs

Write-Host "=== InfiniService VirtIO Diagnostic Tool ===" -ForegroundColor Cyan
Write-Host "Checking VirtIO configuration and connectivity..." -ForegroundColor Yellow

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check administrator privileges
Write-Host "`n1. Checking Administrator Privileges..." -ForegroundColor Green
if (Test-Administrator) {
    Write-Host "   ✓ Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "   ✗ NOT running as Administrator" -ForegroundColor Red
    Write-Host "   Please run this script as Administrator!" -ForegroundColor Yellow
    exit 1
}

# Check VirtIO devices
Write-Host "`n2. Checking VirtIO Devices..." -ForegroundColor Green
$virtioDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.Name -like "*VirtIO*" -or $_.Name -like "*QEMU*" }
if ($virtioDevices) {
    Write-Host "   ✓ VirtIO devices found:" -ForegroundColor Green
    foreach ($device in $virtioDevices) {
        Write-Host "     - $($device.Name) [$($device.Status)]" -ForegroundColor White
    }
} else {
    Write-Host "   ✗ No VirtIO devices found" -ForegroundColor Red
    Write-Host "   Install VirtIO drivers from: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/" -ForegroundColor Yellow
}

# Check VirtIO Serial devices specifically
Write-Host "`n3. Checking VirtIO Serial Devices..." -ForegroundColor Green
$serialDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
    $_.Name -like "*VirtIO Serial*" -or 
    $_.Name -like "*QEMU Serial*" -or
    $_.DeviceID -like "*VEN_1AF4&DEV_1003*"
}
if ($serialDevices) {
    Write-Host "   ✓ VirtIO Serial devices found:" -ForegroundColor Green
    foreach ($device in $serialDevices) {
        Write-Host "     - $($device.Name) [$($device.Status)]" -ForegroundColor White
    }
} else {
    Write-Host "   ✗ No VirtIO Serial devices found" -ForegroundColor Red
}

# Check COM ports
Write-Host "`n4. Checking COM Ports..." -ForegroundColor Green
$comPorts = Get-WmiObject -Class Win32_SerialPort
if ($comPorts) {
    Write-Host "   ✓ COM ports found:" -ForegroundColor Green
    foreach ($port in $comPorts) {
        Write-Host "     - $($port.DeviceID): $($port.Name)" -ForegroundColor White
    }
} else {
    Write-Host "   ⚠ No COM ports found" -ForegroundColor Yellow
}

# Check for VirtIO ports directory
Write-Host "`n5. Checking VirtIO Ports..." -ForegroundColor Green
$virtioPortsPath = "\\.\Global\org.infinibay.agent"
$qemuGuestAgentPath = "\\.\Global\org.qemu.guest_agent.0"

Write-Host "   Checking InfiniService channel: $virtioPortsPath" -ForegroundColor White
try {
    $file = [System.IO.File]::Open($virtioPortsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    $file.Close()
    Write-Host "   ✓ InfiniService VirtIO channel accessible" -ForegroundColor Green
} catch {
    Write-Host "   ✗ InfiniService VirtIO channel not accessible: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "   Checking QEMU Guest Agent channel: $qemuGuestAgentPath" -ForegroundColor White
try {
    $file = [System.IO.File]::Open($qemuGuestAgentPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    $file.Close()
    Write-Host "   ✓ QEMU Guest Agent VirtIO channel accessible" -ForegroundColor Green
} catch {
    Write-Host "   ✗ QEMU Guest Agent VirtIO channel not accessible: $($_.Exception.Message)" -ForegroundColor Red
}

# Check QEMU Guest Agent service
Write-Host "`n6. Checking QEMU Guest Agent Service..." -ForegroundColor Green
$qemuService = Get-Service -Name "QEMU Guest Agent" -ErrorAction SilentlyContinue
if ($qemuService) {
    Write-Host "   ✓ QEMU Guest Agent service found: $($qemuService.Status)" -ForegroundColor Green
    if ($qemuService.Status -ne "Running") {
        Write-Host "   ⚠ Service is not running. Starting..." -ForegroundColor Yellow
        try {
            Start-Service "QEMU Guest Agent"
            Write-Host "   ✓ Service started successfully" -ForegroundColor Green
        } catch {
            Write-Host "   ✗ Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "   ✗ QEMU Guest Agent service not found" -ForegroundColor Red
    Write-Host "   Install QEMU Guest Agent from VirtIO drivers package" -ForegroundColor Yellow
}

# Check InfiniService
Write-Host "`n7. Checking InfiniService..." -ForegroundColor Green
$infiniServicePath = "C:\Program Files\InfiniService\infiniservice.exe"
if (Test-Path $infiniServicePath) {
    Write-Host "   ✓ InfiniService binary found at: $infiniServicePath" -ForegroundColor Green
    
    # Check if service is registered
    $infiniService = Get-Service -Name "InfiniService" -ErrorAction SilentlyContinue
    if ($infiniService) {
        Write-Host "   ✓ InfiniService service registered: $($infiniService.Status)" -ForegroundColor Green
    } else {
        Write-Host "   ✗ InfiniService service not registered" -ForegroundColor Red
    }
} else {
    Write-Host "   ✗ InfiniService binary not found" -ForegroundColor Red
}

# Recommendations
Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Cyan

Write-Host "`n1. If VirtIO devices are missing:" -ForegroundColor Yellow
Write-Host "   - Download VirtIO drivers from: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
Write-Host "   - Install the drivers and reboot the VM"

Write-Host "`n2. If VirtIO channels are not accessible:" -ForegroundColor Yellow
Write-Host "   - Ensure the VM has VirtIO serial devices configured"
Write-Host "   - Check that the VM XML includes <channel> elements for both guest agent and InfiniService"
Write-Host "   - Restart the VM after configuration changes"

Write-Host "`n3. If QEMU Guest Agent is missing:" -ForegroundColor Yellow
Write-Host "   - Install QEMU Guest Agent from the VirtIO drivers package"
Write-Host "   - Ensure the service is running: Start-Service 'QEMU Guest Agent'"

Write-Host "`n4. If InfiniService is missing:" -ForegroundColor Yellow
Write-Host "   - Install InfiniService binary to C:\Program Files\InfiniService\"
Write-Host "   - Register as Windows service"
Write-Host "   - Configure to start automatically"

Write-Host "`nDiagnostic complete!" -ForegroundColor Green
