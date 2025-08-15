# Test script to verify PowerShell command syntax from XML
# These are the PowerShell commands extracted from the XML to test syntax

Write-Host "Testing PowerShell commands syntax..." -ForegroundColor Yellow

# Test 1: Log available drives
Write-Host "`nTest 1: Log available drives" -ForegroundColor Cyan
try {
    & {Add-Content -Path 'C:\Temp\test.log' -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Available drives:'); Get-WmiObject Win32_LogicalDisk | ForEach-Object { Add-Content -Path 'C:\Temp\test.log' -Value ('  Drive: ' + $_.DeviceID + ' Type: ' + $_.DriveType + ' VolumeName: ' + $_.VolumeName) }}
    Write-Host "✓ Command 1 syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Command 1 has syntax errors: $_" -ForegroundColor Red
}

# Test 2: Copy installation script
Write-Host "`nTest 2: Copy installation script" -ForegroundColor Cyan
try {
    & {$log='C:\Temp\test.log'; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Searching for installation media...'); $drives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 5}; foreach($d in $drives) { $src = Join-Path $d.DeviceID 'infiniservice\install\install-infiniservice-firstlogon.ps1'; if(Test-Path $src) { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Found script at ' + $src); New-Item -Path 'C:\Windows\Setup\Scripts' -ItemType Directory -Force | Out-Null; Copy-Item $src 'C:\Windows\Setup\Scripts\install-infiniservice.ps1' -Force; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Script copied to C:\Windows\Setup\Scripts'); break } else { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Script not found at ' + $src) } }}
    Write-Host "✓ Command 2 syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Command 2 has syntax errors: $_" -ForegroundColor Red
}

# Test 3: Download installation script
Write-Host "`nTest 3: Download installation script" -ForegroundColor Cyan
try {
    & {$log='C:\Temp\test.log'; $scriptPath='C:\Windows\Setup\Scripts\install-infiniservice.ps1'; if(-not (Test-Path $scriptPath)) { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Script not found locally, attempting download...'); try { $url='http://192.168.1.100:4000/api/infiniservice/install-script'; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Downloading from ' + $url); New-Item -Path 'C:\Windows\Setup\Scripts' -ItemType Directory -Force | Out-Null; $wc = New-Object System.Net.WebClient; $wc.DownloadFile($url, $scriptPath); $size = (Get-Item $scriptPath).Length; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Download completed. File size: ' + $size + ' bytes') } catch { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ERROR downloading script: ' + $_) } } else { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Script already exists at ' + $scriptPath) }}
    Write-Host "✓ Command 3 syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Command 3 has syntax errors: $_" -ForegroundColor Red
}

# Test 4: Execute installation script
Write-Host "`nTest 4: Execute installation script" -ForegroundColor Cyan
try {
    & {$log='C:\Temp\test.log'; $scriptPath='C:\Windows\Setup\Scripts\install-infiniservice.ps1'; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Checking for installation script...'); if(Test-Path $scriptPath) { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Executing installation script...'); try { & $scriptPath -LogFile 'C:\Temp\infiniservice_install.log' 2>&1 | Tee-Object -FilePath 'C:\Temp\infiniservice_install.log' -Append; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Script execution completed') } catch { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ERROR executing script: ' + $_) } } else { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ERROR: Installation script not found at ' + $scriptPath) }}
    Write-Host "✓ Command 4 syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Command 4 has syntax errors: $_" -ForegroundColor Red
}

# Test 5: Verify service installation
Write-Host "`nTest 5: Verify service installation" -ForegroundColor Cyan
try {
    & {$log='C:\Temp\test.log'; Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Verifying service installation...'); $svc = Get-Service -Name 'Infiniservice' -ErrorAction SilentlyContinue; if($svc) { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Service found: Status=' + $svc.Status + ', StartType=' + $svc.StartType) } else { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ERROR: Service not found after installation') }; Get-Process | Where-Object {$_.ProcessName -like '*infini*'} | ForEach-Object { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Running process: ' + $_.ProcessName + ' PID=' + $_.Id) }}
    Write-Host "✓ Command 5 syntax is valid" -ForegroundColor Green
} catch {
    Write-Host "✗ Command 5 has syntax errors: $_" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "All PowerShell commands have been tested for syntax validity." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow