# Auto-detection and installation script for Windows
Write-Host "🪟 Infiniservice Windows Auto-Installer" -ForegroundColor Green

# Check for ping-pong mode
$ServiceMode = if ($env:INFINISERVICE_MODE -eq "ping-pong" -or $args[0] -eq "ping-pong") { "ping-pong" } else { "normal" }

if ($ServiceMode -eq "ping-pong") {
    Write-Host "🏓 Installing in ping-pong test mode" -ForegroundColor Yellow
} else {
    Write-Host "📊 Installing in normal mode" -ForegroundColor Cyan
}

Set-Location "infiniservice-windows"
.\install-windows.ps1 -ServiceMode $ServiceMode
