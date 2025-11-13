# PowerShell script to run all GoBlog services
param(
    [Parameter()]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "start",
    
    [Parameter()]
    [switch]$Background
)

$AuthBinary = ".\auth.exe"
$UserBinary = ".\user.exe" 
$GatewayBinary = ".\gateway.exe"

function Start-Services {
    param([bool]$RunInBackground = $false)
    
    Write-Host "Starting GoBlog microservices..." -ForegroundColor Green
    
    # Check if binaries exist
    if (-not (Test-Path $AuthBinary)) {
        Write-Host "Auth service binary not found. Running 'make build'..." -ForegroundColor Yellow
        make build
    }
    
    # Start User Service first (since Auth depends on it)
    Write-Host "Starting User Service on port 50052..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath $UserBinary -WindowStyle Minimized
    } else {
        Start-Process -FilePath $UserBinary -WindowStyle Normal
    }
    Start-Sleep -Seconds 5  # Give user service more time to start
    
    Write-Host "Starting Auth Service on port 50051..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath $AuthBinary -WindowStyle Minimized
    } else {
        Start-Process -FilePath $AuthBinary -WindowStyle Normal
    }
    Start-Sleep -Seconds 5  # Give auth service time to start and connect
    
    Write-Host "Starting Gateway on port 8080..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath $GatewayBinary -WindowStyle Minimized
    } else {
        Start-Process -FilePath $GatewayBinary -WindowStyle Normal
    }
    Start-Sleep -Seconds 3
    
    Write-Host "All services started! Gateway available at http://localhost:8080" -ForegroundColor Green
    Write-Host "Use '.\start-services.ps1 -Action stop' to stop all services" -ForegroundColor Yellow
}

function Stop-Services {
    Write-Host "Stopping all services..." -ForegroundColor Red
    
    Get-Process -Name "auth" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "user" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "gateway" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    Write-Host "All services stopped" -ForegroundColor Green
}

function Get-ServiceStatus {
    Write-Host "Service Status:" -ForegroundColor Yellow
    
    $authProcess = Get-Process -Name "auth" -ErrorAction SilentlyContinue
    $userProcess = Get-Process -Name "user" -ErrorAction SilentlyContinue
    $gatewayProcess = Get-Process -Name "gateway" -ErrorAction SilentlyContinue
    
    Write-Host "Auth Service:    " -NoNewline
    if ($authProcess) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    Write-Host "User Service:    " -NoNewline
    if ($userProcess) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    Write-Host "Gateway Service: " -NoNewline
    if ($gatewayProcess) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    if ($gatewayProcess) {
        Write-Host "`nAPI available at: http://localhost:8080" -ForegroundColor Cyan
    }
}

# Main execution
switch ($Action.ToLower()) {
    "start" {
        Start-Services -RunInBackground:$Background
    }
    "stop" {
        Stop-Services
    }
    "restart" {
        Stop-Services
        Start-Sleep -Seconds 2
        Start-Services -RunInBackground:$Background
    }
    "status" {
        Get-ServiceStatus
    }
    default {
        Write-Host "Usage: .\start-services.ps1 [-Action start|stop|restart|status] [-Background]" -ForegroundColor Yellow
        Write-Host "Examples:"
        Write-Host "  .\start-services.ps1                    # Start all services"
        Write-Host "  .\start-services.ps1 -Background        # Start all services minimized"
        Write-Host "  .\start-services.ps1 -Action stop       # Stop all services"
        Write-Host "  .\start-services.ps1 -Action restart    # Restart all services"
        Write-Host "  .\start-services.ps1 -Action status     # Check service status"
    }
}