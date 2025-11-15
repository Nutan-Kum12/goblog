# PowerShell script to run all GoBlog services
param(
    [Parameter()]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "start",
    
    [Parameter()]
    [switch]$Background
)

$AuthBinary = ".\auth"
$UserBinary = ".\user" 
$GatewayBinary = ".\gateway"

function Start-Services {
    param([bool]$RunInBackground = $false)
    
    Write-Host "Starting GoBlog microservices..." -ForegroundColor Green
    
    # Create commands that load environment and run services
    $UserCommand = "cd '$PWD'; Get-Content .env | ForEach-Object { if(`$_ -match '^([^#=]+)=(.*)$') { [System.Environment]::SetEnvironmentVariable(`$matches[1], `$matches[2]) } }; Write-Host 'User Service Starting...' -ForegroundColor Green; go run ./services/user/main.go; Read-Host 'Press Enter to close'"
    
    $AuthCommand = "cd '$PWD'; Get-Content .env | ForEach-Object { if(`$_ -match '^([^#=]+)=(.*)$') { [System.Environment]::SetEnvironmentVariable(`$matches[1], `$matches[2]) } }; Write-Host 'Auth Service Starting...' -ForegroundColor Yellow; go run ./services/auth/main.go; Read-Host 'Press Enter to close'"
    
    $GatewayCommand = "cd '$PWD'; Get-Content .env | ForEach-Object { if(`$_ -match '^([^#=]+)=(.*)$') { [System.Environment]::SetEnvironmentVariable(`$matches[1], `$matches[2]) } }; Write-Host 'Gateway Service Starting...' -ForegroundColor Cyan; go run ./gateway/main.go; Read-Host 'Press Enter to close'"
    
    # Start User Service first (since Auth depends on it)
    Write-Host "Starting User Service on port 50052..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $UserCommand -WindowStyle Minimized
    } else {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $UserCommand -WindowStyle Normal
    }
    Start-Sleep -Seconds 8  # Give user service more time to start
    
    Write-Host "Starting Auth Service on port 50051..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $AuthCommand -WindowStyle Minimized
    } else {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $AuthCommand -WindowStyle Normal
    }
    Start-Sleep -Seconds 8  # Give auth service time to start and connect
    
    Write-Host "Starting Gateway on port 8080..." -ForegroundColor Cyan
    if ($RunInBackground) {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $GatewayCommand -WindowStyle Minimized
    } else {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $GatewayCommand -WindowStyle Normal
    }
    Start-Sleep -Seconds 5
    
    Write-Host "All services started! Gateway available at http://localhost:8080" -ForegroundColor Green
    Write-Host "Each service is running in its own PowerShell window with logs visible" -ForegroundColor Yellow
    Write-Host "Use '.\start-services.ps1 -Action stop' to stop all services" -ForegroundColor Yellow
}

function Stop-Services {
    Write-Host "Stopping all services..." -ForegroundColor Red
    
    # Stop Go processes
    Get-Process -Name "go" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Stop any remaining binary processes
    Get-Process -Name "auth" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "user" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "gateway" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Close PowerShell windows running the services (optional - they can be closed manually)
    Write-Host "Services stopped. You can close the PowerShell windows manually." -ForegroundColor Green
}

function Get-ServiceStatus {
    Write-Host "Service Status:" -ForegroundColor Yellow
    
    # Check for Go processes (since we're running from source)
    $goProcesses = Get-Process -Name "go" -ErrorAction SilentlyContinue
    $authProcess = Get-Process -Name "auth" -ErrorAction SilentlyContinue
    $userProcess = Get-Process -Name "user" -ErrorAction SilentlyContinue
    $gatewayProcess = Get-Process -Name "gateway" -ErrorAction SilentlyContinue
    
    Write-Host "Go Processes:    " -NoNewline
    if ($goProcesses) { Write-Host "RUNNING ($($goProcesses.Count) processes)" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    Write-Host "Auth Service:    " -NoNewline
    if ($authProcess -or $goProcesses) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    Write-Host "User Service:    " -NoNewline
    if ($userProcess -or $goProcesses) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    Write-Host "Gateway Service: " -NoNewline
    if ($gatewayProcess -or $goProcesses) { Write-Host "RUNNING" -ForegroundColor Green } else { Write-Host "STOPPED" -ForegroundColor Red }
    
    if ($goProcesses -or $gatewayProcess) {
        Write-Host "`nAPI available at: http://localhost:8080" -ForegroundColor Cyan
        Write-Host "Check the PowerShell windows for service logs" -ForegroundColor Yellow
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