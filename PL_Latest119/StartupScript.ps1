# PowerShell Script: Environment-Based Configuration Deployment
# This script detects the computer name and copies appropriate config files
# Then sets the uberAgentSvc service to automatic and starts it
# Designed to run as a startup script with event log logging

# Define log source for Windows Event Log
$logSource = "ConfigDeploymentScript"
$logName = "Application"

# Create event log source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($logSource)) {
    try {
        [System.Diagnostics.EventLog]::CreateEventSource($logSource, $logName)
    }
    catch {
        # If we can't create the source, we'll write to a file instead
        $logSource = $null
    }
}

# Function to write log entries
function Write-LogEntry {
    param(
        [string]$Message,
        [string]$EntryType = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    
    # Try to write to Event Log
    if ($logSource) {
        try {
            Write-EventLog -LogName $logName -Source $logSource -EventId 1000 -EntryType $EntryType -Message $Message
        }
        catch {
            # Fall back to file logging
            $logSource = $null
        }
    }
    
    # Also write to a log file as backup
    $logFile = "C:\Windows\Logs\ConfigDeployment.log"
    $logDir = Split-Path -Parent $logFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $logFile -Value $logMessage -Force
}

# Get the computer name
$computerName = $env:COMPUTERNAME
Write-LogEntry "Script started on computer: $computerName"

# Define file paths (modify these paths according to your environment)
$devSourcePath = "C:\ConfigFiles\Dev\config.xml"
$devDestPath = "C:\Program Files\uberAgent\config.xml"
$prodSourcePath = "C:\ConfigFiles\Prod\config.xml"
$prodDestPath = "C:\Program Files\uberAgent\config.xml"

# Service name
$serviceName = "uberAgentSvc"

try {
    # Check if computer name starts with 'dev' or 'prod' (case-insensitive)
    if ($computerName -like "dev*") {
        Write-LogEntry "Development environment detected"
        $sourcePath = $devSourcePath
        $destPath = $devDestPath
    }
    elseif ($computerName -like "prod*") {
        Write-LogEntry "Production environment detected"
        $sourcePath = $prodSourcePath
        $destPath = $prodDestPath
    }
    else {
        Write-LogEntry "Computer name doesn't start with 'dev' or 'prod'. Exiting..." -EntryType "Warning"
        exit 1
    }

    # Check if source file exists
    if (-not (Test-Path $sourcePath)) {
        throw "Source file not found: $sourcePath"
    }

    # Create destination directory if it doesn't exist
    $destDir = Split-Path -Parent $destPath
    if (-not (Test-Path $destDir)) {
        Write-LogEntry "Creating destination directory: $destDir"
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # Copy the configuration file
    Write-LogEntry "Copying configuration file from $sourcePath to $destPath"
    
    Copy-Item -Path $sourcePath -Destination $destPath -Force -ErrorAction Stop
    
    # Validate the copy operation
    if (Test-Path $destPath) {
        $sourceHash = Get-FileHash -Path $sourcePath -Algorithm SHA256
        $destHash = Get-FileHash -Path $destPath -Algorithm SHA256
        
        if ($sourceHash.Hash -eq $destHash.Hash) {
            Write-LogEntry "File copied and validated successfully (SHA256: $($sourceHash.Hash))"
        }
        else {
            throw "File copy validation failed - hashes don't match"
        }
    }
    else {
        throw "Destination file not found after copy operation"
    }

    # Check if the service exists
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($null -eq $service) {
        throw "Service '$serviceName' not found on this system"
    }

    # Set service to automatic startup
    Write-LogEntry "Setting $serviceName to automatic startup"
    Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
    Write-LogEntry "Service startup type set to Automatic"

    # Start the service if it's not already running
    if ($service.Status -ne 'Running') {
        Write-LogEntry "Starting $serviceName service"
        Start-Service -Name $serviceName -ErrorAction Stop
        
        # Wait a moment for the service to start
        Start-Sleep -Seconds 5
        
        # Verify service is running
        $service = Get-Service -Name $serviceName
        if ($service.Status -eq 'Running') {
            Write-LogEntry "Service started successfully"
        }
        else {
            Write-LogEntry "Service may not have started properly. Current status: $($service.Status)" -EntryType "Warning"
        }
    }
    else {
        Write-LogEntry "Service is already running"
    }

    Write-LogEntry "Script completed successfully"
    exit 0

}
catch {
    $errorMessage = "Error occurred: $_"
    Write-LogEntry $errorMessage -EntryType "Error"
    
    # For startup scripts, it's often useful to have some delay before exiting on error
    # This prevents rapid retry loops if there's a persistent issue
    Start-Sleep -Seconds 10
    exit 1
}