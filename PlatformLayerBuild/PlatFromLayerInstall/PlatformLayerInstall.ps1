# Platform Layer Installation Script
# This script automates the platform layer installation process
# It follows the exact order of tasks as shown in the UI interface

# Set execution policy to Unrestricted for this script
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

# Set Error Action to stop on errors
$ErrorActionPreference = "Stop"

# Global Variables
$logFile = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "PlatformLayerInstall.log")
$tempDir = "C:\Temp"
$domainName = ""  # To be specified by administrator
$domainUser = ""  # To be specified by administrator
$domainPassword = ""  # To be specified by administrator

# Initialize Log File
function Initialize-LogFile {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    New-Item -Path $logFile -ItemType File -Force
    Add-Content -Path $logFile -Value "[$timestamp] Platform Layer Installation Started"
    Add-Content -Path $logFile -Value "----------------------------------------"
}

# Write to Log File
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage
    
    # Output to console with colors
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
    }
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ===============================
# PRE-INSTALL TASKS
# ===============================

# Task 1: Map drive and copy installers to C:\Temp
function Map-DriveAndCopyInstallers {
    param (
        [string]$networkPath = "\\server\share\installers"
    )
    
    try {
        Write-Log "Starting Task: Map drive and copy installers to C:\Temp" "INFO"
        
        # Map network drive to Z:
        Write-Log "Mapping network drive $networkPath to Z:" "INFO"
        New-PSDrive -Name Z -PSProvider FileSystem -Root $networkPath -ErrorAction Stop | Out-Null
        
        # Create Temp directory if it doesn't exist
        if (-not (Test-Path $tempDir)) {
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $tempDir" "INFO"
        }
        
        # Copy installers
        Write-Log "Copying installers from $networkPath to $tempDir" "INFO"
        Copy-Item -Path "Z:\*" -Destination $tempDir -Recurse -Force
        
        # Remove drive mapping
        Remove-PSDrive -Name Z
        
        Write-Log "Successfully copied installers to $tempDir" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to map drive and copy installers: $_" "ERROR"
        return $false
    }
}

# Task 2: Check if D drive is present
function Check-DriveD {
    try {
        Write-Log "Starting Task: Check if D drive is present" "INFO"
        
        $dDrive = Get-PSDrive -Name D -ErrorAction SilentlyContinue
        
        if ($dDrive) {
            $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='D:'"
            $sizeGB = [math]::Round($driveInfo.Size / 1GB, 2)
            $freeGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
            
            Write-Log "D: drive detected. Size: $sizeGB GB, Free Space: $freeGB GB" "SUCCESS"
            return $true
        }
        else {
            Write-Log "D: drive not detected. Please add a D: drive before continuing." "ERROR"
            
            # Prompt user
            Write-Host ""
            Write-Host "D: drive is required for this installation." -ForegroundColor Red
            Write-Host "Please add a D: drive and press Enter to continue, or Ctrl+C to exit." -ForegroundColor Yellow
            Read-Host
            
            # Check again after user action
            return Check-DriveD
        }
    }
    catch {
        Write-Log "Error checking for D: drive: $_" "ERROR"
        return $false
    }
}

# ===============================
# INSTALL STAGE 1
# ===============================

# Task 3: Install Citrix VDA (Server Mode)
function Install-CitrixVDA {
    param (
        [string]$installerPath = "$tempDir\CitrixVDA.exe",
        [bool]$includeVdaPlugins = $true,
        [bool]$includeProfileManagement = $true,
        [string]$commandLineOptions = "/quiet /optimize /components VDA,plugins,pm"
    )
    
    try {
        Write-Log "Starting Task: Install Citrix VDA (Server Mode)" "INFO"
        
        if (!(Test-Path $installerPath)) {
            Write-Log "VDA installer not found at: $installerPath" "ERROR"
            return $false
        }
        
        # Check if custom command line options are provided
        if ([string]::IsNullOrWhiteSpace($commandLineOptions)) {
            # Build the command with selected components
            $arguments = "/quiet /optimize /components VDA"
            
            if ($includeVdaPlugins) {
                $arguments += ",plugins"
                Write-Log "Including: VDA Plugins" "INFO"
            }
            
            if ($includeProfileManagement) {
                $arguments += ",pm"
                Write-Log "Including: Profile Management" "INFO"
            }
        } else {
            # Use provided command line options
            $arguments = $commandLineOptions
            Write-Log "Using custom command line options: $arguments" "INFO"
        }
        
        # Run the installer
        Write-Log "Executing VDA installer with arguments: $arguments" "INFO"
        $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "VDA installation failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully installed Citrix VDA" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Citrix VDA: $_" "ERROR"
        return $false
    }
}

# Task 4: Install Citrix PVS Target Device Software
function Install-CitrixPVS {
    param (
        [string]$installerPath = "$tempDir\CitrixPVS.exe",
        [string]$commandLineOptions = "/quiet /passive TARGETDEVICETYPE=1 BASEIMAGE=1 REQUIREPVSCLIENT=1 ADDFIREKEEPR=1"
    )
    
    try {
        Write-Log "Starting Task: Install Citrix PVS Target Device Software" "INFO"
        
        if (!(Test-Path $installerPath)) {
            Write-Log "PVS installer not found at: $installerPath" "ERROR"
            return $false
        }
        
        # Use command line options
        $arguments = $commandLineOptions
        Write-Log "Executing PVS installer with arguments: $arguments" "INFO"
        
        $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "PVS installation failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully installed Citrix PVS Target Device Software (Shared Mode)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Citrix PVS: $_" "ERROR"
        return $false
    }
}

# Task 5: Install Citrix WEM Agent
function Install-CitrixWEM {
    param (
        [string]$installerPath = "$tempDir\CitrixWEM.msi",
        [string]$commandLineOptions = "/quiet /norestart AGENTCONFIGURATIONPORT=8286 AGENTSERVICEPORT=8288"
    )
    
    try {
        Write-Log "Starting Task: Install Citrix WEM Agent" "INFO"
        
        if (!(Test-Path $installerPath)) {
            Write-Log "WEM installer not found at: $installerPath" "ERROR"
            return $false
        }
        
        # Use command line options
        $arguments = $commandLineOptions
        Write-Log "Executing WEM installer with arguments: $arguments" "INFO"
        
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" $arguments" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "WEM installation failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully installed Citrix WEM Agent" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install Citrix WEM Agent: $_" "ERROR"
        return $false
    }
}

# Task 6: Install UberAgent Monitoring Software
function Install-UberAgent {
    param (
        [string]$installerPath = "$tempDir\UberAgent.msi",
        [string]$commandLineOptions = "/quiet /norestart"
    )
    
    try {
        Write-Log "Starting Task: Install UberAgent Monitoring Software" "INFO"
        
        if (!(Test-Path $installerPath)) {
            Write-Log "UberAgent installer not found at: $installerPath" "ERROR"
            return $false
        }
        
        # Use command line options
        $arguments = $commandLineOptions
        Write-Log "Executing UberAgent installer with arguments: $arguments" "INFO"
        
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" $arguments" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "UberAgent installation failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully installed UberAgent Monitoring Software" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install UberAgent: $_" "ERROR"
        return $false
    }
}

# Task 7: Run Citrix Optimizer (Execute Mode)
function Run-CitrixOptimizer {
    param (
        [string]$optimizerPath = "$tempDir\CitrixOptimizer.exe"
    )
    
    try {
        Write-Log "Starting Task: Run Citrix Optimizer (Execute Mode)" "INFO"
        
        if (!(Test-Path $optimizerPath)) {
            Write-Log "Citrix Optimizer not found at: $optimizerPath" "ERROR"
            return $false
        }
        
        # Run the Optimizer
        $templatePath = "$tempDir\OptimizationTemplate.xml"
        $arguments = "-mode Execute -template `"$templatePath`""
        Write-Log "Executing Citrix Optimizer with arguments: $arguments" "INFO"
        
        $process = Start-Process -FilePath $optimizerPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "Citrix Optimizer execution failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully ran Citrix Optimizer" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to run Citrix Optimizer: $_" "ERROR"
        return $false
    }
}

# Task 8: Run KMS Licensing Rearm (slmgr /rearm)
function Run-KmsRearm {
    try {
        Write-Log "Starting Task: Run KMS Licensing Rearm (slmgr /rearm)" "INFO"
        
        # Execute slmgr /rearm
        $process = Start-Process -FilePath "cscript.exe" -ArgumentList "//B //NoLogo C:\Windows\System32\slmgr.vbs /rearm" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            Write-Log "KMS rearm failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
        
        Write-Log "Successfully ran KMS Licensing Rearm" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to run KMS Licensing Rearm: $_" "ERROR"
        return $false
    }
}

# Task 9: Remove Ghost Devices
function Remove-GhostDevices {
    try {
        Write-Log "Starting Task: Remove Ghost Devices" "INFO"
        
        # Set DevMgr_ShowNonPresent environment variable
        [System.Environment]::SetEnvironmentVariable('DevMgr_ShowNonPresent', '1', 'Process')
        
        # Get all non-present devices
        Write-Log "Retrieving non-present devices..." "INFO"
        $devcon = "$tempDir\devcon.exe"
        
        if (!(Test-Path $devcon)) {
            Write-Log "devcon.exe not found at: $devcon. Trying to download..." "WARNING"
            
            # Try to download devcon if not present
            try {
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab" -OutFile "$tempDir\devcon.cab"
                Expand-Archive -Path "$tempDir\devcon.cab" -DestinationPath "$tempDir\devcon"
                Copy-Item -Path "$tempDir\devcon\*.exe" -Destination $devcon
            }
            catch {
                Write-Log "Failed to download devcon.exe: $_" "ERROR"
                return $false
            }
        }
        
        # Remove ghost devices
        Write-Log "Removing ghost devices..." "INFO"
        $ghostDevices = & $devcon findall @"=*" | Where-Object { $_ -match "matching device(s) found" }
        
        if ($ghostDevices) {
            $count = [int]($ghostDevices -replace '.*(\d+) matching.*', '$1')
            Write-Log "Found $count ghost devices. Removing..." "INFO"
            
            # Remove each ghost device
            & $devcon remove @"=*"
            
            Write-Log "Ghost devices removed successfully" "SUCCESS"
        }
        else {
            Write-Log "No ghost devices found" "INFO"
        }
        
        # Reset environment variable
        [System.Environment]::SetEnvironmentVariable('DevMgr_ShowNonPresent', $null, 'Process')
        
        Write-Log "Ghost device removal completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to remove ghost devices: $_" "ERROR"
        return $false
    }
}

# Task 10: Move Page File to D: Drive
function Move-PageFile {
    param (
        [int]$pageFileSize = 8192 # Default 8GB
    )
    
    try {
        Write-Log "Starting Task: Move Page File to D: Drive" "INFO"
        
        # Check if D: drive exists and has enough space
        $dDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='D:'"
        
        if (!$dDrive) {
            Write-Log "D: drive not found. Cannot move page file." "ERROR"
            return $false
        }
        
        $freeSpaceGB = [math]::Round($dDrive.FreeSpace / 1GB, 2)
        $requiredSpaceGB = [math]::Round($pageFileSize / 1024, 2)
        
        if ($freeSpaceGB -lt $requiredSpaceGB) {
            Write-Log "Not enough free space on D: drive. Required: ${requiredSpaceGB}GB, Available: ${freeSpaceGB}GB" "ERROR"
            return $false
        }
        
        # Get the current page file settings
        Write-Log "Getting current page file settings..." "INFO"
        $currentPageFile = Get-WmiObject -Class Win32_ComputerSystem
        
        # Check if automatic page file management is enabled
        if ($currentPageFile.AutomaticManagedPagefile) {
            Write-Log "Disabling automatic page file management..." "INFO"
            $currentPageFile.AutomaticManagedPagefile = $false
            $currentPageFile.Put() | Out-Null
        }
        
        # Remove existing page files
        Write-Log "Removing existing page files..." "INFO"
        $pagefiles = Get-WmiObject -Class Win32_PageFileSetting
        if ($pagefiles) {
            foreach ($pagefile in $pagefiles) {
                $pagefile.Delete()
            }
        }
        
        # Create new page file on D: drive
        Write-Log "Creating new page file on D: drive with size: ${pageFileSize}MB" "INFO"
        $newPageFile = New-Object System.Management.ManagementClass("Win32_PageFileSetting")
        $newPageFile.Create("D:\pagefile.sys", $pageFileSize, $pageFileSize)
        
        Write-Log "Page file moved to D: drive successfully. Reboot required for changes to take effect." "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to move page file: $_" "ERROR"
        return $false
    }
}

# Task 11: Redirect Event Logs to D:\EventLogs
function Redirect-EventLogs {
    try {
        Write-Log "Starting Task: Redirect Event Logs to D:\EventLogs" "INFO"
        
        # Check if D: drive exists
        if (!(Test-Path "D:\")) {
            Write-Log "D: drive not found. Cannot redirect event logs." "ERROR"
            return $false
        }
        
        # Create EventLogs directory on D: drive
        $eventLogsDir = "D:\EventLogs"
        if (!(Test-Path $eventLogsDir)) {
            New-Item -Path $eventLogsDir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $eventLogsDir" "INFO"
        }
        
        # Get a list of all event logs
        $eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.LogName -notlike "*Analytic" -and $_.LogName -notlike "*Debug" }
        
        # Stop the Event Log service before making changes
        Write-Log "Stopping Event Log service..." "INFO"
        Stop-Service -Name EventLog -Force
        
        # Redirect each event log
        foreach ($log in $eventLogs) {
            $logName = $log.LogName
            $logFileName = $logName -replace "/", "-"
            $newPath = Join-Path -Path $eventLogsDir -ChildPath "$logFileName.evtx"
            
            try {
                # Use WevtUtil to set the new log file path
                $result = & wevtutil.exe sl $logName /lf:$newPath
                Write-Log "Redirected log: $logName to $newPath" "INFO"
            }
            catch {
                Write-Log "Failed to redirect log $logName: $_" "WARNING"
            }
        }
        
        # Start the Event Log service
        Write-Log "Starting Event Log service..." "INFO"
        Start-Service -Name EventLog
        
        Write-Log "Successfully redirected event logs to D:\EventLogs" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to redirect event logs: $_" "ERROR"
        
        # Make sure the Event Log service is started even if the redirection fails
        Start-Service -Name EventLog -ErrorAction SilentlyContinue
        
        return $false
    }
}

# Task 12: Copy Login Script Files
function Copy-LoginScriptFiles {
    param (
        [string]$scriptSourcePath = "\\server\share\scripts",
        [string]$scriptDestPath = "C:\Program Files\Login Scripts"
    )
    
    try {
        Write-Log "Starting Task: Copy Login Script Files" "INFO"
        
        # Create destination directory if it doesn't exist
        if (!(Test-Path $scriptDestPath)) {
            New-Item -Path $scriptDestPath -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $scriptDestPath" "INFO"
        }
        
        # Map the network drive temporarily
        $driveLetter = "Z"
        New-PSDrive -Name $driveLetter -PSProvider FileSystem -Root $scriptSourcePath -ErrorAction Stop | Out-Null
        
        # Copy script files
        Write-Log "Copying script files from $scriptSourcePath to $scriptDestPath" "INFO"
        $scriptFiles = Get-ChildItem -Path "${driveLetter}:\" -Recurse
        
        foreach ($file in $scriptFiles) {
            $relativePath = $file.FullName.Substring("${driveLetter}:\".Length)
            $destFile = Join-Path -Path $scriptDestPath -ChildPath $relativePath
            
            # Create directory structure if needed
            $destDir = Split-Path -Path $destFile -Parent
            if (!(Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            
            # Copy the file
            Copy-Item -Path $file.FullName -Destination $destFile -Force
            Write-Log "Copied: $relativePath" "INFO"
        }
        
        # Remove drive mapping
        Remove-PSDrive -Name $driveLetter
        
        Write-Log "Successfully copied login script files to $scriptDestPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to copy login script files: $_" "ERROR"
        
        # Remove drive mapping if it exists
        if (Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue
        }
        
        return $false
    }
}

# Task 13: Join Domain
function Join-DomainFunc {
    param (
        [string]$domain = $domainName,
        [string]$user = $domainUser,
        [string]$password = $domainPassword
    )
    
    try {
        Write-Log "Starting Task: Join Domain ($domain)" "INFO"
        
        # Check if already joined to domain
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $domain) {
            Write-Log "Computer is already joined to domain: $domain" "INFO"
            return $true
        }
        
        # Create credentials for domain join
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("$domain\$user", $securePassword)
        
        # Join the domain
        Write-Log "Joining domain: $domain with user: $user" "INFO"
        Add-Computer -DomainName $domain -Credential $credential -Restart:$false -Force
        
        Write-Log "Successfully joined domain: $domain. Reboot required for changes to take effect." "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to join domain: $_" "ERROR"
        return $false
    }
}

# ===============================
# STAGE 2 (POST-REBOOT) TASKS
# ===============================

# Task 14: Clear Event Logs
function Clear-EventLogsFunc {
    try {
        Write-Log "Starting Task: Clear Event Logs" "INFO"
        
        # Get all the event logs
        $eventLogs = Get-EventLog -List | Where-Object { $_.Entries.Count -gt 0 }
        
        foreach ($log in $eventLogs) {
            $logName = $log.Log
            Write-Log "Clearing event log: $logName (Entries: $($log.Entries.Count))" "INFO"
            
            try {
                # Clear the event log
                Clear-EventLog -LogName $logName
                Write-Log "Cleared event log: $logName" "INFO"
            }
            catch {
                Write-Log "Failed to clear event log $logName: $_" "WARNING"
            }
        }
        
        Write-Log "All event logs cleared successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to clear event logs: $_" "ERROR"
        return $false
    }
}

# Task 15: Clear Temp Files
function Clear-TempFiles {
    try {
        Write-Log "Starting Task: Clear Temp Files" "INFO"
        
        # Define temp directories to clean
        $tempDirs = @(
            "$env:SystemRoot\Temp",
            "$env:TEMP",
            "$env:SystemDrive\Windows.old",
            "$env:SystemRoot\SoftwareDistribution\Download"
        )
        
        # Get all user temp folders
        $userTempDirs = Get-ChildItem -Path "C:\Users\*\AppData\Local\Temp" -Directory -ErrorAction SilentlyContinue
        $tempDirs += $userTempDirs.FullName
        
        # Clear each temp directory
        foreach ($dir in $tempDirs) {
            if (Test-Path $dir) {
                Write-Log "Clearing temp directory: $dir" "INFO"
                
                try {
                    Get-ChildItem -Path $dir -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { $_.FullName -ne $logFile } | # Don't delete our own log file
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    
                    Write-Log "Cleared temp directory: $dir" "INFO"
                }
                catch {
                    Write-Log "Failed to clear some files in $dir: $_" "WARNING"
                }
            }
        }
        
        # Force Windows Update to regenerate SoftwareDistribution folder
        Write-Log "Stopping Windows Update service to clear SoftwareDistribution folder" "INFO"
        Stop-Service -Name wuauserv -Force
        
        # Clear SoftwareDistribution folder
        Get-ChildItem -Path "$env:SystemRoot\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        
        # Restart Windows Update service
        Start-Service -Name wuauserv
        
        Write-Log "Temp files cleared successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to clear temp files: $_" "ERROR"
        # Ensure Windows Update service is running
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        return $false
    }
}

# Task 16: Empty Recycle Bin
function Empty-RecycleBin {
    try {
        Write-Log "Starting Task: Empty Recycle Bin" "INFO"
        
        # Clear all recycle bins
        Write-Log "Emptying all recycle bins..." "INFO"
        Clear-RecycleBin -Force -DriveLetter C, D -ErrorAction SilentlyContinue
        
        Write-Log "Recycle bins emptied successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to empty recycle bins: $_" "ERROR"
        return $false
    }
}

# Task 17: Run NGEN Optimization
function Run-NgenOptimization {
    try {
        Write-Log "Starting Task: Run NGEN Optimization" "INFO"
        
        # Get all .NET Framework versions
        $netFrameworkDirs = Get-ChildItem -Path "$env:SystemRoot\Microsoft.NET\Framework*\v*" -Directory | 
                            Where-Object { Test-Path -Path "$($_.FullName)\ngen.exe" }
        
        if (!$netFrameworkDirs) {
            Write-Log "No .NET Framework installations found" "ERROR"
            return $false
        }
        
        # Run NGEN for each .NET Framework version
        foreach ($dir in $netFrameworkDirs) {
            $ngenPath = Join-Path -Path $dir.FullName -ChildPath "ngen.exe"
            $version = $dir.Name
            
            Write-Log "Running NGEN optimization for .NET Framework $version" "INFO"
            
            # Execute NGEN update
            $process = Start-Process -FilePath $ngenPath -ArgumentList "executeQueuedItems" -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -ne 0) {
                Write-Log "NGEN optimization for $version failed with exit code: $($process.ExitCode)" "WARNING"
            }
            else {
                Write-Log "NGEN optimization for $version completed successfully" "SUCCESS"
            }
        }
        
        Write-Log "NGEN optimization completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to run NGEN optimization: $_" "ERROR"
        return $false
    }
}

# Task 18: Finalize App Layer
function Finalize-AppLayer {
    try {
        Write-Log "Starting Task: Finalize App Layer" "INFO"
        
        # Final cleanup tasks
        Write-Log "Running final cleanup tasks..." "INFO"
        
        # Clean up registry
        Write-Log "Cleaning up registry..." "INFO"
        
        # Remove temporary registry keys
        $temRegKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Citrix*",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*"
        )
        
        foreach ($key in $temRegKeys) {
            try {
                Remove-Item -Path $key -Force -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore errors for wildcard paths
            }
        }
        
        # Run disk cleanup
        Write-Log "Running disk cleanup..." "INFO"
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow
        
        # Defragment the drives
        Write-Log "Optimizing drives..." "INFO"
        Optimize-Volume -DriveLetter C -Defrag
        if (Get-Volume -DriveLetter D -ErrorAction SilentlyContinue) {
            Optimize-Volume -DriveLetter D -Defrag
        }
        
        # Create a flag file to indicate app layer is finalized
        $finalizeFlag = "C:\ProgramData\PlatformLayer_Finalized.txt"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Set-Content -Path $finalizeFlag -Value "Platform layer finalized on $timestamp"
        
        Write-Log "App layer finalized successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to finalize app layer: $_" "ERROR"
        return $false
    }
}

# ===============================
# MAIN EXECUTION FUNCTION
# ===============================

function Start-PlatformLayerInstallation {
    param (
        [switch]$PreInstallOnly,
        [switch]$Stage1Only,
        [switch]$Stage2Only,
        [switch]$SkipConfirmation
    )
    
    # Check if running as Administrator
    if (-not (Test-Administrator)) {
        Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
        return
    }
    
    # Initialize log
    Initialize-LogFile
    
    # Display welcome message
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "        Platform Layer Installation Script          " -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Confirmation if not skipped
    if (-not $SkipConfirmation) {
        Write-Host "This script will perform the platform layer installation." -ForegroundColor Yellow
        Write-Host "Log file will be created at: $logFile" -ForegroundColor Yellow
        Write-Host ""
        $confirmation = Read-Host "Do you want to continue? (Y/N)"
        
        if ($confirmation -ne "Y" -and $confirmation -ne "y") {
            Write-Host "Installation cancelled by user." -ForegroundColor Red
            return
        }
    }
    
    # STAGE: PRE-INSTALL
    if (-not $Stage1Only -and -not $Stage2Only) {
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "                PRE-INSTALL TASKS                   " -ForegroundColor Cyan
        Write-Host "====================================================" -ForegroundColor Cyan
        
        # Task 1: Map drive and copy installers
        $result = Map-DriveAndCopyInstallers
        if (-not $result) {
            Write-Host "Pre-install task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 2: Check if D drive is present
        $result = Check-DriveD
        if (-not $result) {
            Write-Host "Pre-install task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        if ($PreInstallOnly) {
            Write-Host "Pre-install tasks completed successfully. Exiting as requested." -ForegroundColor Green
            return
        }
    }
    
    # STAGE 1: INSTALLATION
    if ((-not $PreInstallOnly -and -not $Stage2Only) -or $Stage1Only) {
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "                INSTALL STAGE 1                     " -ForegroundColor Cyan
        Write-Host "====================================================" -ForegroundColor Cyan
        
        # Task 3: Install Citrix VDA
        $result = Install-CitrixVDA
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 4: Install Citrix PVS
        $result = Install-CitrixPVS
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 5: Install Citrix WEM Agent
        $result = Install-CitrixWEM
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 6: Install UberAgent
        $result = Install-UberAgent
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 7: Run Citrix Optimizer
        $result = Run-CitrixOptimizer
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 8: Run KMS Licensing Rearm
        $result = Run-KmsRearm
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 9: Remove Ghost Devices
        $result = Remove-GhostDevices
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 10: Move Page File to D: Drive
        $result = Move-PageFile
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 11: Redirect Event Logs
        $result = Redirect-EventLogs
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 12: Copy Login Script Files
        $result = Copy-LoginScriptFiles
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 13: Join Domain
        $result = Join-DomainFunc
        if (-not $result) {
            Write-Host "Stage 1 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        Write-Host "====================================================" -ForegroundColor Yellow
        Write-Host "Stage 1 installation completed successfully." -ForegroundColor Yellow
        Write-Host "A system reboot is required before running Stage 2." -ForegroundColor Yellow
        Write-Host "====================================================" -ForegroundColor Yellow
        
        if ($Stage1Only) {
            $rebootNow = Read-Host "Do you want to reboot now? (Y/N)"
            if ($rebootNow -eq "Y" -or $rebootNow -eq "y") {
                Write-Host "Rebooting system..." -ForegroundColor Cyan
                Restart-Computer -Force
            }
            return
        }
        
        if (-not $SkipConfirmation) {
            $rebootNow = Read-Host "Do you want to reboot now? (Y/N)"
            if ($rebootNow -eq "Y" -or $rebootNow -eq "y") {
                Write-Host "Rebooting system..." -ForegroundColor Cyan
                Restart-Computer -Force
                return
            }
            else {
                Write-Host "Please reboot and run Stage 2 manually." -ForegroundColor Yellow
                return
            }
        }
    }
    
    # STAGE 2: POST-REBOOT
    if (($Stage2Only -or (-not $PreInstallOnly -and -not $Stage1Only)) -and $SkipConfirmation) {
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "                STAGE 2 (POST-REBOOT)               " -ForegroundColor Cyan
        Write-Host "====================================================" -ForegroundColor Cyan
        
        # Task 14: Clear Event Logs
        $result = Clear-EventLogsFunc
        if (-not $result) {
            Write-Host "Stage 2 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 15: Clear Temp Files
        $result = Clear-TempFiles
        if (-not $result) {
            Write-Host "Stage 2 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 16: Empty Recycle Bin
        $result = Empty-RecycleBin
        if (-not $result) {
            Write-Host "Stage 2 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 17: Run NGEN Optimization
        $result = Run-NgenOptimization
        if (-not $result) {
            Write-Host "Stage 2 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        # Task 18: Finalize App Layer
        $result = Finalize-AppLayer
        if (-not $result) {
            Write-Host "Stage 2 task failed. Aborting installation." -ForegroundColor Red
            return
        }
        
        Write-Host "====================================================" -ForegroundColor Green
        Write-Host "Platform Layer Installation completed successfully!" -ForegroundColor Green
        Write-Host "Log file is available at: $logFile" -ForegroundColor Green
        Write-Host "====================================================" -ForegroundColor Green
    }
}

# ===============================
# SCRIPT EXECUTION
# ===============================

# Parse command-line arguments
param (
    [switch]$PreInstall,
    [switch]$Stage1,
    [switch]$Stage2,
    [switch]$Force
)

# Determine which stages to run based on arguments
if ($PreInstall) {
    Start-PlatformLayerInstallation -PreInstallOnly -SkipConfirmation:$Force
}
elseif ($Stage1) {
    Start-PlatformLayerInstallation -Stage1Only -SkipConfirmation:$Force
}
elseif ($Stage2) {
    Start-PlatformLayerInstallation -Stage2Only -SkipConfirmation:$Force
}
else {
    # No specific stage specified, run the interactive mode
    Start-PlatformLayerInstallation -SkipConfirmation:$Force
}
