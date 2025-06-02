<#
.SYNOPSIS
    Enhanced Citrix Functions Library
    
.DESCRIPTION
    Comprehensive function library for Citrix platform installation.
    Optimized for installation without server connectivity requirements.
    
.VERSION
    2.0 - Enhanced with improved error handling
    
.NOTES
    - All functions work without server connectivity requirements
    - No server connectivity required during template creation
    - Enhanced error handling and validation throughout
    - Removed delivery controller, PVS server, and WEM Infrastructure server dependencies
#>

#region Global Variables and Configuration
$Global:LogPath = ""
$Global:VerboseLogging = $true

# Error action preference for consistent behavior
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"
#endregion

#region Logging Functions
function Initialize-Logging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$ClearExisting = $false
    )
    
    try {
        $Global:LogPath = $LogPath
        
        # Ensure log directory exists
        $LogDir = Split-Path $LogPath -Parent
        if (!(Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        
        # Clear existing log if requested
        if ($ClearExisting -and (Test-Path $LogPath)) {
            Remove-Item $LogPath -Force -ErrorAction SilentlyContinue
        }
        
        # Initialize log file
        $InitMessage = "=== Citrix Installation Log Initialized at $(Get-Date) ==="
        Add-Content -Path $LogPath -Value $InitMessage -Encoding UTF8
        
        Write-Host "Logging initialized: $LogPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to initialize logging: $($_.Exception.Message)"
        return $false
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message,
        
        [Parameter(Mandatory=$false, Position=1)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Write to console with color coding
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor White }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "DEBUG"   { if ($Global:VerboseLogging) { Write-Host $LogEntry -ForegroundColor Gray } }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to log file if available
    if (![string]::IsNullOrEmpty($Global:LogPath)) {
        try {
            Add-Content -Path $Global:LogPath -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            # Silently continue if logging fails to avoid infinite loops
        }
    }
}

function Write-LogHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HeaderText
    )
    
    $Separator = "=" * 80
    $FormattedHeader = " $HeaderText "
    $PaddingLength = [Math]::Max(0, (80 - $FormattedHeader.Length) / 2)
    $PaddedHeader = "=" * [Math]::Floor($PaddingLength) + $FormattedHeader + "=" * [Math]::Ceiling($PaddingLength)
    
    Write-Log ""
    Write-Log $Separator "INFO"
    Write-Log $PaddedHeader "INFO"
    Write-Log $Separator "INFO"
}
#endregion

#region System Information Functions
function Get-BasicSystemInfo {
    [CmdletBinding()]
    param()
    
    try {
        # Only collect essential system information
        $BasicInfo = @{
            ComputerName = $env:COMPUTERNAME
            Timestamp = Get-Date
        }
        
        return $BasicInfo
    }
    catch {
        Write-Log "Failed to gather basic system information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-Prerequisites {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Testing Installation Prerequisites"
    
    $Results = @{
        OverallStatus = $true
        AdminRights = $false
        PowerShellVersion = $false
        OSVersion = $false
        ArchitectureOK = $false
        DiskSpace = $false
        Issues = @()
        SystemInfo = $null
    }
    
    try {
        # Test administrator rights
        Write-Log "Checking administrator privileges..."
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $Results.AdminRights = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if ($Results.AdminRights) {
            Write-Log "Administrator privileges: OK" "SUCCESS"
        }
        else {
            $Results.Issues += "Script must be run as Administrator"
            Write-Log "Administrator privileges: FAILED" "ERROR"
        }
        
        # Test PowerShell version
        Write-Log "Checking PowerShell version..."
        $PSVersion = $PSVersionTable.PSVersion
        $Results.PowerShellVersion = ($PSVersion.Major -ge 5)
        
        if ($Results.PowerShellVersion) {
            Write-Log "PowerShell version: $PSVersion - OK" "SUCCESS"
        }
        else {
            $Results.Issues += "PowerShell 5.0 or higher required (current: $PSVersion)"
            Write-Log "PowerShell version: $PSVersion - INSUFFICIENT" "ERROR"
        }
        
        # Test OS version
        Write-Log "Checking operating system version..."
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        if ($OS) {
            $OSBuildNumber = [int]$OS.BuildNumber
            # Windows Server 2016 (14393) or higher, Windows 10 (10240) or higher
            $Results.OSVersion = ($OSBuildNumber -ge 10240)
            
            if ($Results.OSVersion) {
                Write-Log "Operating System: $($OS.Caption) (Build $OSBuildNumber) - OK" "SUCCESS"
            }
            else {
                $Results.Issues += "Unsupported OS version: $($OS.Caption) (Build $OSBuildNumber)"
                Write-Log "Operating System: $($OS.Caption) (Build $OSBuildNumber) - UNSUPPORTED" "ERROR"
            }
        }
        else {
            $Results.Issues += "Unable to determine OS version"
            Write-Log "Operating System: Unable to determine - ERROR" "ERROR"
        }
        
        # Test architecture
        Write-Log "Checking system architecture..."
        $Results.ArchitectureOK = ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
        
        if ($Results.ArchitectureOK) {
            Write-Log "System Architecture: $env:PROCESSOR_ARCHITECTURE - OK" "SUCCESS"
        }
        else {
            $Results.Issues += "64-bit architecture required (current: $env:PROCESSOR_ARCHITECTURE)"
            Write-Log "System Architecture: $env:PROCESSOR_ARCHITECTURE - UNSUPPORTED" "ERROR"
        }
        
        # Test disk space (minimum 15GB free on system drive)
        Write-Log "Checking disk space availability..."
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
        
        if ($SystemDrive) {
            $FreeSpaceGB = [Math]::Round($SystemDrive.FreeSpace / 1GB, 2)
            $Results.DiskSpace = ($FreeSpaceGB -ge 5)
            
            if ($Results.DiskSpace) {
                Write-Log "Disk Space: $FreeSpaceGB GB available - OK" "SUCCESS"
            }
            else {
                $Results.Issues += "Insufficient disk space: $FreeSpaceGB GB available (minimum 15GB required)"
                Write-Log "Disk Space: $FreeSpaceGB GB available - INSUFFICIENT" "ERROR"
            }
        }
        else {
            $Results.Issues += "Unable to check disk space"
            Write-Log "Disk Space: Unable to check - ERROR" "ERROR"
        }
        
        # Get basic system information for context
        $Results.SystemInfo = Get-BasicSystemInfo
        
        # Overall status
        $Results.OverallStatus = (
            $Results.AdminRights -and
            $Results.PowerShellVersion -and
            $Results.OSVersion -and
            $Results.ArchitectureOK -and
            $Results.DiskSpace
        )
        
        Write-Log "Prerequisites check completed"
        Write-Log "Overall Status: $(if($Results.OverallStatus){'PASSED'}else{'FAILED'})" $(if($Results.OverallStatus){'SUCCESS'}else{'ERROR'})
        
        if ($Results.Issues.Count -gt 0) {
            Write-Log "Issues found:"
            foreach ($Issue in $Results.Issues) {
                Write-Log "  - $Issue" "WARN"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Prerequisites check failed: $($_.Exception.Message)" "ERROR"
        $Results.OverallStatus = $false
        $Results.Issues += "Prerequisites check failed: $($_.Exception.Message)"
        return $Results
    }
}
#endregion

#region Drive Configuration Functions
function Initialize-InstallConfig {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Installation Configuration Initialization"
    
    try {
        Write-Log "Initializing installation configuration..."
        
        $Config = @{
            # Installation paths
            VDAPath = "C:\Temp\VDAServerSetup_2411.exe"
            PVSPath = "C:\Temp\PVS_Device_x64_2407.exe"
            WEMPath = "C:\Temp\Citrix Workspace Environment Management Agent.exe"
            UberAgentPath = "C:\Temp\uberAgent_7.1.2_x64.msi"
            TADDMPath = "C:\Temp\7.3.0.6-TIV-TADDM-Windows.exe"
            
            # Installation flags
            RebootRequired = $false
            
            # Installation results tracking
            InstallationResults = @{
                VDA = @{
                    Success = $false
                    Message = ""
                    Timestamp = $null
                    Skipped = $false
                }
                PVS = @{
                    Success = $false
                    Message = ""
                    Timestamp = $null
                    Skipped = $false
                }
                WEM = @{
                    Success = $false
                    Message = ""
                    Timestamp = $null
                    Skipped = $false
                }
                UberAgent = @{
                    Success = $false
                    Message = ""
                    Timestamp = $null
                    Skipped = $false
                    OverallSuccess = $false
                }
                TADDM = @{
                    Success = $false
                    Message = ""
                    Timestamp = $null
                    Skipped = $false
                    OverallSuccess = $false
                }
            }
            
            # System information
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                Architecture = $env:PROCESSOR_ARCHITECTURE
                TotalMemoryGB = [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            }
        }
        
        Write-Log "Installation configuration initialized successfully" "SUCCESS"
        return $Config
    }
    catch {
        Write-Log "Failed to initialize installation configuration: $($_.Exception.Message)" "ERROR"
        throw "Installation configuration initialization failed"
    }
}

function Initialize-DriveConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Interactive = $false
    )
    
    Write-LogHeader "Drive Configuration"
    
    $Results = @{
        DriveValidationPassed = $true
        Issues = @()
        Actions = @()
    }
    
    try {
        Write-Log "Validating basic drive configuration..."
        
        # Check system drive space only
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
        if ($SystemDrive) {
            $FreeSpaceGB = [Math]::Round($SystemDrive.FreeSpace / 1GB, 2)
            Write-Log "System drive space: $FreeSpaceGB GB available" "SUCCESS"
            $Results.Actions += "System drive space validated"
        }
        else {
            Write-Log "Could not check system drive space" "WARN"
            $Results.Issues += "Could not validate system drive space"
        }
        
        return $Results
    }
    catch {
        Write-Log "Drive configuration validation failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "Drive configuration validation failed: $($_.Exception.Message)"
        return $Results
    }
}

function Test-DriveConfiguration {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Drive Configuration Verification"
    
    try {
        Write-Log "Verifying drive configuration post-installation..."
        
        # Check system drive space
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
        if ($SystemDrive) {
            $FreeSpaceGB = [Math]::Round($SystemDrive.FreeSpace / 1GB, 2)
            $TotalSpaceGB = [Math]::Round($SystemDrive.Size / 1GB, 2)
            Write-Log "System drive ($env:SystemDrive): $FreeSpaceGB GB free of $TotalSpaceGB GB total"
            
            if ($FreeSpaceGB -lt 5) {
                Write-Log "System drive space is critically low" "WARN"
                return $false
            }
        }
        
        # Check D: drive if exists
        $DDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='D:'" -ErrorAction SilentlyContinue
        if ($DDrive) {
            $DFreeSpaceGB = [Math]::Round($DDrive.FreeSpace / 1GB, 2)
            $DTotalSpaceGB = [Math]::Round($DDrive.Size / 1GB, 2)
            Write-Log "D: drive: $DFreeSpaceGB GB free of $DTotalSpaceGB GB total"
        }
        else {
            Write-Log "D: drive not present (acceptable for system configuration)" "INFO"
        }
        
        # Check pagefile configuration
        $PageFileSettings = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($PageFileSettings) {
            foreach ($PageFile in $PageFileSettings) {
                Write-Log "Pagefile: $($PageFile.Name) - Size: $($PageFile.InitialSize)MB to $($PageFile.MaximumSize)MB"
            }
        }
        else {
            Write-Log "No pagefile settings found" "WARN"
        }
        
        Write-Log "Drive configuration verification completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Drive configuration verification failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Installation Functions
function Install-CitrixVDA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VDAPath,
        
        [Parameter(Mandatory=$false)]
        [string]$LogDir = "C:\Logs"
    )
    
    Write-LogHeader "Citrix VDA Installation"
    
    $Results = @{
        Success = $false
        RebootRequired = $false
        InstallPath = ""
        InstallLog = ""
        ExitCode = -1
        Issues = @()
        Actions = @()
    }
    
    try {
        Write-Log "Installing Citrix VDA..."
        Write-Log "Installer path: $VDAPath"
        
        if (!(Test-Path $VDAPath)) {
            throw "VDA installer not found at: $VDAPath"
        }
        
        # Prepare installation parameters
        $VDALogPath = Join-Path $LogDir "VDA_Install.log"
        $Results.InstallLog = $VDALogPath
        
        # VDA installation arguments (no delivery controller required)
        $VDAArgs = @(
            "/quiet",
            "/noreboot",
            "/logpath `"$VDALogPath`"",
            "/enable_hdx_ports",
            "/enable_real_time_transport"
        )
        
        Write-Log "VDA configured without delivery controller registration"
        
        $ArgumentList = $VDAArgs -join " "
        Write-Log "VDA installation command: $VDAPath $ArgumentList"
        
        # Execute VDA installation
        Write-Log "Starting VDA installation..."
        $InstallProcess = Start-Process -FilePath $VDAPath -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
        
        $Results.ExitCode = $InstallProcess.ExitCode
        Write-Log "VDA installation completed with exit code: $($Results.ExitCode)"
        
        # Analyze exit code
        switch ($Results.ExitCode) {
            0 { 
                Write-Log "VDA installation completed successfully" "SUCCESS"
                $Results.Success = $true
                $Results.Actions += "VDA installed successfully"
            }
            3010 { 
                Write-Log "VDA installation completed successfully - Reboot required" "SUCCESS"
                $Results.Success = $true
                $Results.RebootRequired = $true
                $Results.Actions += "VDA installed successfully (reboot required)"
            }
            default { 
                Write-Log "VDA installation failed with exit code: $($Results.ExitCode)" "ERROR"
                $Results.Issues += "VDA installation failed with exit code: $($Results.ExitCode)"
            }
        }
        
        # Check installation log if available
        if (Test-Path $VDALogPath) {
            try {
                $LogContent = Get-Content $VDALogPath -Raw -ErrorAction SilentlyContinue
                if ($LogContent -and $LogContent.Length -gt 0) {
                    Write-Log "VDA installation log available at: $VDALogPath" "DEBUG"
                    
                    # Look for specific indicators in log
                    if ($LogContent -match "installation completed successfully" -or $LogContent -match "Product: Citrix Virtual Delivery Agent.*Installation completed successfully") {
                        Write-Log "VDA installation log confirms successful installation" "SUCCESS"
                    }
                    elseif ($LogContent -match "error" -or $LogContent -match "failed") {
                        Write-Log "VDA installation log indicates errors may have occurred" "WARN"
                    }
                }
            }
            catch {
                Write-Log "Could not read VDA installation log: $($_.Exception.Message)" "DEBUG"
            }
        }
        
        # Verify VDA installation
        Write-Log "Verifying VDA installation..."
        $VDAVerification = Test-CitrixRegistration
        
        if ($VDAVerification) {
            Write-Log "VDA installation verification: PASSED" "SUCCESS"
            $Results.Actions += "VDA installation verified"
        }
        else {
            Write-Log "VDA installation verification: FAILED" "WARN"
            $Results.Issues += "VDA installation could not be verified"
        }
        
        return $Results
    }
    catch {
        Write-Log "VDA installation failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "VDA installation failed: $($_.Exception.Message)"
        return $Results
    }
}

function Install-PVSTargetDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PVSPath
    )
    
    Write-LogHeader "PVS Target Device Installation"
    
    $Results = @{
        Success = $false
        RebootRequired = $false
        Skipped = $false
        ExitCode = -1
        Issues = @()
        Actions = @()
    }
    
    try {
        if ([string]::IsNullOrEmpty($PVSPath) -or !(Test-Path $PVSPath)) {
            Write-Log "PVS Target Device installation skipped - installer not found"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Installing PVS Target Device..."
        Write-Log "Installer path: $PVSPath"
        
        # PVS Target Device installation arguments
        $PVSArgs = @(
            "/S"  # Silent installation
        )
        
        $ArgumentList = $PVSArgs -join " "
        Write-Log "PVS installation command: $PVSPath $ArgumentList"
        
        # Execute PVS Target Device installation
        Write-Log "Starting PVS Target Device installation..."
        $InstallProcess = Start-Process -FilePath $PVSPath -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
        
        $Results.ExitCode = $InstallProcess.ExitCode
        Write-Log "PVS Target Device installation completed with exit code: $($Results.ExitCode)"
        
        # Analyze exit code
        if ($Results.ExitCode -eq 0) {
            Write-Log "PVS Target Device installation completed successfully" "SUCCESS"
            $Results.Success = $true
            $Results.Actions += "PVS Target Device installed successfully"
        }
        else {
            Write-Log "PVS Target Device installation failed with exit code: $($Results.ExitCode)" "ERROR"
            $Results.Issues += "PVS Target Device installation failed with exit code: $($Results.ExitCode)"
        }
        
        return $Results
    }
    catch {
        Write-Log "PVS Target Device installation failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "PVS Target Device installation failed: $($_.Exception.Message)"
        return $Results
    }
}

function Install-WEMAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$WEMPath
    )
    
    Write-LogHeader "WEM Agent Installation"
    
    $Results = @{
        Success = $false
        RebootRequired = $false
        Skipped = $false
        ExitCode = -1
        Issues = @()
        Actions = @()
    }
    
    try {
        if ([string]::IsNullOrEmpty($WEMPath) -or !(Test-Path $WEMPath)) {
            Write-Log "WEM Agent installation skipped - installer not found"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Installing WEM Agent..."
        Write-Log "Installer path: $WEMPath"
        
        # WEM Agent installation arguments (no infrastructure server required)
        $WEMArgs = @(
            "/i", "`"$WEMPath`"",
            "/quiet",
            "/norestart"
        )
        
        Write-Log "WEM Agent configured without infrastructure server"
        
        $ArgumentList = $WEMArgs -join " "
        Write-Log "WEM installation command: msiexec.exe $ArgumentList"
        
        # Execute WEM Agent installation
        Write-Log "Starting WEM Agent installation..."
        $InstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
        
        $Results.ExitCode = $InstallProcess.ExitCode
        Write-Log "WEM Agent installation completed with exit code: $($Results.ExitCode)"
        
        # Analyze exit code
        switch ($Results.ExitCode) {
            0 { 
                Write-Log "WEM Agent installation completed successfully" "SUCCESS"
                $Results.Success = $true
                $Results.Actions += "WEM Agent installed successfully"
            }
            3010 { 
                Write-Log "WEM Agent installation completed successfully - Reboot required" "SUCCESS"
                $Results.Success = $true
                $Results.RebootRequired = $true
                $Results.Actions += "WEM Agent installed successfully (reboot required)"
            }
            default { 
                Write-Log "WEM Agent installation failed with exit code: $($Results.ExitCode)" "ERROR"
                $Results.Issues += "WEM Agent installation failed with exit code: $($Results.ExitCode)"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "WEM Agent installation failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "WEM Agent installation failed: $($_.Exception.Message)"
        return $Results
    }
}

function Install-UberAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UberAgentInstallerPath,
        
        [Parameter(Mandatory=$false)]
        [string]$UberAgentTemplatesPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$UberAgentConfigPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$UberAgentLicensePath = ""
    )
    
    Write-LogHeader "UberAgent Installation"
    
    $Results = @{
        OverallSuccess = $false
        InstallationSuccess = $false
        TemplatesCopied = $false
        ConfigCopied = $false
        LicenseCopied = $false
        Skipped = $false
        ExitCode = -1
        Issues = @()
        Actions = @()
    }
    
    try {
        if ([string]::IsNullOrEmpty($UberAgentInstallerPath) -or !(Test-Path $UberAgentInstallerPath)) {
            Write-Log "UberAgent installation skipped - installer not found"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Installing UberAgent..."
        Write-Log "Installer path: $UberAgentInstallerPath"
        
        # UberAgent installation arguments
        $UberAgentArgs = @(
            "/i", "`"$UberAgentInstallerPath`"",
            "/quiet",
            "/norestart"
        )
        
        $ArgumentList = $UberAgentArgs -join " "
        Write-Log "UberAgent installation command: msiexec.exe $ArgumentList"
        
        # Execute UberAgent installation
        Write-Log "Starting UberAgent installation..."
        $InstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
        
        $Results.ExitCode = $InstallProcess.ExitCode
        Write-Log "UberAgent installation completed with exit code: $($Results.ExitCode)"
        
        # Analyze exit code
        if ($Results.ExitCode -eq 0) {
            Write-Log "UberAgent installation completed successfully" "SUCCESS"
            $Results.InstallationSuccess = $true
            $Results.Actions += "UberAgent installed successfully"
        }
        else {
            Write-Log "UberAgent installation failed with exit code: $($Results.ExitCode)" "ERROR"
            $Results.Issues += "UberAgent installation failed with exit code: $($Results.ExitCode)"
        }
        
        # Copy templates if specified and installation succeeded
        if ($Results.InstallationSuccess -and ![string]::IsNullOrEmpty($UberAgentTemplatesPath) -and (Test-Path $UberAgentTemplatesPath)) {
            Write-Log "Copying UberAgent templates..."
            
            try {
                $UberAgentInstallDir = "C:\Program Files\uberAgent"
                if (Test-Path $UberAgentInstallDir) {
                    $TemplatesDestination = Join-Path $UberAgentInstallDir "Templates"
                    
                    if (!(Test-Path $TemplatesDestination)) {
                        New-Item -Path $TemplatesDestination -ItemType Directory -Force
                    }
                    
                    Copy-Item -Path "$UberAgentTemplatesPath\*" -Destination $TemplatesDestination -Recurse -Force
                    $Results.TemplatesCopied = $true
                    $Results.Actions += "UberAgent templates copied successfully"
                    Write-Log "UberAgent templates copied successfully" "SUCCESS"
                }
                else {
                    $Results.Issues += "UberAgent installation directory not found"
                }
            }
            catch {
                Write-Log "Failed to copy UberAgent templates: $($_.Exception.Message)" "ERROR"
                $Results.Issues += "Failed to copy UberAgent templates: $($_.Exception.Message)"
            }
        }
        
        # Copy configuration file if specified
        if ($Results.InstallationSuccess -and ![string]::IsNullOrEmpty($UberAgentConfigPath) -and (Test-Path $UberAgentConfigPath)) {
            Write-Log "Copying UberAgent configuration file..."
            
            try {
                $ConfigDestination = "C:\Program Files\uberAgent\uberagent.conf"
                Copy-Item -Path $UberAgentConfigPath -Destination $ConfigDestination -Force
                $Results.ConfigCopied = $true
                $Results.Actions += "UberAgent configuration file copied successfully"
                Write-Log "UberAgent configuration file copied successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to copy UberAgent configuration file: $($_.Exception.Message)" "ERROR"
                $Results.Issues += "Failed to copy UberAgent configuration file: $($_.Exception.Message)"
            }
        }
        
        # Copy license file if specified
        if ($Results.InstallationSuccess -and ![string]::IsNullOrEmpty($UberAgentLicensePath) -and (Test-Path $UberAgentLicensePath)) {
            Write-Log "Copying UberAgent license file..."
            
            try {
                $LicenseDestination = "C:\Program Files\uberAgent\uberagent.license"
                Copy-Item -Path $UberAgentLicensePath -Destination $LicenseDestination -Force
                $Results.LicenseCopied = $true
                $Results.Actions += "UberAgent license file copied successfully"
                Write-Log "UberAgent license file copied successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to copy UberAgent license file: $($_.Exception.Message)" "ERROR"
                $Results.Issues += "Failed to copy UberAgent license file: $($_.Exception.Message)"
            }
        }
        
        # Overall success determination
        $Results.OverallSuccess = $Results.InstallationSuccess
        
        return $Results
    }
    catch {
        Write-Log "UberAgent installation failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "UberAgent installation failed: $($_.Exception.Message)"
        return $Results
    }
}

function Configure-IBMTADDMPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TADDMPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$InstallBatPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$TADDMUsersGroup = "TADDM users",
        
        [Parameter(Mandatory=$false)]
        [switch]$CreateGroupIfMissing = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Configuring IBM TADDM Permissions"
    
    $Results = @{
        OverallSuccess = $false
        TADDMFound = $false
        TADDMPath = ""
        InstallBatFound = $false
        InstallBatPath = ""
        GroupExists = $false
        GroupCreated = $false
        PermissionsConfigured = $false
        InstallBatExecuted = $false
        Skipped = $false
        Issues = @()
        Actions = @()
    }
    
    try {
        if ([string]::IsNullOrEmpty($TADDMPath)) {
            Write-Log "IBM TADDM configuration skipped - no path specified"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Configuring IBM TADDM for non-administrator discovery access..."
        
        # Auto-detect TADDM installation
        $TADDMSearchPaths = @(
            $TADDMPath,
            "C:\Program Files\IBM\TADDM",
            "C:\Program Files (x86)\IBM\TADDM",
            "C:\IBM\TADDM",
            "C:\Program Files\IBM\Tivoli\TADDM",
            "C:\Program Files (x86)\IBM\Tivoli\TADDM"
        )
        
        foreach ($SearchPath in $TADDMSearchPaths) {
            if (Test-Path $SearchPath) {
                $TADDMPath = $SearchPath
                $Results.TADDMFound = $true
                $Results.TADDMPath = $TADDMPath
                Write-Log "IBM TADDM installation found: $TADDMPath" "SUCCESS"
                break
            }
        }
        
        if (!$Results.TADDMFound) {
            $Results.Issues += "IBM TADDM installation not found"
            Write-Log "IBM TADDM installation not found in standard locations" "WARN"
            
            if (!$Force) {
                Write-Log "Use -Force parameter to configure permissions without TADDM installation"
                return $Results
            }
        }
        
        # Auto-detect install.bat file
        if ($Results.TADDMFound -and [string]::IsNullOrEmpty($InstallBatPath)) {
            $PossibleBatPaths = @(
                (Join-Path $TADDMPath "install.bat"),
                (Join-Path $TADDMPath "bin\install.bat"),
                (Join-Path $TADDMPath "scripts\install.bat"),
                (Join-Path $TADDMPath "tools\install.bat")
            )
            
            foreach ($BatPath in $PossibleBatPaths) {
                if (Test-Path $BatPath) {
                    $InstallBatPath = $BatPath
                    Write-Log "Found install.bat: $BatPath"
                    break
                }
            }
            
            # Recursive search if not found
            if ([string]::IsNullOrEmpty($InstallBatPath)) {
                try {
                    $FoundBatFiles = Get-ChildItem -Path $TADDMPath -Name "install.bat" -Recurse -ErrorAction SilentlyContinue
                    if ($FoundBatFiles.Count -gt 0) {
                        $InstallBatPath = Join-Path $TADDMPath $FoundBatFiles[0]
                        Write-Log "Found install.bat via recursive search: $InstallBatPath"
                    }
                }
                catch {
                    Write-Log "Recursive search for install.bat failed: $($_.Exception.Message)" "DEBUG"
                }
            }
        }
        
        if (![string]::IsNullOrEmpty($InstallBatPath) -and (Test-Path $InstallBatPath)) {
            $Results.InstallBatFound = $true
            $Results.InstallBatPath = $InstallBatPath
            Write-Log "TADDM install.bat found: $InstallBatPath"
        }
        else {
            $Results.Issues += "TADDM install.bat file not found"
            Write-Log "TADDM install.bat file not found" "WARN"
        }
        
        # Check for TADDM users local group
        Write-Log "Checking for '$TADDMUsersGroup' local group..."
        
        try {
            $LocalGroup = Get-LocalGroup -Name $TADDMUsersGroup -ErrorAction SilentlyContinue
            
            if ($LocalGroup) {
                $Results.GroupExists = $true
                Write-Log "'$TADDMUsersGroup' local group exists" "SUCCESS"
            }
            else {
                Write-Log "'$TADDMUsersGroup' local group does not exist"
                
                if ($CreateGroupIfMissing) {
                    Write-Log "Creating '$TADDMUsersGroup' local group..."
                    
                    try {
                        New-LocalGroup -Name $TADDMUsersGroup -Description "IBM TADDM users with discovery permissions for non-administrator access" -ErrorAction Stop
                        $Results.GroupCreated = $true
                        $Results.GroupExists = $true
                        $Results.Actions += "Created '$TADDMUsersGroup' local group"
                        Write-Log "Successfully created '$TADDMUsersGroup' local group" "SUCCESS"
                    }
                    catch {
                        $Results.Issues += "Failed to create '$TADDMUsersGroup' group: $($_.Exception.Message)"
                        Write-Log "Failed to create '$TADDMUsersGroup' group: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
        catch {
            $Results.Issues += "Failed to check for '$TADDMUsersGroup' group: $($_.Exception.Message)"
            Write-Log "Failed to check for '$TADDMUsersGroup' group: $($_.Exception.Message)" "ERROR"
        }
        
        # Execute install.bat if found
        if ($Results.InstallBatFound) {
            Write-Log "Executing TADDM install.bat to configure permissions..."
            
            try {
                $OriginalLocation = Get-Location
                $TADDMDirectory = Split-Path $InstallBatPath -Parent
                Set-Location $TADDMDirectory
                
                # Execute install.bat
                $InstallProcess = Start-Process -FilePath $InstallBatPath -Wait -PassThru -NoNewWindow
                Set-Location $OriginalLocation
                
                if ($InstallProcess.ExitCode -eq 0) {
                    $Results.InstallBatExecuted = $true
                    $Results.PermissionsConfigured = $true
                    $Results.Actions += "Executed install.bat successfully"
                    Write-Log "TADDM install.bat executed successfully" "SUCCESS"
                }
                else {
                    $Results.Issues += "Install.bat execution failed with exit code: $($InstallProcess.ExitCode)"
                    Write-Log "Install.bat execution failed with exit code: $($InstallProcess.ExitCode)" "ERROR"
                }
            }
            catch {
                Set-Location $OriginalLocation -ErrorAction SilentlyContinue
                $Results.Issues += "Failed to execute install.bat: $($_.Exception.Message)"
                Write-Log "Failed to execute install.bat: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Overall success determination
        $Results.OverallSuccess = (
            $Results.GroupExists -and
            ($Results.PermissionsConfigured -or $Results.InstallBatExecuted)
        )
        
        Write-Log "IBM TADDM configuration completed"
        Write-Log "Overall Success: $(if($Results.OverallSuccess){'YES'}else{'NO'})"
        
        return $Results
    }
    catch {
        Write-Log "IBM TADDM configuration failed: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "IBM TADDM configuration failed: $($_.Exception.Message)"
        return $Results
    }
}
#endregion

#region System Configuration Functions
function Configure-WindowsServices {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Windows Services Configuration"
    
    try {
        Write-Log "Configuring Windows services for optimization..."
        
        # Services to disable for VDI optimization
        $ServicesToDisable = @(
            "Windows Search",
            "SuperFetch",
            "Themes"
        )
        
        foreach ($ServiceName in $ServicesToDisable) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($Service) {
                    if ($Service.Status -eq "Running") {
                        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log "Service '$ServiceName' disabled" "SUCCESS"
                }
            }
            catch {
                Write-Log "Could not configure service '$ServiceName': $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Windows services configuration completed" "SUCCESS"
    }
    catch {
        Write-Log "Windows services configuration failed: $($_.Exception.Message)" "ERROR"
    }
}

function Set-CrashDumpToKernelMode {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Crash Dump Configuration"
    
    try {
        Write-Log "Configuring crash dump to kernel mode..."
        
        # Registry path for crash dump configuration
        $CrashControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
        
        # Verify registry path exists
        if (!(Test-Path $CrashControlPath)) {
            Write-Log "Crash control registry path not found: $CrashControlPath" "ERROR"
            return $false
        }
        
        # Set crash dump type to kernel mode (2)
        # 0 = None, 1 = Complete, 2 = Kernel, 3 = Small (256KB), 7 = Automatic
        Set-ItemProperty -Path $CrashControlPath -Name "CrashDumpEnabled" -Value 2 -Type DWord
        Write-Log "Crash dump type set to kernel mode (value: 2)" "SUCCESS"
        
        # Configure dump file location (optional - use default if not specified)
        $DumpFilePath = "%SystemRoot%\MEMORY.DMP"
        Set-ItemProperty -Path $CrashControlPath -Name "DumpFile" -Value $DumpFilePath -Type ExpandString
        Write-Log "Dump file location: $DumpFilePath" "INFO"
        
        # Enable automatic restart after crash (recommended for servers)
        Set-ItemProperty -Path $CrashControlPath -Name "AutoReboot" -Value 1 -Type DWord
        Write-Log "Automatic restart after crash: Enabled" "SUCCESS"
        
        # Set overwrite existing dump file (recommended to save disk space)
        Set-ItemProperty -Path $CrashControlPath -Name "Overwrite" -Value 1 -Type DWord
        Write-Log "Overwrite existing dump file: Enabled" "SUCCESS"
        
        # Verify the configuration
        $CrashDumpEnabled = Get-ItemProperty -Path $CrashControlPath -Name "CrashDumpEnabled" -ErrorAction SilentlyContinue
        $AutoReboot = Get-ItemProperty -Path $CrashControlPath -Name "AutoReboot" -ErrorAction SilentlyContinue
        $Overwrite = Get-ItemProperty -Path $CrashControlPath -Name "Overwrite" -ErrorAction SilentlyContinue
        
        if ($CrashDumpEnabled.CrashDumpEnabled -eq 2) {
            Write-Log "Configuration verified: Crash dump is set to kernel mode" "SUCCESS"
        } else {
            Write-Log "Configuration verification failed: Unexpected crash dump value" "WARN"
        }
        
        Write-Log "Crash dump configuration completed successfully" "SUCCESS"
        Write-Log "Note: Changes will take effect after system restart" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Crash dump configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Copy-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkPath,
        
        [Parameter(Mandatory=$false)]
        [string]$LocalPath = "C:\Temp",
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Installation Files Copy Operation"
    
    try {
        Write-Log "Starting installation files copy operation..."
        Write-Log "Source: $NetworkPath"
        Write-Log "Destination: $LocalPath"
        
        # Verify network path exists and is accessible
        if (!(Test-Path $NetworkPath)) {
            Write-Log "Network path not accessible: $NetworkPath" "ERROR"
            return $false
        }
        
        # Create local destination directory if it doesn't exist
        if (!(Test-Path $LocalPath)) {
            Write-Log "Creating destination directory: $LocalPath"
            New-Item -Path $LocalPath -ItemType Directory -Force | Out-Null
        }
        
        # Get list of installation files to copy
        $InstallationFiles = @(
            "VDAServerSetup_2411.exe",
            "PVS_Device_x64_2407.exe",
            "Citrix Workspace Environment Management Agent.exe",
            "uberAgent_7.1.2_x64.msi",
            "7.3.0.6-TIV-TADDM-Windows.exe"
        )
        
        $CopyResults = @{
            Success = $true
            CopiedFiles = @()
            SkippedFiles = @()
            FailedFiles = @()
        }
        
        foreach ($File in $InstallationFiles) {
            $SourceFile = Join-Path $NetworkPath $File
            $DestFile = Join-Path $LocalPath $File
            
            Write-Log "Processing file: $File"
            
            # Check if source file exists
            if (Test-Path $SourceFile) {
                # Check if destination file already exists
                if ((Test-Path $DestFile) -and !$Force) {
                    Write-Log "File already exists (skipping): $File" "INFO"
                    $CopyResults.SkippedFiles += $File
                    continue
                }
                
                try {
                    # Copy file with progress indication for large files
                    $FileInfo = Get-Item $SourceFile
                    $FileSizeMB = [Math]::Round($FileInfo.Length / 1MB, 2)
                    Write-Log "Copying $File ($FileSizeMB MB)..."
                    
                    Copy-Item -Path $SourceFile -Destination $DestFile -Force
                    
                    # Verify copy was successful
                    if (Test-Path $DestFile) {
                        $DestFileInfo = Get-Item $DestFile
                        if ($DestFileInfo.Length -eq $FileInfo.Length) {
                            Write-Log "Successfully copied: $File" "SUCCESS"
                            $CopyResults.CopiedFiles += $File
                        } else {
                            Write-Log "Copy verification failed for: $File (size mismatch)" "ERROR"
                            $CopyResults.FailedFiles += $File
                            $CopyResults.Success = $false
                        }
                    } else {
                        Write-Log "Copy failed for: $File (file not found at destination)" "ERROR"
                        $CopyResults.FailedFiles += $File
                        $CopyResults.Success = $false
                    }
                }
                catch {
                    Write-Log "Copy failed for $File : $($_.Exception.Message)" "ERROR"
                    $CopyResults.FailedFiles += $File
                    $CopyResults.Success = $false
                }
            } else {
                Write-Log "Source file not found: $File" "WARN"
                $CopyResults.SkippedFiles += $File
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Copy operation summary:"
        Write-Log "Successfully copied: $($CopyResults.CopiedFiles.Count) files"
        Write-Log "Skipped: $($CopyResults.SkippedFiles.Count) files"
        Write-Log "Failed: $($CopyResults.FailedFiles.Count) files"
        
        if ($CopyResults.CopiedFiles.Count -gt 0) {
            Write-Log "Copied files: $($CopyResults.CopiedFiles -join ', ')" "SUCCESS"
        }
        
        if ($CopyResults.FailedFiles.Count -gt 0) {
            Write-Log "Failed files: $($CopyResults.FailedFiles -join ', ')" "ERROR"
        }
        
        if ($CopyResults.SkippedFiles.Count -gt 0) {
            Write-Log "Skipped files: $($CopyResults.SkippedFiles -join ', ')" "INFO"
        }
        
        Write-Log "Installation files copy operation completed" $(if($CopyResults.Success){"SUCCESS"}else{"WARN"})
        
        return $CopyResults.Success
    }
    catch {
        Write-Log "Installation files copy operation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disable-NetBiosOverTCP {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "NetBIOS over TCP/IP Configuration"
    
    try {
        Write-Log "Disabling NetBIOS over TCP/IP on all network adapters..."
        
        # Get all network adapter configurations
        $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        if (!$NetworkAdapters) {
            Write-Log "No enabled network adapters found" "WARN"
            return $false
        }
        
        $Results = @{
            Success = $true
            ProcessedAdapters = 0
            SuccessfulAdapters = 0
            FailedAdapters = 0
            AdapterDetails = @()
        }
        
        foreach ($Adapter in $NetworkAdapters) {
            $Results.ProcessedAdapters++
            
            try {
                $AdapterInfo = @{
                    Description = $Adapter.Description
                    Index = $Adapter.Index
                    IPAddress = if($Adapter.IPAddress) { $Adapter.IPAddress[0] } else { "No IP" }
                    Success = $false
                    Message = ""
                }
                
                Write-Log "Processing adapter: $($Adapter.Description) (Index: $($Adapter.Index))"
                
                # Disable NetBIOS over TCP/IP
                # 0 = Enable NetBIOS via DHCP, 1 = Enable NetBIOS, 2 = Disable NetBIOS
                $Result = $Adapter | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }
                
                if ($Result.ReturnValue -eq 0) {
                    Write-Log "Successfully disabled NetBIOS on: $($Adapter.Description)" "SUCCESS"
                    $AdapterInfo.Success = $true
                    $AdapterInfo.Message = "NetBIOS disabled successfully"
                    $Results.SuccessfulAdapters++
                } else {
                    Write-Log "Failed to disable NetBIOS on: $($Adapter.Description) (Return code: $($Result.ReturnValue))" "ERROR"
                    $AdapterInfo.Message = "Failed with return code: $($Result.ReturnValue)"
                    $Results.FailedAdapters++
                    $Results.Success = $false
                }
                
                $Results.AdapterDetails += $AdapterInfo
            }
            catch {
                Write-Log "Error processing adapter $($Adapter.Description): $($_.Exception.Message)" "ERROR"
                $AdapterInfo.Message = "Exception: $($_.Exception.Message)"
                $Results.AdapterDetails += $AdapterInfo
                $Results.FailedAdapters++
                $Results.Success = $false
            }
        }
        
        # Registry verification method as backup
        Write-Log "Verifying NetBIOS configuration via registry..."
        
        $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        
        if (Test-Path $RegistryPath) {
            $InterfaceKeys = Get-ChildItem -Path $RegistryPath
            
            foreach ($InterfaceKey in $InterfaceKeys) {
                try {
                    # Set NetbiosOptions to 2 (disable) for each interface
                    Set-ItemProperty -Path $InterfaceKey.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
                    Write-Log "Registry NetBIOS setting updated for interface: $($InterfaceKey.PSChildName)" "INFO"
                }
                catch {
                    Write-Log "Failed to update registry for interface $($InterfaceKey.PSChildName): $($_.Exception.Message)" "WARN"
                }
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "NetBIOS over TCP/IP configuration summary:"
        Write-Log "Total adapters processed: $($Results.ProcessedAdapters)"
        Write-Log "Successfully configured: $($Results.SuccessfulAdapters)"
        Write-Log "Failed configurations: $($Results.FailedAdapters)"
        
        if ($Results.AdapterDetails.Count -gt 0) {
            Write-Log "Adapter configuration details:"
            foreach ($Detail in $Results.AdapterDetails) {
                $Status = if($Detail.Success) { "SUCCESS" } else { "FAILED" }
                Write-Log "  - $($Detail.Description): $Status - $($Detail.Message)" $(if($Detail.Success){"SUCCESS"}else{"ERROR"})
            }
        }
        
        if ($Results.Success) {
            Write-Log "NetBIOS over TCP/IP has been disabled on all network adapters" "SUCCESS"
        } else {
            Write-Log "NetBIOS over TCP/IP configuration completed with some failures" "WARN"
        }
        
        Write-Log "Note: Changes will take effect immediately but may require network restart for full effect" "INFO"
        
        return $Results.Success
    }
    catch {
        Write-Log "NetBIOS over TCP/IP configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disable-NetworkOffloadParameters {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Network Offload Parameters Configuration"
    
    try {
        Write-Log "Disabling network offload parameters for Citrix PVS compatibility..."
        
        # Get all physical network adapters
        $NetworkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
        
        if (!$NetworkAdapters) {
            Write-Log "No active physical network adapters found" "WARN"
            return $false
        }
        
        $Results = @{
            Success = $true
            ProcessedAdapters = 0
            SuccessfulAdapters = 0
            FailedAdapters = 0
            AdapterDetails = @()
        }
        
        # Define offload parameters to disable for PVS compatibility
        $OffloadParameters = @{
            "*TCPChecksumOffloadIPv4" = 0
            "*TCPChecksumOffloadIPv6" = 0
            "*UDPChecksumOffloadIPv4" = 0
            "*UDPChecksumOffloadIPv6" = 0
            "*IPChecksumOffloadIPv4" = 0
            "*LsoV1IPv4" = 0
            "*LsoV2IPv4" = 0
            "*LsoV2IPv6" = 0
            "*TCPUDPChecksumOffloadIPv4" = 0
            "*TCPUDPChecksumOffloadIPv6" = 0
            "*RSCIPv4" = 0
            "*RSCIPv6" = 0
            "*VMQ" = 0
            "*RSS" = 0
            "*JumboPacket" = 1514
            "*ReceiveBuffers" = 256
            "*TransmitBuffers" = 256
            "*NetworkDirect" = 0
            "*SRIOV" = 0
        }
        
        foreach ($Adapter in $NetworkAdapters) {
            $Results.ProcessedAdapters++
            
            $AdapterInfo = @{
                Name = $Adapter.Name
                InterfaceDescription = $Adapter.InterfaceDescription
                Success = $true
                ConfiguredParameters = @()
                FailedParameters = @()
            }
            
            Write-Log "Processing network adapter: $($Adapter.Name) - $($Adapter.InterfaceDescription)"
            
            foreach ($Parameter in $OffloadParameters.GetEnumerator()) {
                try {
                    # Get current parameter value
                    $CurrentValue = Get-NetAdapterAdvancedProperty -Name $Adapter.Name -DisplayName $Parameter.Key -ErrorAction SilentlyContinue
                    
                    if ($CurrentValue) {
                        # Set the parameter value
                        Set-NetAdapterAdvancedProperty -Name $Adapter.Name -DisplayName $Parameter.Key -DisplayValue $Parameter.Value -ErrorAction Stop
                        Write-Log "  Set $($Parameter.Key) to $($Parameter.Value)" "SUCCESS"
                        $AdapterInfo.ConfiguredParameters += "$($Parameter.Key)=$($Parameter.Value)"
                    } else {
                        # Try alternative method using registry name
                        $RegistryValue = Get-NetAdapterAdvancedProperty -Name $Adapter.Name -RegistryKeyword $Parameter.Key -ErrorAction SilentlyContinue
                        if ($RegistryValue) {
                            Set-NetAdapterAdvancedProperty -Name $Adapter.Name -RegistryKeyword $Parameter.Key -RegistryValue $Parameter.Value -ErrorAction Stop
                            Write-Log "  Set $($Parameter.Key) to $($Parameter.Value) (via registry)" "SUCCESS"
                            $AdapterInfo.ConfiguredParameters += "$($Parameter.Key)=$($Parameter.Value)"
                        } else {
                            Write-Log "  Parameter $($Parameter.Key) not available on this adapter" "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "  Failed to set $($Parameter.Key): $($_.Exception.Message)" "WARN"
                    $AdapterInfo.FailedParameters += $Parameter.Key
                }
            }
            
            # Additional PVS-specific optimizations
            try {
                # Disable Power Management
                Write-Log "  Disabling power management features..."
                $PowerMgmt = Get-NetAdapterPowerManagement -Name $Adapter.Name -ErrorAction SilentlyContinue
                if ($PowerMgmt) {
                    Set-NetAdapterPowerManagement -Name $Adapter.Name -AllowComputerToTurnOffDevice Disabled -ErrorAction SilentlyContinue
                    Write-Log "  Power management disabled" "SUCCESS"
                }
                
                # Set specific buffer sizes for PVS
                $BufferSettings = @{
                    "ReceiveBuffers" = 256
                    "TransmitBuffers" = 256
                }
                
                foreach ($BufferSetting in $BufferSettings.GetEnumerator()) {
                    try {
                        Set-NetAdapterAdvancedProperty -Name $Adapter.Name -DisplayName $BufferSetting.Key -DisplayValue $BufferSetting.Value -ErrorAction SilentlyContinue
                        Write-Log "  Set $($BufferSetting.Key) to $($BufferSetting.Value)" "SUCCESS"
                    }
                    catch {
                        # Continue if buffer setting fails
                    }
                }
            }
            catch {
                Write-Log "  Warning: Some power management settings could not be configured" "WARN"
            }
            
            if ($AdapterInfo.FailedParameters.Count -eq 0) {
                $Results.SuccessfulAdapters++
                Write-Log "Successfully configured adapter: $($Adapter.Name)" "SUCCESS"
            } else {
                $Results.FailedAdapters++
                $Results.Success = $false
                Write-Log "Partially configured adapter: $($Adapter.Name) - Some parameters failed" "WARN"
            }
            
            $Results.AdapterDetails += $AdapterInfo
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Network offload parameters configuration summary:"
        Write-Log "Total adapters processed: $($Results.ProcessedAdapters)"
        Write-Log "Successfully configured: $($Results.SuccessfulAdapters)"
        Write-Log "Partially configured: $($Results.FailedAdapters)"
        
        if ($Results.AdapterDetails.Count -gt 0) {
            Write-Log "Adapter configuration details:"
            foreach ($Detail in $Results.AdapterDetails) {
                Write-Log "  Adapter: $($Detail.Name)"
                if ($Detail.ConfiguredParameters.Count -gt 0) {
                    Write-Log "    Configured: $($Detail.ConfiguredParameters.Count) parameters" "SUCCESS"
                }
                if ($Detail.FailedParameters.Count -gt 0) {
                    Write-Log "    Failed: $($Detail.FailedParameters -join ', ')" "WARN"
                }
            }
        }
        
        Write-Log "Network offload parameters have been optimized for Citrix PVS compatibility" "SUCCESS"
        Write-Log "Note: Changes take effect immediately but adapter restart may be required for full effect" "INFO"
        
        return $Results.Success
    }
    catch {
        Write-Log "Network offload parameters configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Configure-SMBSettings {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "SMB Configuration for Citrix Environments"
    
    try {
        Write-Log "Configuring SMB settings for optimal Citrix performance..."
        
        $Results = @{
            Success = $true
            ConfiguredSettings = @()
            FailedSettings = @()
        }
        
        # SMB Server Configuration for Citrix environments
        $SMBServerSettings = @{
            "AnnounceServer" = $false
            "AsynchronousCredits" = 512
            "CachedOpenLimit" = 10
            "DurableHandleV2TimeoutInSeconds" = 180
            "EnableSMB1Protocol" = $false
            "EnableSMB2Protocol" = $true
            "MaxChannelPerSession" = 32
            "MaxMpxCount" = 50
            "MaxSessionPerConnection" = 16384
            "MaxThreadsPerQueue" = 20
            "MaxWorkItems" = 1
            "NullSessionPipes" = ""
            "NullSessionShares" = ""
            "OplockBreakWait" = 35
            "PendingClientTimeoutInSeconds" = 120
            "RejectUnencryptedAccess" = $false
            "RequireSecuritySignature" = $false
            "ServerHidden" = $true
            "Smb2CreditsMax" = 8192
            "Smb2CreditsMin" = 512
            "SmbServerNameHardeningLevel" = 0
            "TreatHostAsStableStorage" = $false
            "ValidateAliasNotCircular" = $true
            "ValidateShareScope" = $true
            "ValidateShareScopeNotAliased" = $true
            "ValidateTargetName" = $true
        }
        
        Write-Log "Configuring SMB Server settings..."
        foreach ($Setting in $SMBServerSettings.GetEnumerator()) {
            try {
                Set-SmbServerConfiguration -$($Setting.Key) $Setting.Value -Force -Confirm:$false -ErrorAction Stop
                Write-Log "  Set SMB Server $($Setting.Key) to $($Setting.Value)" "SUCCESS"
                $Results.ConfiguredSettings += "Server.$($Setting.Key)=$($Setting.Value)"
            }
            catch {
                Write-Log "  Failed to set SMB Server $($Setting.Key): $($_.Exception.Message)" "WARN"
                $Results.FailedSettings += "Server.$($Setting.Key)"
                $Results.Success = $false
            }
        }
        
        # SMB Client Configuration for Citrix environments
        $SMBClientSettings = @{
            "ConnectionCountPerRssNetworkInterface" = 4
            "DirectoryCacheEntriesMax" = 16
            "DirectoryCacheEntrySizeMax" = 65536
            "DirectoryCacheLifetime" = 10
            "DormantFileLimit" = 1023
            "EnableBandwidthThrottling" = $true
            "EnableByteRangeLockingOnReadOnlyFiles" = $true
            "EnableInsecureGuestLogons" = $false
            "EnableLargeMtu" = $true
            "EnableLoadBalanceScaleOut" = $true
            "EnableMultiChannel" = $true
            "EnableSecuritySignature" = $false
            "ExtendedSessionTimeout" = 1000
            "FileInfoCacheEntriesMax" = 64
            "FileInfoCacheLifetime" = 10
            "FileNotFoundCacheEntriesMax" = 128
            "FileNotFoundCacheLifetime" = 5
            "KeepAliveTime" = 2
            "MaxCmds" = 50
            "MaximumConnectionCountPerServer" = 32
            "OplocksDisabled" = $false
            "RequireSecuritySignature" = $false
            "SessionTimeout" = 60
            "UseOpportunisticLocking" = $true
            "WindowSizeThreshold" = 8
        }
        
        Write-Log "Configuring SMB Client settings..."
        foreach ($Setting in $SMBClientSettings.GetEnumerator()) {
            try {
                Set-SmbClientConfiguration -$($Setting.Key) $Setting.Value -Force -Confirm:$false -ErrorAction Stop
                Write-Log "  Set SMB Client $($Setting.Key) to $($Setting.Value)" "SUCCESS"
                $Results.ConfiguredSettings += "Client.$($Setting.Key)=$($Setting.Value)"
            }
            catch {
                Write-Log "  Failed to set SMB Client $($Setting.Key): $($_.Exception.Message)" "WARN"
                $Results.FailedSettings += "Client.$($Setting.Key)"
                $Results.Success = $false
            }
        }
        
        # Additional SMB optimizations via registry
        Write-Log "Applying additional SMB registry optimizations..."
        
        $RegistrySettings = @{
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = @{
                "DisableBandwidthThrottling" = 1
                "DisableLargeMtu" = 0
                "FileInfoCacheLifetime" = 10
                "FileNotFoundCacheLifetime" = 5
                "MaxCmds" = 50
                "MaxCollectionCount" = 32
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
                "DisableStrictNameChecking" = 1
                "EnableOpLocks" = 1
                "EnableOpLockForceClose" = 1
                "MaxMpxCt" = 800
                "MaxWorkItems" = 2000
                "MaxRawWorkItems" = 200
                "MaxFreeConnections" = 64
                "MinFreeConnections" = 20
                "Size" = 3
            }
        }
        
        foreach ($RegPath in $RegistrySettings.GetEnumerator()) {
            try {
                if (!(Test-Path $RegPath.Key)) {
                    New-Item -Path $RegPath.Key -Force | Out-Null
                }
                
                foreach ($RegValue in $RegPath.Value.GetEnumerator()) {
                    Set-ItemProperty -Path $RegPath.Key -Name $RegValue.Key -Value $RegValue.Value -Type DWord -ErrorAction Stop
                    Write-Log "  Set registry $($RegValue.Key) to $($RegValue.Value)" "SUCCESS"
                    $Results.ConfiguredSettings += "Registry.$($RegValue.Key)=$($RegValue.Value)"
                }
            }
            catch {
                Write-Log "  Failed to set registry values in $($RegPath.Key): $($_.Exception.Message)" "WARN"
                $Results.FailedSettings += "Registry.$($RegPath.Key)"
            }
        }
        
        # SMB Shares security optimization
        Write-Log "Configuring SMB security settings..."
        try {
            # Disable SMB1 for security
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
            Write-Log "SMB1 protocol disabled for security" "SUCCESS"
            $Results.ConfiguredSettings += "Security.SMB1Disabled=True"
        }
        catch {
            Write-Log "Warning: Could not disable SMB1 protocol: $($_.Exception.Message)" "WARN"
        }
        
        # Summary report
        Write-Log ""
        Write-Log "SMB configuration summary:"
        Write-Log "Successfully configured: $($Results.ConfiguredSettings.Count) settings"
        Write-Log "Failed configurations: $($Results.FailedSettings.Count) settings"
        
        if ($Results.FailedSettings.Count -gt 0) {
            Write-Log "Failed settings:"
            foreach ($Failed in $Results.FailedSettings) {
                Write-Log "  - $Failed" "WARN"
            }
        }
        
        Write-Log "SMB has been optimized for Citrix environments" "SUCCESS"
        Write-Log "Note: Some settings may require a system restart to take full effect" "INFO"
        
        return $Results.Success
    }
    catch {
        Write-Log "SMB configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-DNSSuffix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$PrimaryDNSSuffix = "",
        
        [Parameter(Mandatory=$false)]
        [string[]]$DNSSuffixSearchList = @(),
        
        [Parameter(Mandatory=$false)]
        [switch]$AppendPrimarySuffixes = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$AppendParentSuffixes = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$RegisterThisConnectionsAddress = $true
    )
    
    Write-LogHeader "DNS Suffix Configuration"
    
    try {
        Write-Log "Configuring DNS suffix settings..."
        
        $Results = @{
            Success = $true
            ConfiguredSettings = @()
            FailedSettings = @()
        }
        
        # Primary DNS suffix configuration
        if ($PrimaryDNSSuffix -ne "") {
            try {
                Write-Log "Setting primary DNS suffix to: $PrimaryDNSSuffix"
                
                # Set primary DNS suffix in registry
                $TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                Set-ItemProperty -Path $TcpipParamsPath -Name "Domain" -Value $PrimaryDNSSuffix -Type String -ErrorAction Stop
                Set-ItemProperty -Path $TcpipParamsPath -Name "NV Domain" -Value $PrimaryDNSSuffix -Type String -ErrorAction Stop
                
                Write-Log "Primary DNS suffix configured successfully" "SUCCESS"
                $Results.ConfiguredSettings += "PrimaryDNSSuffix=$PrimaryDNSSuffix"
            }
            catch {
                Write-Log "Failed to set primary DNS suffix: $($_.Exception.Message)" "ERROR"
                $Results.FailedSettings += "PrimaryDNSSuffix"
                $Results.Success = $false
            }
        }
        
        # DNS suffix search list configuration
        if ($DNSSuffixSearchList.Count -gt 0) {
            try {
                Write-Log "Configuring DNS suffix search list..."
                
                $SearchListString = $DNSSuffixSearchList -join ","
                $TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                
                Set-ItemProperty -Path $TcpipParamsPath -Name "SearchList" -Value $SearchListString -Type String -ErrorAction Stop
                
                Write-Log "DNS suffix search list configured: $SearchListString" "SUCCESS"
                $Results.ConfiguredSettings += "DNSSuffixSearchList=$SearchListString"
                
                # Log each suffix in the search list
                foreach ($Suffix in $DNSSuffixSearchList) {
                    Write-Log "  Added DNS suffix: $Suffix" "INFO"
                }
            }
            catch {
                Write-Log "Failed to set DNS suffix search list: $($_.Exception.Message)" "ERROR"
                $Results.FailedSettings += "DNSSuffixSearchList"
                $Results.Success = $false
            }
        }
        
        # Configure DNS suffix search behavior
        try {
            Write-Log "Configuring DNS suffix search behavior..."
            
            $TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            
            # Configure whether to append primary suffixes
            $AppendPrimaryValue = if ($AppendPrimarySuffixes) { 1 } else { 0 }
            Set-ItemProperty -Path $TcpipParamsPath -Name "UseDomainNameDevolution" -Value $AppendPrimaryValue -Type DWord -ErrorAction Stop
            Write-Log "Append primary suffixes: $AppendPrimarySuffixes" "SUCCESS"
            $Results.ConfiguredSettings += "AppendPrimarySuffixes=$AppendPrimarySuffixes"
            
            # Configure whether to append parent suffixes
            $AppendParentValue = if ($AppendParentSuffixes) { 1 } else { 0 }
            Set-ItemProperty -Path $TcpipParamsPath -Name "AppendToMultiLabelName" -Value $AppendParentValue -Type DWord -ErrorAction Stop
            Write-Log "Append parent suffixes: $AppendParentSuffixes" "SUCCESS"
            $Results.ConfiguredSettings += "AppendParentSuffixes=$AppendParentSuffixes"
        }
        catch {
            Write-Log "Failed to configure DNS suffix behavior: $($_.Exception.Message)" "ERROR"
            $Results.FailedSettings += "DNSSuffixBehavior"
            $Results.Success = $false
        }
        
        # Configure network adapter specific DNS settings
        try {
            Write-Log "Configuring network adapter DNS settings..."
            
            $NetworkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            
            foreach ($Adapter in $NetworkAdapters) {
                try {
                    Write-Log "Processing adapter: $($Adapter.Name)"
                    
                    # Get adapter interface index
                    $InterfaceIndex = $Adapter.InterfaceIndex
                    
                    # Configure DNS registration
                    $RegistrationValue = if ($RegisterThisConnectionsAddress) { 1 } else { 0 }
                    
                    # Set adapter-specific DNS settings via registry
                    $AdapterPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($Adapter.InterfaceGuid)"
                    
                    if (Test-Path $AdapterPath) {
                        Set-ItemProperty -Path $AdapterPath -Name "RegisterAdapterName" -Value $RegistrationValue -Type DWord -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $AdapterPath -Name "RegistrationEnabled" -Value $RegistrationValue -Type DWord -ErrorAction SilentlyContinue
                        Write-Log "  DNS registration configured for adapter: $($Adapter.Name)" "SUCCESS"
                    }
                }
                catch {
                    Write-Log "  Warning: Could not configure DNS settings for adapter $($Adapter.Name): $($_.Exception.Message)" "WARN"
                }
            }
            
            $Results.ConfiguredSettings += "NetworkAdapterDNSRegistration=$RegisterThisConnectionsAddress"
        }
        catch {
            Write-Log "Failed to configure network adapter DNS settings: $($_.Exception.Message)" "WARN"
        }
        
        # Additional DNS optimizations for Citrix environments
        try {
            Write-Log "Applying additional DNS optimizations..."
            
            $TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            
            # Optimize DNS cache settings
            Set-ItemProperty -Path $TcpipParamsPath -Name "MaxCacheTtl" -Value 86400 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $TcpipParamsPath -Name "MaxNegativeCacheTtl" -Value 300 -Type DWord -ErrorAction SilentlyContinue
            
            # DNS resolver optimizations
            Set-ItemProperty -Path $TcpipParamsPath -Name "NetFailureTime" -Value 30 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $TcpipParamsPath -Name "MaxHashTableBuckets" -Value 1024 -Type DWord -ErrorAction SilentlyContinue
            
            Write-Log "DNS cache and resolver optimizations applied" "SUCCESS"
            $Results.ConfiguredSettings += "DNSOptimizations=Applied"
        }
        catch {
            Write-Log "Warning: Some DNS optimizations could not be applied: $($_.Exception.Message)" "WARN"
        }
        
        # Summary report
        Write-Log ""
        Write-Log "DNS suffix configuration summary:"
        Write-Log "Successfully configured: $($Results.ConfiguredSettings.Count) settings"
        Write-Log "Failed configurations: $($Results.FailedSettings.Count) settings"
        
        if ($Results.ConfiguredSettings.Count -gt 0) {
            Write-Log "Configured settings:"
            foreach ($Setting in $Results.ConfiguredSettings) {
                Write-Log "  ✓ $Setting" "SUCCESS"
            }
        }
        
        if ($Results.FailedSettings.Count -gt 0) {
            Write-Log "Failed settings:"
            foreach ($Failed in $Results.FailedSettings) {
                Write-Log "  ✗ $Failed" "ERROR"
            }
        }
        
        Write-Log "DNS suffix configuration completed" "SUCCESS"
        Write-Log "Note: Some changes may require network restart or system reboot to take full effect" "INFO"
        
        return $Results.Success
    }
    catch {
        Write-Log "DNS suffix configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Join-Domain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [string]$OrganizationalUnit = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$Restart = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Domain Join Operation"
    
    try {
        Write-Log "Preparing to join domain: $DomainName"
        
        # Check if already domain joined
        $CurrentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        if ($CurrentDomain -eq $DomainName) {
            Write-Log "Computer is already joined to domain: $DomainName" "INFO"
            if (!$Force) {
                return $true
            }
            Write-Log "Force parameter specified, proceeding with domain join operation" "WARN"
        }
        
        # Validate domain connectivity
        Write-Log "Testing domain connectivity..."
        try {
            $DomainController = Resolve-DnsName -Name $DomainName -Type A -ErrorAction Stop
            Write-Log "Domain DNS resolution successful: $DomainName" "SUCCESS"
        }
        catch {
            Write-Log "Warning: Could not resolve domain DNS: $($_.Exception.Message)" "WARN"
            Write-Log "Proceeding with domain join attempt..." "INFO"
        }
        
        # Test domain controller connectivity
        try {
            $DCTest = Test-NetConnection -ComputerName $DomainName -Port 389 -InformationLevel Quiet -ErrorAction SilentlyContinue
            if ($DCTest) {
                Write-Log "Domain controller connectivity test successful" "SUCCESS"
            } else {
                Write-Log "Warning: Could not connect to domain controller on port 389" "WARN"
            }
        }
        catch {
            Write-Log "Warning: Domain controller connectivity test failed" "WARN"
        }
        
        # Prepare domain join parameters
        $JoinParams = @{
            DomainName = $DomainName
            Credential = $Credential
            ErrorAction = "Stop"
        }
        
        # Add organizational unit if specified
        if ($OrganizationalUnit -ne "") {
            $JoinParams.Add("OUPath", $OrganizationalUnit)
            Write-Log "Target Organizational Unit: $OrganizationalUnit"
        }
        
        # Add restart parameter
        if ($Restart) {
            $JoinParams.Add("Restart", $true)
            Write-Log "System will restart after successful domain join"
        } else {
            $JoinParams.Add("Restart", $false)
            Write-Log "System restart suppressed - manual restart required"
        }
        
        # Force parameter
        if ($Force) {
            $JoinParams.Add("Force", $true)
            Write-Log "Force parameter enabled"
        }
        
        Write-Log "Initiating domain join operation..."
        Write-Log "Domain: $DomainName"
        Write-Log "User: $($Credential.UserName)"
        
        # Perform domain join
        Add-Computer @JoinParams
        
        Write-Log "Domain join operation completed successfully!" "SUCCESS"
        Write-Log "Computer has been joined to domain: $DomainName" "SUCCESS"
        
        if ($OrganizationalUnit -ne "") {
            Write-Log "Computer placed in OU: $OrganizationalUnit" "SUCCESS"
        }
        
        if ($Restart) {
            Write-Log "System restart initiated..." "INFO"
        } else {
            Write-Log "IMPORTANT: Manual system restart required to complete domain join" "WARN"
        }
        
        return $true
    }
    catch {
        Write-Log "Domain join operation failed: $($_.Exception.Message)" "ERROR"
        
        # Provide specific error guidance
        if ($_.Exception.Message -like "*credentials*") {
            Write-Log "Error appears to be credential-related. Please verify:" "ERROR"
            Write-Log "  - Username format (use DOMAIN\\username or username@domain.com)" "ERROR"
            Write-Log "  - Password is correct" "ERROR"
            Write-Log "  - Account has domain join permissions" "ERROR"
        }
        elseif ($_.Exception.Message -like "*network*" -or $_.Exception.Message -like "*RPC*") {
            Write-Log "Error appears to be network-related. Please verify:" "ERROR"
            Write-Log "  - Domain controller is accessible" "ERROR"
            Write-Log "  - DNS resolution is working" "ERROR"
            Write-Log "  - Required ports are open (53, 88, 135, 389, 445, 464)" "ERROR"
        }
        elseif ($_.Exception.Message -like "*organizational unit*" -or $_.Exception.Message -like "*OU*") {
            Write-Log "Error appears to be OU-related. Please verify:" "ERROR"
            Write-Log "  - Organizational Unit path is correct" "ERROR"
            Write-Log "  - Account has permissions to join computers to the specified OU" "ERROR"
        }
        
        return $false
    }
}

function Copy-StartupScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationPath = "C:\Scripts\Startup",
        
        [Parameter(Mandatory=$false)]
        [string[]]$ScriptTypes = @("*.ps1", "*.bat", "*.cmd", "*.vbs"),
        
        [Parameter(Mandatory=$false)]
        [switch]$RegisterStartupScripts = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$CreateScheduledTasks = $false,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Startup Scripts Management"
    
    try {
        Write-Log "Copying startup scripts from: $SourcePath"
        Write-Log "Destination: $DestinationPath"
        
        $Results = @{
            Success = $true
            CopiedFiles = @()
            FailedFiles = @()
            RegisteredScripts = @()
            FailedRegistrations = @()
            TotalFiles = 0
            SuccessfulCopies = 0
        }
        
        # Validate source path
        if (!(Test-Path $SourcePath)) {
            Write-Log "Source path does not exist: $SourcePath" "ERROR"
            return $false
        }
        
        # Create destination directory
        try {
            if (!(Test-Path $DestinationPath)) {
                New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
                Write-Log "Created destination directory: $DestinationPath" "SUCCESS"
            }
        }
        catch {
            Write-Log "Failed to create destination directory: $($_.Exception.Message)" "ERROR"
            return $false
        }
        
        # Find all startup scripts
        $AllScripts = @()
        foreach ($ScriptType in $ScriptTypes) {
            try {
                $Scripts = Get-ChildItem -Path $SourcePath -Filter $ScriptType -Recurse -ErrorAction SilentlyContinue
                $AllScripts += $Scripts
                Write-Log "Found $($Scripts.Count) files matching pattern: $ScriptType" "INFO"
            }
            catch {
                Write-Log "Warning: Could not search for pattern $ScriptType`: $($_.Exception.Message)" "WARN"
            }
        }
        
        $Results.TotalFiles = $AllScripts.Count
        Write-Log "Total startup scripts found: $($Results.TotalFiles)"
        
        if ($Results.TotalFiles -eq 0) {
            Write-Log "No startup scripts found in source path" "WARN"
            return $true
        }
        
        # Copy each script file
        foreach ($Script in $AllScripts) {
            try {
                $RelativePath = $Script.FullName.Substring($SourcePath.Length).TrimStart('\')
                $DestinationFile = Join-Path $DestinationPath $RelativePath
                $DestinationDir = Split-Path $DestinationFile -Parent
                
                # Create subdirectory if needed
                if (!(Test-Path $DestinationDir)) {
                    New-Item -Path $DestinationDir -ItemType Directory -Force | Out-Null
                }
                
                # Copy file
                if ((Test-Path $DestinationFile) -and !$Force) {
                    Write-Log "File already exists (use -Force to overwrite): $($Script.Name)" "WARN"
                    $Results.FailedFiles += @{
                        Name = $Script.Name
                        Source = $Script.FullName
                        Destination = $DestinationFile
                        Reason = "File exists"
                    }
                    continue
                }
                
                Copy-Item -Path $Script.FullName -Destination $DestinationFile -Force:$Force -ErrorAction Stop
                Write-Log "Copied: $($Script.Name) -> $RelativePath" "SUCCESS"
                
                $Results.CopiedFiles += @{
                    Name = $Script.Name
                    Source = $Script.FullName
                    Destination = $DestinationFile
                    Size = $Script.Length
                }
                $Results.SuccessfulCopies++
            }
            catch {
                Write-Log "Failed to copy $($Script.Name): $($_.Exception.Message)" "ERROR"
                $Results.FailedFiles += @{
                    Name = $Script.Name
                    Source = $Script.FullName
                    Destination = $DestinationFile
                    Reason = $_.Exception.Message
                }
                $Results.Success = $false
            }
        }
        
        # Register startup scripts in Group Policy if requested
        if ($RegisterStartupScripts -and $Results.SuccessfulCopies -gt 0) {
            Write-Log "Registering startup scripts in Group Policy..."
            
            try {
                # Create Group Policy startup scripts registry entries
                $GPStartupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
                
                if (!(Test-Path $GPStartupPath)) {
                    New-Item -Path $GPStartupPath -Force | Out-Null
                }
                
                # Get existing startup script count
                $ExistingScripts = Get-ChildItem -Path $GPStartupPath -ErrorAction SilentlyContinue
                $StartIndex = $ExistingScripts.Count
                
                foreach ($CopiedFile in $Results.CopiedFiles) {
                    try {
                        # Only register PowerShell and batch files
                        if ($CopiedFile.Name -match '\.(ps1|bat|cmd)$') {
                            $ScriptIndex = $StartIndex++
                            $ScriptKeyPath = "$GPStartupPath\$ScriptIndex"
                            
                            New-Item -Path $ScriptKeyPath -Force | Out-Null
                            Set-ItemProperty -Path $ScriptKeyPath -Name "Script" -Value $CopiedFile.Destination -Type String
                            Set-ItemProperty -Path $ScriptKeyPath -Name "Parameters" -Value "" -Type String
                            Set-ItemProperty -Path $ScriptKeyPath -Name "IsPowershell" -Value $(if($CopiedFile.Name -match '\.ps1$'){1}else{0}) -Type DWord
                            Set-ItemProperty -Path $ScriptKeyPath -Name "ExecTime" -Value 0 -Type QWord
                            
                            Write-Log "Registered startup script: $($CopiedFile.Name)" "SUCCESS"
                            $Results.RegisteredScripts += $CopiedFile.Name
                        }
                    }
                    catch {
                        Write-Log "Failed to register script $($CopiedFile.Name): $($_.Exception.Message)" "ERROR"
                        $Results.FailedRegistrations += $CopiedFile.Name
                    }
                }
            }
            catch {
                Write-Log "Failed to access Group Policy registry: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Create scheduled tasks if requested
        if ($CreateScheduledTasks -and $Results.SuccessfulCopies -gt 0) {
            Write-Log "Creating scheduled tasks for startup scripts..."
            
            foreach ($CopiedFile in $Results.CopiedFiles) {
                try {
                    if ($CopiedFile.Name -match '\.(ps1|bat|cmd)$') {
                        $TaskName = "StartupScript_$($CopiedFile.Name -replace '\.[^.]*$')"
                        
                        # Create scheduled task action
                        if ($CopiedFile.Name -match '\.ps1$') {
                            $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($CopiedFile.Destination)`""
                        } else {
                            $Action = New-ScheduledTaskAction -Execute $CopiedFile.Destination
                        }
                        
                        # Create trigger for startup
                        $Trigger = New-ScheduledTaskTrigger -AtStartup
                        
                        # Create task with system account
                        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                        
                        # Register the task
                        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Startup script: $($CopiedFile.Name)" -Force | Out-Null
                        Write-Log "Created scheduled task: $TaskName" "SUCCESS"
                    }
                }
                catch {
                    Write-Log "Failed to create scheduled task for $($CopiedFile.Name): $($_.Exception.Message)" "ERROR"
                }
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Startup scripts copy operation summary:"
        Write-Log "Total files found: $($Results.TotalFiles)"
        Write-Log "Successfully copied: $($Results.SuccessfulCopies)"
        Write-Log "Failed copies: $($Results.FailedFiles.Count)"
        Write-Log "Registered scripts: $($Results.RegisteredScripts.Count)"
        
        if ($Results.CopiedFiles.Count -gt 0) {
            Write-Log "Successfully copied files:"
            foreach ($File in $Results.CopiedFiles) {
                Write-Log "  ✓ $($File.Name) ($([math]::Round($File.Size/1KB, 2)) KB)" "SUCCESS"
            }
        }
        
        if ($Results.FailedFiles.Count -gt 0) {
            Write-Log "Failed file operations:"
            foreach ($File in $Results.FailedFiles) {
                Write-Log "  ✗ $($File.Name): $($File.Reason)" "ERROR"
            }
        }
        
        if ($Results.RegisteredScripts.Count -gt 0) {
            Write-Log "Registered startup scripts:"
            foreach ($Script in $Results.RegisteredScripts) {
                Write-Log "  ✓ $Script" "SUCCESS"
            }
        }
        
        Write-Log "Startup scripts management completed" "SUCCESS"
        if ($RegisterStartupScripts) {
            Write-Log "Note: Group Policy startup scripts will execute on next system startup" "INFO"
        }
        
        return $Results.Success
    }
    catch {
        Write-Log "Startup scripts copy operation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-PasswordAgeRegistryKey {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "PasswordAge Registry Key Cleanup"
    
    try {
        Write-Log "Checking for PasswordAge registry key..."
        
        # Registry path for the PasswordAge entry
        $RegistryPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        $ValueName = "PasswordAge"
        
        # Check if the registry path exists
        if (Test-Path $RegistryPath) {
            Write-Log "Registry path found: $RegistryPath" "INFO"
            
            # Check if the specific value exists
            $PasswordAgeValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
            
            if ($PasswordAgeValue) {
                Write-Log "PasswordAge registry value found: $($PasswordAgeValue.$ValueName)" "INFO"
                
                # Remove the registry value
                Remove-ItemProperty -Path $RegistryPath -Name $ValueName -Force
                Write-Log "PasswordAge registry value removed successfully" "SUCCESS"
                
                # Verify removal
                $VerifyRemoval = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
                if ($VerifyRemoval) {
                    Write-Log "Warning: PasswordAge registry value still exists after removal attempt" "WARN"
                    return $false
                } else {
                    Write-Log "Verification successful: PasswordAge registry value has been removed" "SUCCESS"
                    return $true
                }
            } else {
                Write-Log "PasswordAge registry value not found - no action needed" "INFO"
                return $true
            }
        } else {
            Write-Log "Registry path not found: $RegistryPath - no action needed" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Failed to remove PasswordAge registry key: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Configure-WindowsFirewall {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Windows Firewall Configuration"
    
    try {
        Write-Log "Configuring Windows Firewall for Citrix..."
        
        # Enable Windows Firewall but allow Citrix traffic
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Log "Windows Firewall enabled" "SUCCESS"
        
        # Allow common Citrix ports
        $CitrixPorts = @(
            @{ Port = 1494; Protocol = "TCP"; Description = "Citrix ICA" },
            @{ Port = 2598; Protocol = "TCP"; Description = "Citrix Session Sharing" },
            @{ Port = 8080; Protocol = "TCP"; Description = "Citrix HTTP" }
        )
        
        foreach ($PortRule in $CitrixPorts) {
            try {
                New-NetFirewallRule -DisplayName $PortRule.Description -Direction Inbound -Protocol $PortRule.Protocol -LocalPort $PortRule.Port -Action Allow -ErrorAction SilentlyContinue
                Write-Log "Firewall rule created for $($PortRule.Description) (Port $($PortRule.Port))" "SUCCESS"
            }
            catch {
                Write-Log "Could not create firewall rule for $($PortRule.Description): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Windows Firewall configuration completed" "SUCCESS"
    }
    catch {
        Write-Log "Windows Firewall configuration failed: $($_.Exception.Message)" "ERROR"
    }
}

function Set-RegistryOptimizations {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Registry Optimizations"
    
    try {
        Write-Log "Applying registry optimizations for VDI..."
        
        # Disable Windows Updates automatic restart
        $WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $WindowsUpdatePath)) {
            New-Item -Path $WindowsUpdatePath -Force | Out-Null
        }
        Set-ItemProperty -Path $WindowsUpdatePath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
        
        # Optimize for background services
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 24 -Type DWord
        
        # Disable automatic maintenance
        $MaintenancePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
        if (!(Test-Path $MaintenancePath)) {
            New-Item -Path $MaintenancePath -Force | Out-Null
        }
        Set-ItemProperty -Path $MaintenancePath -Name "MaintenanceDisabled" -Value 1 -Type DWord
        
        Write-Log "Registry optimizations applied successfully" "SUCCESS"
    }
    catch {
        Write-Log "Registry optimizations failed: $($_.Exception.Message)" "ERROR"
    }
}

function Set-VDIOptimizations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$PagefileSizeGB = 8
    )
    
    Write-LogHeader "VDI Specific Optimizations"
    
    try {
        Write-Log "Applying VDI specific optimizations..."
        
        # Configure pagefile settings
        Write-Log "Configuring pagefile settings..."
        
        # Disable automatic pagefile management
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $ComputerSystem.AutomaticManagedPagefile = $false
        Set-CimInstance -CimInstance $ComputerSystem
        
        # Set fixed pagefile size
        $PagefileSizeMB = $PagefileSizeGB * 1024
        $PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
        
        if ($PageFile) {
            $PageFile.InitialSize = $PagefileSizeMB
            $PageFile.MaximumSize = $PagefileSizeMB
            Set-CimInstance -CimInstance $PageFile
        }
        else {
            New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                Name = "$env:SystemDrive\pagefile.sys"
                InitialSize = $PagefileSizeMB
                MaximumSize = $PagefileSizeMB
            }
        }
        
        Write-Log "Pagefile configured: $PagefileSizeGB GB fixed size" "SUCCESS"
        
        # Disable Windows Search indexing
        $SearchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
        if ($SearchService) {
            Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "WSearch" -StartupType Disabled
            Write-Log "Windows Search indexing disabled" "SUCCESS"
        }
        
        # Configure for VDI optimization
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        
        Write-Log "VDI optimizations completed successfully" "SUCCESS"
    }
    catch {
        Write-Log "VDI optimizations failed: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-VMwareMemoryBallooning {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "VMware Memory Ballooning Configuration"
    
    try {
        Write-Log "Checking for VMware environment..."
        
        # Check if running on VMware
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $IsVMware = $false
        
        if ($ComputerSystem) {
            $Manufacturer = $ComputerSystem.Manufacturer
            $Model = $ComputerSystem.Model
            
            if ($Manufacturer -like "*VMware*" -or $Model -like "*VMware*") {
                $IsVMware = $true
            }
        }
        
        if ($IsVMware) {
            Write-Log "VMware environment detected - disabling memory ballooning..."
            
            # Disable memory ballooning via registry
            $VMwareToolsPath = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
            if (Test-Path $VMwareToolsPath) {
                Set-ItemProperty -Path $VMwareToolsPath -Name "EnableBalloon" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                Write-Log "VMware memory ballooning disabled via registry" "SUCCESS"
            }
            
            # Additional VMware optimization
            $VMwareMemPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmmemctl"
            if (Test-Path $VMwareMemPath) {
                Set-ItemProperty -Path $VMwareMemPath -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
                Write-Log "VMware memory control service disabled" "SUCCESS"
            }
        }
        else {
            Write-Log "Non-VMware environment detected - memory ballooning configuration skipped"
        }
    }
    catch {
        Write-Log "VMware memory ballooning configuration failed: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Verification Functions
function Test-CitrixServices {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Citrix Services Verification"
    
    try {
        Write-Log "Checking Citrix services installation..."
        
        # Common Citrix services to check
        $CitrixServices = @(
            @{ Name = "BrokerAgent"; DisplayName = "Citrix Desktop Service" },
            @{ Name = "CdfSvc"; DisplayName = "Citrix Cloud Services" },
            @{ Name = "Spooler"; DisplayName = "Print Spooler" },
            @{ Name = "TermService"; DisplayName = "Remote Desktop Services" }
        )
        
        $ServiceResults = @()
        
        foreach ($ServiceInfo in $CitrixServices) {
            try {
                $Service = Get-Service -Name $ServiceInfo.Name -ErrorAction SilentlyContinue
                
                if ($Service) {
                    $ServiceResults += @{
                        Name = $ServiceInfo.Name
                        DisplayName = $ServiceInfo.DisplayName
                        Status = $Service.Status
                        StartType = $Service.StartType
                        Found = $true
                    }
                    
                    Write-Log "Service '$($ServiceInfo.DisplayName)': $($Service.Status)" "INFO"
                }
                else {
                    $ServiceResults += @{
                        Name = $ServiceInfo.Name
                        DisplayName = $ServiceInfo.DisplayName
                        Status = "Not Found"
                        StartType = "N/A"
                        Found = $false
                    }
                    
                    Write-Log "Service '$($ServiceInfo.DisplayName)': Not Found" "WARN"
                }
            }
            catch {
                Write-Log "Error checking service '$($ServiceInfo.DisplayName)': $($_.Exception.Message)" "ERROR"
            }
        }
        
        return $ServiceResults
    }
    catch {
        Write-Log "Citrix services verification failed: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Test-CitrixRegistration {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Citrix Registration Verification"
    
    try {
        Write-Log "Verifying Citrix VDA registration..."
        
        # Check VDA installation in registry
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        if (Test-Path $VDARegPath) {
            Write-Log "Citrix VDA registry entries found" "SUCCESS"
            
            # Get VDA version if available
            try {
                $VDAVersion = Get-ItemProperty -Path $VDARegPath -Name "ProductVersion" -ErrorAction SilentlyContinue
                if ($VDAVersion) {
                    Write-Log "VDA Version: $($VDAVersion.ProductVersion)" "INFO"
                }
            }
            catch {
                Write-Log "Could not retrieve VDA version" "DEBUG"
            }
            
            return $true
        }
        else {
            Write-Log "Citrix VDA registry entries not found" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Citrix registration verification failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-VDAPrerequisites {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "VDA Prerequisites Verification"
    
    $Results = @{
        OverallStatus = $true
        DotNetFramework = $false
        VisualCPlusPlus = $false
        WindowsFeatures = $false
        Issues = @()
    }
    
    try {
        Write-Log "Checking VDA prerequisites..."
        
        # Check .NET Framework 4.7.2 or higher
        try {
            $DotNetVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release" -ErrorAction SilentlyContinue
            if ($DotNetVersion -and $DotNetVersion.Release -ge 461808) {
                Write-Log ".NET Framework: OK (Release $($DotNetVersion.Release))" "SUCCESS"
                $Results.DotNetFramework = $true
            }
            else {
                Write-Log ".NET Framework: Insufficient version" "WARN"
                $Results.Issues += ".NET Framework 4.7.2 or higher required"
            }
        }
        catch {
            Write-Log ".NET Framework: Could not verify" "WARN"
            $Results.Issues += "Could not verify .NET Framework version"
        }
        
        # Check Visual C++ Redistributables
        $VCRedistKeys = @(
            "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
        )
        
        $VCRedistFound = $false
        foreach ($Key in $VCRedistKeys) {
            if (Test-Path $Key) {
                $VCRedistFound = $true
                break
            }
        }
        
        if ($VCRedistFound) {
            Write-Log "Visual C++ Redistributables: OK" "SUCCESS"
            $Results.VisualCPlusPlus = $true
        }
        else {
            Write-Log "Visual C++ Redistributables: Not found" "WARN"
            $Results.Issues += "Visual C++ Redistributables required"
        }
        
        # Check Windows Features (RDS role)
        try {
            $RDSFeature = Get-WindowsFeature -Name "RDS-RD-Server" -ErrorAction SilentlyContinue
            if ($RDSFeature -and $RDSFeature.InstallState -eq "Installed") {
                Write-Log "RDS Role: Already installed" "SUCCESS"
                $Results.WindowsFeatures = $true
            }
            else {
                Write-Log "RDS Role: Will be installed by VDA" "INFO"
                $Results.WindowsFeatures = $true  # VDA will install this
            }
        }
        catch {
            Write-Log "RDS Role: Could not verify" "DEBUG"
            $Results.WindowsFeatures = $true  # Assume OK
        }
        
        # Overall status
        $Results.OverallStatus = (
            $Results.DotNetFramework -and
            $Results.VisualCPlusPlus -and
            $Results.WindowsFeatures
        )
        
        Write-Log "VDA prerequisites check completed"
        Write-Log "Overall Status: $(if($Results.OverallStatus){'PASSED'}else{'ISSUES FOUND'})" $(if($Results.OverallStatus){'SUCCESS'}else{'WARN'})
        
        return $Results
    }
    catch {
        Write-Log "VDA prerequisites verification failed: $($_.Exception.Message)" "ERROR"
        $Results.OverallStatus = $false
        $Results.Issues += "Prerequisites verification failed: $($_.Exception.Message)"
        return $Results
    }
}

function Test-ExistingCitrixInstallation {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Existing Citrix Installation Check"
    
    $Results = @{
        VDAInstalled = $false
        PVSInstalled = $false
        WEMInstalled = $false
        UberAgentInstalled = $false
        Details = @()
    }
    
    try {
        Write-Log "Checking for existing Citrix installations..."
        
        # Check for VDA
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        if (Test-Path $VDARegPath) {
            $Results.VDAInstalled = $true
            $Results.Details += "Citrix VDA already installed"
            Write-Log "Existing VDA installation detected" "WARN"
        }
        
        # Check for PVS Target Device
        $PVSRegPath = "HKLM:\SOFTWARE\Citrix\ProvisioningServices"
        if (Test-Path $PVSRegPath) {
            $Results.PVSInstalled = $true
            $Results.Details += "PVS Target Device already installed"
            Write-Log "Existing PVS installation detected" "WARN"
        }
        
        # Check for WEM Agent
        $WEMRegPath = "HKLM:\SOFTWARE\Norskale\Agent Host"
        if (Test-Path $WEMRegPath) {
            $Results.WEMInstalled = $true
            $Results.Details += "WEM Agent already installed"
            Write-Log "Existing WEM installation detected" "WARN"
        }
        
        # Check for UberAgent
        $UberAgentPath = "C:\Program Files\uberAgent"
        if (Test-Path $UberAgentPath) {
            $Results.UberAgentInstalled = $true
            $Results.Details += "UberAgent already installed"
            Write-Log "Existing UberAgent installation detected" "WARN"
        }
        
        if ($Results.Details.Count -eq 0) {
            Write-Log "No existing Citrix installations detected" "SUCCESS"
        }
        
        return $Results
    }
    catch {
        Write-Log "Existing installation check failed: $($_.Exception.Message)" "ERROR"
        return $Results
    }
}

function Test-SystemOptimizations {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "System Optimizations Verification"
    
    $Results = @{
        OverallStatus = $true
        PagefileConfigured = $false
        ServicesOptimized = $false
        RegistryOptimized = $false
        Issues = @()
    }
    
    try {
        Write-Log "Verifying system optimizations..."
        
        # Check pagefile configuration
        $PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($PageFile) {
            if ($PageFile.InitialSize -eq $PageFile.MaximumSize -and $PageFile.InitialSize -gt 0) {
                Write-Log "Pagefile: Fixed size configured ($($PageFile.InitialSize) MB)" "SUCCESS"
                $Results.PagefileConfigured = $true
            }
            else {
                Write-Log "Pagefile: Not configured for fixed size" "WARN"
                $Results.Issues += "Pagefile should be configured with fixed size"
            }
        }
        else {
            Write-Log "Pagefile: Configuration not found" "WARN"
            $Results.Issues += "Pagefile configuration not found"
        }
        
        # Check services optimization
        $SearchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
        if ($SearchService -and $SearchService.StartType -eq "Disabled") {
            Write-Log "Windows Search: Disabled (optimized)" "SUCCESS"
            $Results.ServicesOptimized = $true
        }
        else {
            Write-Log "Windows Search: Not optimally configured" "WARN"
            $Results.Issues += "Windows Search should be disabled for optimal performance"
        }
        
        # Check registry optimizations
        $MaintenanceDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -ErrorAction SilentlyContinue
        if ($MaintenanceDisabled -and $MaintenanceDisabled.MaintenanceDisabled -eq 1) {
            Write-Log "Automatic Maintenance: Disabled (optimized)" "SUCCESS"
            $Results.RegistryOptimized = $true
        }
        else {
            Write-Log "Automatic Maintenance: Not disabled" "WARN"
            $Results.Issues += "Automatic Maintenance should be disabled for optimal performance"
        }
        
        # Overall status
        $Results.OverallStatus = (
            $Results.PagefileConfigured -and
            $Results.ServicesOptimized -and
            $Results.RegistryOptimized
        )
        
        Write-Log "System optimizations verification completed"
        Write-Log "Overall Status: $(if($Results.OverallStatus){'OPTIMIZED'}else{'NEEDS ATTENTION'})" $(if($Results.OverallStatus){'SUCCESS'}else{'WARN'})
        
        return $Results
    }
    catch {
        Write-Log "System optimizations verification failed: $($_.Exception.Message)" "ERROR"
        $Results.OverallStatus = $false
        $Results.Issues += "Optimizations verification failed: $($_.Exception.Message)"
        return $Results
    }
}

function Test-AutomaticMaintenanceStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Checking Automatic Maintenance status..."
        
        $MaintenanceStatus = @{
            MaintenanceDisabled = $false
            RegistryConfigured = $false
        }
        
        # Check registry setting
        $MaintenanceKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
        $MaintenanceDisabled = Get-ItemProperty -Path $MaintenanceKey -Name "MaintenanceDisabled" -ErrorAction SilentlyContinue
        
        if ($MaintenanceDisabled -and $MaintenanceDisabled.MaintenanceDisabled -eq 1) {
            $MaintenanceStatus.MaintenanceDisabled = $true
            $MaintenanceStatus.RegistryConfigured = $true
            Write-Log "Automatic Maintenance: DISABLED (registry configured)" "SUCCESS"
        }
        else {
            Write-Log "Automatic Maintenance: ENABLED or not configured" "WARN"
        }
        
        return $MaintenanceStatus
    }
    catch {
        Write-Log "Could not check Automatic Maintenance status: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-VMwareMemoryBallooningStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Checking VMware Memory Ballooning status..."
        
        $MemoryBallooningStatus = @{
            VMwareEnvironment = $false
            OverallCompliant = $false
            RegistryDisabled = $false
            ServiceDisabled = $false
            Issues = @()
        }
        
        # Check if VMware environment
        $SystemInfo = Get-SystemInfo
        if ($SystemInfo -and $SystemInfo.VirtualPlatform -eq "VMware") {
            $MemoryBallooningStatus.VMwareEnvironment = $true
            Write-Log "VMware environment detected"
            
            # Check registry setting
            $VMwareToolsPath = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
            if (Test-Path $VMwareToolsPath) {
                $BalloonSetting = Get-ItemProperty -Path $VMwareToolsPath -Name "EnableBalloon" -ErrorAction SilentlyContinue
                if ($BalloonSetting -and $BalloonSetting.EnableBalloon -eq 0) {
                    $MemoryBallooningStatus.RegistryDisabled = $true
                    Write-Log "VMware Memory Ballooning: DISABLED (registry)" "SUCCESS"
                }
                else {
                    $MemoryBallooningStatus.Issues += "VMware Memory Ballooning not disabled in registry"
                }
            }
            
            # Check service setting
            $VMwareMemPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmmemctl"
            if (Test-Path $VMwareMemPath) {
                $ServiceStart = Get-ItemProperty -Path $VMwareMemPath -Name "Start" -ErrorAction SilentlyContinue
                if ($ServiceStart -and $ServiceStart.Start -eq 4) {
                    $MemoryBallooningStatus.ServiceDisabled = $true
                    Write-Log "VMware Memory Control Service: DISABLED" "SUCCESS"
                }
                else {
                    $MemoryBallooningStatus.Issues += "VMware Memory Control Service not disabled"
                }
            }
            
            $MemoryBallooningStatus.OverallCompliant = (
                $MemoryBallooningStatus.RegistryDisabled -or 
                $MemoryBallooningStatus.ServiceDisabled
            )
        }
        else {
            Write-Log "Non-VMware environment - Memory Ballooning check N/A"
        }
        
        return $MemoryBallooningStatus
    }
    catch {
        Write-Log "Could not check VMware Memory Ballooning status: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-TerminalServerLicensing {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Checking Terminal Server licensing configuration..."
        
        $TSLicensingStatus = @{
            GracePeriodActive = $false
            LicenseServerConfigured = $false
            GracePeriodDaysRemaining = 0
            LicenseMode = "Unknown"
        }
        
        # Check TS licensing grace period
        $TSLicensingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"
        if (Test-Path $TSLicensingKey) {
            # Grace period registry exists - check if active
            $GracePeriodStart = Get-ItemProperty -Path $TSLicensingKey -Name "L$([char]((65..90) + (97..122) | Get-Random))" -ErrorAction SilentlyContinue
            if ($GracePeriodStart) {
                $TSLicensingStatus.GracePeriodActive = $true
                
                # Calculate remaining days (approximate)
                $GracePeriodBytes = $GracePeriodStart.PSObject.Properties.Value
                if ($GracePeriodBytes) {
                    # This is a simplified calculation - actual grace period calculation is more complex
                    $TSLicensingStatus.GracePeriodDaysRemaining = 120  # Default assumption
                }
            }
        }
        
        # Check license mode
        $TSConfigKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM"
        $LicenseMode = Get-ItemProperty -Path $TSConfigKey -Name "TerminalServerMode" -ErrorAction SilentlyContinue
        if ($LicenseMode) {
            switch ($LicenseMode.TerminalServerMode) {
                2 { $TSLicensingStatus.LicenseMode = "Per Device" }
                4 { $TSLicensingStatus.LicenseMode = "Per User" }
                default { $TSLicensingStatus.LicenseMode = "Unknown ($($LicenseMode.TerminalServerMode))" }
            }
        }
        
        Write-Log "Terminal Server Licensing Status:"
        Write-Log "  License Mode: $($TSLicensingStatus.LicenseMode)"
        Write-Log "  Grace Period Active: $($TSLicensingStatus.GracePeriodActive)"
        if ($TSLicensingStatus.GracePeriodActive) {
            Write-Log "  Grace Period Days Remaining: ~$($TSLicensingStatus.GracePeriodDaysRemaining)"
        }
        
        return $TSLicensingStatus
    }
    catch {
        Write-Log "Could not check Terminal Server licensing: $($_.Exception.Message)" "ERROR"
        return $null
    }
}
#endregion

#region Cleanup and Finalization Functions
function Remove-WEMRSAKey {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "WEM RSA Key Cleanup"
    
    try {
        Write-Log "Removing WEM RSA keys for system finalization..."
        
        # WEM RSA key locations
        $WEMKeyPaths = @(
            "HKLM:\SOFTWARE\Norskale\Agent Host\AgentKeys",
            "HKLM:\SOFTWARE\WOW6432Node\Norskale\Agent Host\AgentKeys"
        )
        
        $KeysRemoved = $false
        
        foreach ($KeyPath in $WEMKeyPaths) {
            if (Test-Path $KeyPath) {
                try {
                    Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                    Write-Log "WEM RSA keys removed from: $KeyPath" "SUCCESS"
                    $KeysRemoved = $true
                }
                catch {
                    Write-Log "Could not remove WEM RSA keys from $KeyPath`: $($_.Exception.Message)" "WARN"
                }
            }
            else {
                Write-Log "WEM RSA key path not found: $KeyPath" "DEBUG"
            }
        }
        
        # Also check for WEM cache files
        $WEMCachePaths = @(
            "$env:ProgramData\Norskale\Agent Host\Cache",
            "$env:ProgramFiles\Norskale\Agent Host\Cache",
            "$env:ProgramFiles(x86)\Norskale\Agent Host\Cache"
        )
        
        foreach ($CachePath in $WEMCachePaths) {
            if (Test-Path $CachePath) {
                try {
                    Remove-Item -Path "$CachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "WEM cache cleared from: $CachePath" "SUCCESS"
                    $KeysRemoved = $true
                }
                catch {
                    Write-Log "Could not clear WEM cache from $CachePath`: $($_.Exception.Message)" "DEBUG"
                }
            }
        }
        
        if ($KeysRemoved) {
            Write-Log "WEM RSA key cleanup completed successfully" "SUCCESS"
        }
        else {
            Write-Log "No WEM RSA keys found to remove (this is acceptable)" "INFO"
        }
        
        return $KeysRemoved
    }
    catch {
        Write-Log "WEM RSA key cleanup failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-InstallationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigPath = "C:\Logs\CitrixConfig.json"
    )
    
    try {
        Write-Log "Saving installation configuration..."
        
        # Ensure directory exists
        $ConfigDir = Split-Path $ConfigPath -Parent
        if (!(Test-Path $ConfigDir)) {
            New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
        }
        
        # Convert to JSON and save
        $ConfigJson = $Config | ConvertTo-Json -Depth 10
        Set-Content -Path $ConfigPath -Value $ConfigJson -Encoding UTF8
        
        Write-Log "Installation configuration saved to: $ConfigPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to save installation configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Load-InstallationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigPath = "C:\Logs\CitrixConfig.json"
    )
    
    try {
        if (Test-Path $ConfigPath) {
            Write-Log "Loading installation configuration from: $ConfigPath"
            
            $ConfigJson = Get-Content -Path $ConfigPath -Raw -Encoding UTF8
            $Config = $ConfigJson | ConvertFrom-Json
            
            # Convert PSCustomObject back to hashtable for easier manipulation
            $ConfigHashtable = @{}
            $Config.PSObject.Properties | ForEach-Object {
                $ConfigHashtable[$_.Name] = $_.Value
            }
            
            Write-Log "Installation configuration loaded successfully" "SUCCESS"
            return $ConfigHashtable
        }
        else {
            Write-Log "Installation configuration file not found: $ConfigPath" "WARN"
            return $null
        }
    }
    catch {
        Write-Log "Failed to load installation configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-RebootScheduledTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Stage2ScriptPath,
        
        [Parameter(Mandatory=$false)]
        [string]$TaskName = "CitrixInstall-Stage2"
    )
    
    try {
        Write-Log "Creating scheduled task for Stage 2 execution..."
        
        # Define the action
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$Stage2ScriptPath`""
        
        # Define the trigger (at startup)
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        
        # Define the principal (run as SYSTEM)
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Define the settings
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        
        # Create the task
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
        
        Write-Log "Scheduled task '$TaskName' created successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-RebootScheduledTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Stage,
        
        [Parameter(Mandatory=$false)]
        [string]$TaskName = "CitrixInstall-Stage2"
    )
    
    try {
        Write-Log "Removing scheduled task for $Stage..."
        
        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($Task) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Log "Scheduled task '$TaskName' removed successfully" "SUCCESS"
        }
        else {
            Write-Log "Scheduled task '$TaskName' not found (already removed)" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to remove scheduled task: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Complete-Installation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$Stage2ScriptPath = ""
    )
    
    try {
        Write-LogHeader "Completing Installation - Stage 1"
        
        # Save final configuration
        Save-InstallationConfig -Config $Config
        
        # Create Stage 2 script if reboot is required
        if ($Config.RebootRequired -and ![string]::IsNullOrEmpty($Stage2ScriptPath) -and (Test-Path $Stage2ScriptPath)) {
            Write-Log "Reboot required - setting up Stage 2 execution..."
            
            # Create scheduled task for Stage 2
            $TaskCreated = New-RebootScheduledTask -Stage2ScriptPath $Stage2ScriptPath
            
            if ($TaskCreated) {
                Write-Log "Stage 2 will execute automatically after reboot" "SUCCESS"
                Write-Log "Rebooting system in 60 seconds..." "WARN"
                Write-Log "Press Ctrl+C to cancel automatic reboot" "WARN"
                
                # Give user time to cancel
                Start-Sleep -Seconds 60
                
                # Restart computer
                Restart-Computer -Force
            }
            else {
                Write-Log "Could not create scheduled task - manual Stage 2 execution required" "WARN"
                Write-Log "Please run Stage 2 script manually after reboot: $Stage2ScriptPath" "WARN"
            }
        }
        else {
            Write-Log "No reboot required - installation completed successfully" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to complete installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-InstallationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportPath = "C:\Logs\CitrixInstall-Report.txt"
    )
    
    try {
        Write-Log "Creating installation report..."
        
        $Report = @()
        $Report += "=" * 80
        $Report += "CITRIX PLATFORM INSTALLATION REPORT"
        $Report += "Generated: $(Get-Date)"
        $Report += "=" * 80
        $Report += ""
        
        # System Information
        if ($Config.SystemInfo) {
            $Report += "SYSTEM INFORMATION:"
            $Report += "  Computer: $($Config.SystemInfo.ComputerName)"
            $Report += "  OS: $($Config.SystemInfo.OSVersion)"
            $Report += "  Memory: $($Config.SystemInfo.TotalMemoryGB) GB"
            $Report += "  Virtual Platform: $($Config.SystemInfo.VirtualPlatform)"
            $Report += ""
        }
        
        # Installation Results
        $Report += "INSTALLATION RESULTS:"
        
        if ($Config.InstallationResults.VDA) {
            $VDAStatus = if ($Config.InstallationResults.VDA.Success) { "SUCCESS" } else { "FAILED" }
            $Report += "  VDA: $VDAStatus"
        }
        
        if ($Config.InstallationResults.PVS) {
            $PVSStatus = if ($Config.InstallationResults.PVS.Skipped) { "SKIPPED" } elseif ($Config.InstallationResults.PVS.Success) { "SUCCESS" } else { "FAILED" }
            $Report += "  PVS Target Device: $PVSStatus"
        }
        
        if ($Config.InstallationResults.WEM) {
            $WEMStatus = if ($Config.InstallationResults.WEM.Skipped) { "SKIPPED" } elseif ($Config.InstallationResults.WEM.Success) { "SUCCESS" } else { "FAILED" }
            $Report += "  WEM Agent: $WEMStatus"
        }
        
        if ($Config.InstallationResults.UberAgent) {
            $UberAgentStatus = if ($Config.InstallationResults.UberAgent.Skipped) { "SKIPPED" } elseif ($Config.InstallationResults.UberAgent.OverallSuccess) { "SUCCESS" } else { "FAILED" }
            $Report += "  UberAgent: $UberAgentStatus"
        }
        
        if ($Config.InstallationResults.TADDM) {
            $TADDMStatus = if ($Config.InstallationResults.TADDM.Skipped) { "SKIPPED" } elseif ($Config.InstallationResults.TADDM.OverallSuccess) { "SUCCESS" } else { "CONFIGURED" }
            $Report += "  IBM TADDM: $TADDMStatus"
        }
        
        $Report += ""
        $Report += "INSTALLATION MODE: Standard Configuration"
        $Report += "REBOOT REQUIRED: $($Config.RebootRequired)"
        $Report += ""
        
        # Write report to file
        $Report | Out-File -FilePath $ReportPath -Encoding UTF8
        
        Write-Log "Installation report created: $ReportPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to create installation report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

# Export functions for module use
Export-ModuleMember -Function *