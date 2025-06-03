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
$Global:ConfigData = @{}

# Error action preference for consistent behavior
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

function Read-ConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigPath = ".\CitrixConfig.txt"
    )
    
    try {
        if (!(Test-Path $ConfigPath)) {
            Write-Warning "Configuration file not found: $ConfigPath"
            Write-Warning "Using default values. Please create CitrixConfig.txt with your environment settings."
            return @{}
        }
        
        $ConfigData = @{}
        $ConfigContent = Get-Content $ConfigPath
        
        foreach ($Line in $ConfigContent) {
            $Line = $Line.Trim()
            
            # Skip empty lines and comments
            if ($Line -eq "" -or $Line.StartsWith("#")) {
                continue
            }
            
            # Parse key=value pairs
            if ($Line -contains "=") {
                $Parts = $Line -split "=", 2
                if ($Parts.Count -eq 2) {
                    $Key = $Parts[0].Trim()
                    $Value = $Parts[1].Trim()
                    
                    # Expand environment variables
                    $Value = [System.Environment]::ExpandEnvironmentVariables($Value)
                    
                    # Convert boolean values
                    if ($Value -eq "true") { $Value = $true }
                    elseif ($Value -eq "false") { $Value = $false }
                    # Convert numeric values
                    elseif ($Value -match "^\d+$") { $Value = [int]$Value }
                    
                    $ConfigData[$Key] = $Value
                }
            }
        }
        
        $Global:ConfigData = $ConfigData
        Write-Host "Configuration loaded from: $ConfigPath" -ForegroundColor Green
        Write-Host "Loaded $($ConfigData.Count) configuration values" -ForegroundColor Green
        
        return $ConfigData
    }
    catch {
        Write-Warning "Failed to read configuration file: $($_.Exception.Message)"
        return @{}
    }
}

function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        
        [Parameter(Mandatory=$false)]
        $DefaultValue = $null
    )
    
    if ($Global:ConfigData.ContainsKey($Key)) {
        return $Global:ConfigData[$Key]
    }
    else {
        if ($DefaultValue -ne $null) {
            Write-Warning "Configuration key '$Key' not found, using default: $DefaultValue"
        }
        return $DefaultValue
    }
}
#endregion

#region Logging Functions
function Get-DesktopLogPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogFileName = "CitrixInstallation.log"
    )
    
    try {
        # Get the current user's desktop path
        $DesktopPath = [Environment]::GetFolderPath('Desktop')
        
        if ([string]::IsNullOrEmpty($DesktopPath)) {
            # Fallback to USERPROFILE\Desktop if GetFolderPath fails
            $DesktopPath = "$env:USERPROFILE\Desktop"
        }
        
        # Ensure desktop directory exists
        if (!(Test-Path $DesktopPath)) {
            New-Item -Path $DesktopPath -ItemType Directory -Force | Out-Null
        }
        
        return Join-Path $DesktopPath $LogFileName
    }
    catch {
        # Final fallback to current directory
        Write-Warning "Could not determine desktop path, using current directory: $($_.Exception.Message)"
        return ".\$LogFileName"
    }
}

function Initialize-Logging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$ClearExisting = $false
    )
    
    try {
        # Use desktop path if no log path provided
        if ([string]::IsNullOrEmpty($LogPath)) {
            $LogPath = Get-DesktopLogPath
        }
        
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
function Get-WindowsVersion {
    [CmdletBinding()]
    param()
    
    try {
        # Get OS information
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $OSVersion = $OS.Version
        $OSCaption = $OS.Caption
        
        Write-Log "Detected OS: $OSCaption (Version: $OSVersion)" "INFO"
        
        # Determine Windows Server version
        if ($OSCaption -match "Windows Server 2019") {
            $WindowsVersion = "2019"
            Write-Log "Windows Server 2019 detected" "SUCCESS"
        }
        elseif ($OSCaption -match "Windows Server 2022") {
            $WindowsVersion = "2022"
            Write-Log "Windows Server 2022 detected" "SUCCESS"
        }
        elseif ($OSCaption -match "Windows Server 2016") {
            $WindowsVersion = "2016"
            Write-Log "Windows Server 2016 detected" "SUCCESS"
        }
        elseif ($OSCaption -match "Windows 10" -or $OSCaption -match "Windows 11") {
            # For client OS, default to 2022 scripts
            $WindowsVersion = "2022"
            Write-Log "Windows client OS detected - using Windows 2022 script configuration" "INFO"
        }
        else {
            # Default to 2022 for unknown versions
            $WindowsVersion = "2022"
            Write-Log "Unknown Windows version detected - defaulting to Windows 2022 script configuration" "WARN"
        }
        
        return @{
            Version = $WindowsVersion
            FullVersion = $OSVersion
            Caption = $OSCaption
            BuildNumber = $OS.BuildNumber
            Is2019 = ($WindowsVersion -eq "2019")
            Is2022 = ($WindowsVersion -eq "2022")
            Is2016 = ($WindowsVersion -eq "2016")
        }
    }
    catch {
        Write-Log "Failed to detect Windows version: $($_.Exception.Message)" "ERROR"
        # Return default values if detection fails
        return @{
            Version = "2022"
            FullVersion = "Unknown"
            Caption = "Unknown"
            BuildNumber = "Unknown"
            Is2019 = $false
            Is2022 = $true
            Is2016 = $false
        }
    }
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


#endregion

#region Drive Configuration Functions
function Initialize-InstallConfig {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Installation Configuration Initialization"
    
    try {
        Write-Log "Initializing installation configuration..."
        
        # Load configuration from file
        $ConfigData = Read-ConfigFile
        
        $Config = @{
            # Installation paths - from config file or defaults
            VDAISOPath = Get-ConfigValue "VDAISOPath" "C:\Temp\VDA_Server.iso"
            PVSISOPath = Get-ConfigValue "PVSISOPath" "C:\Temp\PVS_Agent.iso"
            WEMPath = Get-ConfigValue "WEMInstallerPath" "C:\Temp\Citrix_WEM_Agent.msi"
            UberAgentPath = Get-ConfigValue "UberAgentInstallerPath" "C:\Temp\uberAgent.msi"
            TADDMPath = "C:\Temp\7.3.0.6-TIV-TADDM-Windows.exe"
            
            # Network configuration from config file
            NetworkSourcePath = Get-ConfigValue "NetworkSourcePath" "\\fileserver\citrix\installers"
            LocalInstallPath = Get-ConfigValue "LocalInstallPath" "C:\Temp"
            
            # Domain configuration from config file
            DomainName = Get-ConfigValue "DomainName" ""
            DomainJoinOU = Get-ConfigValue "DomainJoinOU" ""
            DomainJoinUsername = Get-ConfigValue "DomainJoinUsername" ""
            
            # DNS configuration from config file
            PrimaryDNSSuffix = Get-ConfigValue "PrimaryDNSSuffix" ""
            DNSSuffixSearchList = if (Get-ConfigValue "DNSSuffixSearchList") { (Get-ConfigValue "DNSSuffixSearchList").Split(",") } else { @() }
            
            # System configuration from config file
            PagefileSizeGB = Get-ConfigValue "PagefileSizeGB" 8
            DisableNetBIOS = Get-ConfigValue "DisableNetBIOS" $true
            DisableNetworkOffload = Get-ConfigValue "DisableNetworkOffload" $true
            ConfigureSMB = Get-ConfigValue "ConfigureSMB" $true
            AutoReboot = Get-ConfigValue "AutoReboot" $true
            RebootDelay = Get-ConfigValue "RebootDelay" 30
            
            # Logging from config file - default to user's desktop
            LogPath = Get-ConfigValue "LogPath" "$([Environment]::GetFolderPath('Desktop'))\CitrixInstallation.log"
            ReportPath = Get-ConfigValue "ReportPath" "$([Environment]::GetFolderPath('Desktop'))\CitrixInstallationReport.txt"
            
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
        
        # Validate system drive availability
        if (Test-Path $env:SystemDrive) {
            Write-Log "System drive configuration validated" "SUCCESS"
            $Results.Actions += "System drive configuration validated"
        }
        else {
            Write-Log "System drive not accessible" "ERROR"
            $Results.Issues += "System drive not accessible"
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
        
        # Verify system drive availability
        if (Test-Path $env:SystemDrive) {
            Write-Log "System drive ($env:SystemDrive): Accessible and configured"
        }
        else {
            Write-Log "System drive not accessible" "ERROR"
            return $false
        }
        
        # Check D: drive if exists
        if (Test-Path "D:\") {
            Write-Log "D: drive: Available and accessible"
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

#region File Copy Functions
function Copy-InstallationFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ComponentName
    )
    
    Write-Log "Copying $ComponentName installation file..." "INFO"
    Write-Log "Source: $SourcePath" "DEBUG"
    Write-Log "Destination: $DestinationPath" "DEBUG"
    
    try {
        # Validate source exists
        if (!(Test-Path $SourcePath)) {
            throw "$ComponentName source file not found: $SourcePath"
        }
        
        # Ensure destination directory exists
        $DestinationDir = Split-Path $DestinationPath -Parent
        if (!(Test-Path $DestinationDir)) {
            Write-Log "Creating destination directory: $DestinationDir" "INFO"
            New-Item -Path $DestinationDir -ItemType Directory -Force | Out-Null
        }
        
        # Get source file size for progress tracking
        $SourceSize = (Get-Item $SourcePath).Length
        $SourceSizeMB = [Math]::Round($SourceSize / 1MB, 1)
        Write-Log "Copying $ComponentName ($SourceSizeMB MB)..." "INFO"
        
        # Copy the file with robocopy for better network handling
        $RobocopySource = Split-Path $SourcePath -Parent
        $RobocopyFile = Split-Path $SourcePath -Leaf
        $RobocopyDest = Split-Path $DestinationPath -Parent
        
        $RobocopyArgs = @(
            "`"$RobocopySource`""
            "`"$RobocopyDest`""
            "`"$RobocopyFile`""
            "/R:3"    # Retry 3 times
            "/W:10"   # Wait 10 seconds between retries
            "/NP"     # No progress display
            "/NDL"    # No directory listing
        )
        
        $Process = Start-Process -FilePath "robocopy.exe" -ArgumentList $RobocopyArgs -Wait -PassThru -NoNewWindow
        
        # Robocopy exit codes: 0-7 are success, 8+ are errors
        if ($Process.ExitCode -ge 8) {
            # Fallback to PowerShell copy if robocopy fails
            Write-Log "Robocopy failed, using PowerShell copy..." "WARN"
            Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
        }
        
        # Validate copy succeeded
        if (Test-Path $DestinationPath) {
            $DestSize = (Get-Item $DestinationPath).Length
            
            if ($SourceSize -eq $DestSize) {
                Write-Log "$ComponentName file copied successfully" "SUCCESS"
                return $true
            } else {
                throw "File size mismatch after copy - Source: $SourceSize bytes, Destination: $DestSize bytes"
            }
        } else {
            throw "Destination file not found after copy operation"
        }
    }
    catch {
        Write-Log "$ComponentName file copy failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Script Management Functions
function Copy-OSSpecificStartupShutdownScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StartupSourceWin2019,
        
        [Parameter(Mandatory=$true)]
        [string]$StartupSourceWin2022,
        
        [Parameter(Mandatory=$true)]
        [string]$StartupDestination,
        
        [Parameter(Mandatory=$true)]
        [string]$ShutdownSourceWin2019,
        
        [Parameter(Mandatory=$true)]
        [string]$ShutdownSourceWin2022,
        
        [Parameter(Mandatory=$true)]
        [string]$ShutdownDestination
    )
    
    Write-LogHeader "OS-Aware Startup and Shutdown Scripts Copying"
    
    $Results = @{
        StartupCopied = $false
        ShutdownCopied = $false
        StartupSkipped = $false
        ShutdownSkipped = $false
        DetectedOS = ""
        SelectedStartupSource = ""
        SelectedShutdownSource = ""
        Issues = @()
        Actions = @()
    }
    
    try {
        # Detect Windows version
        Write-Log "Detecting Windows version for script selection..."
        $WindowsInfo = Get-WindowsVersion
        $Results.DetectedOS = $WindowsInfo.Version
        
        # Select appropriate source paths based on OS version
        if ($WindowsInfo.Is2019) {
            $StartupSource = $StartupSourceWin2019
            $ShutdownSource = $ShutdownSourceWin2019
            Write-Log "Windows Server 2019 detected - using 2019 script sources" "SUCCESS"
        }
        elseif ($WindowsInfo.Is2022) {
            $StartupSource = $StartupSourceWin2022
            $ShutdownSource = $ShutdownSourceWin2022
            Write-Log "Windows Server 2022 detected - using 2022 script sources" "SUCCESS"
        }
        else {
            # Default to 2022 scripts for other versions
            $StartupSource = $StartupSourceWin2022
            $ShutdownSource = $ShutdownSourceWin2022
            Write-Log "Using Windows 2022 script sources as default for detected OS: $($WindowsInfo.Caption)" "INFO"
        }
        
        $Results.SelectedStartupSource = $StartupSource
        $Results.SelectedShutdownSource = $ShutdownSource
        
        Write-Log "Selected startup source: $StartupSource"
        Write-Log "Selected shutdown source: $ShutdownSource"
        
        # Copy startup scripts
        if (![string]::IsNullOrEmpty($StartupSource) -and (Test-Path $StartupSource)) {
            Write-Log "Copying OS-specific startup scripts from: $StartupSource"
            Write-Log "Destination: $StartupDestination"
            
            # Ensure destination directory exists
            if (!(Test-Path $StartupDestination)) {
                New-Item -Path $StartupDestination -ItemType Directory -Force | Out-Null
                Write-Log "Created startup scripts directory: $StartupDestination" "SUCCESS"
            }
            
            # Copy all files from source to destination
            $StartupFiles = Get-ChildItem -Path $StartupSource -File -ErrorAction SilentlyContinue
            if ($StartupFiles.Count -gt 0) {
                foreach ($File in $StartupFiles) {
                    $DestinationPath = Join-Path $StartupDestination $File.Name
                    Copy-Item -Path $File.FullName -Destination $DestinationPath -Force
                    Write-Log "Copied startup script: $($File.Name)" "SUCCESS"
                }
                $Results.StartupCopied = $true
                $Results.Actions += "Copied $($StartupFiles.Count) Windows $($WindowsInfo.Version) startup script(s)"
            }
            else {
                Write-Log "No startup scripts found in OS-specific source directory" "WARN"
                $Results.StartupSkipped = $true
                $Results.Issues += "No startup scripts found in Windows $($WindowsInfo.Version) source directory"
            }
        }
        else {
            Write-Log "OS-specific startup scripts source not found: $StartupSource" "WARN"
            $Results.StartupSkipped = $true
            $Results.Issues += "Windows $($WindowsInfo.Version) startup scripts source not accessible"
        }
        
        # Copy shutdown scripts
        if (![string]::IsNullOrEmpty($ShutdownSource) -and (Test-Path $ShutdownSource)) {
            Write-Log "Copying OS-specific shutdown scripts from: $ShutdownSource"
            Write-Log "Destination: $ShutdownDestination"
            
            # Ensure destination directory exists
            if (!(Test-Path $ShutdownDestination)) {
                New-Item -Path $ShutdownDestination -ItemType Directory -Force | Out-Null
                Write-Log "Created shutdown scripts directory: $ShutdownDestination" "SUCCESS"
            }
            
            # Copy all files from source to destination
            $ShutdownFiles = Get-ChildItem -Path $ShutdownSource -File -ErrorAction SilentlyContinue
            if ($ShutdownFiles.Count -gt 0) {
                foreach ($File in $ShutdownFiles) {
                    $DestinationPath = Join-Path $ShutdownDestination $File.Name
                    Copy-Item -Path $File.FullName -Destination $DestinationPath -Force
                    Write-Log "Copied shutdown script: $($File.Name)" "SUCCESS"
                }
                $Results.ShutdownCopied = $true
                $Results.Actions += "Copied $($ShutdownFiles.Count) Windows $($WindowsInfo.Version) shutdown script(s)"
            }
            else {
                Write-Log "No shutdown scripts found in OS-specific source directory" "WARN"
                $Results.ShutdownSkipped = $true
                $Results.Issues += "No shutdown scripts found in Windows $($WindowsInfo.Version) source directory"
            }
        }
        else {
            Write-Log "OS-specific shutdown scripts source not found: $ShutdownSource" "WARN"
            $Results.ShutdownSkipped = $true
            $Results.Issues += "Windows $($WindowsInfo.Version) shutdown scripts source not accessible"
        }
        
        return $Results
    }
    catch {
        Write-Log "Error copying OS-specific startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "Error copying OS-specific scripts: $($_.Exception.Message)"
        return $Results
    }
}

function Configure-StartupShutdownScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ScriptCopyResults,
        
        [Parameter(Mandatory=$true)]
        [string]$StartupDestination,
        
        [Parameter(Mandatory=$true)]
        [string]$ShutdownDestination
    )
    
    Write-LogHeader "Configuring Startup and Shutdown Scripts via Group Policy"
    
    $Results = @{
        StartupConfigured = $false
        ShutdownConfigured = $false
        RegistryConfigured = $false
        GroupPolicyConfigured = $false
        Issues = @()
        Actions = @()
    }
    
    try {
        # Configure startup scripts registry entries
        if ($ScriptCopyResults.StartupCopied) {
            Write-Log "Configuring startup scripts registry entries..."
            
            $StartupScripts = Get-ChildItem -Path $StartupDestination -File -ErrorAction SilentlyContinue
            if ($StartupScripts.Count -gt 0) {
                $StartupRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
                
                # Ensure registry path exists
                if (!(Test-Path $StartupRegistryPath)) {
                    New-Item -Path $StartupRegistryPath -Force | Out-Null
                }
                
                $ScriptIndex = 0
                foreach ($Script in $StartupScripts) {
                    $ScriptRegPath = "$StartupRegistryPath\$ScriptIndex"
                    
                    if (!(Test-Path $ScriptRegPath)) {
                        New-Item -Path $ScriptRegPath -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path $ScriptRegPath -Name "Script" -Value $Script.FullName
                    Set-ItemProperty -Path $ScriptRegPath -Name "Parameters" -Value ""
                    Set-ItemProperty -Path $ScriptRegPath -Name "IsPowershell" -Value 0
                    Set-ItemProperty -Path $ScriptRegPath -Name "ExecTime" -Value 0
                    
                    Write-Log "Registered startup script: $($Script.Name)" "SUCCESS"
                    $ScriptIndex++
                }
                
                $Results.StartupConfigured = $true
                $Results.Actions += "Configured $($StartupScripts.Count) startup scripts in registry"
            }
        }
        
        # Configure shutdown scripts registry entries
        if ($ScriptCopyResults.ShutdownCopied) {
            Write-Log "Configuring shutdown scripts registry entries..."
            
            $ShutdownScripts = Get-ChildItem -Path $ShutdownDestination -File -ErrorAction SilentlyContinue
            if ($ShutdownScripts.Count -gt 0) {
                $ShutdownRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown"
                
                # Ensure registry path exists
                if (!(Test-Path $ShutdownRegistryPath)) {
                    New-Item -Path $ShutdownRegistryPath -Force | Out-Null
                }
                
                $ScriptIndex = 0
                foreach ($Script in $ShutdownScripts) {
                    $ScriptRegPath = "$ShutdownRegistryPath\$ScriptIndex"
                    
                    if (!(Test-Path $ScriptRegPath)) {
                        New-Item -Path $ScriptRegPath -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path $ScriptRegPath -Name "Script" -Value $Script.FullName
                    Set-ItemProperty -Path $ScriptRegPath -Name "Parameters" -Value ""
                    Set-ItemProperty -Path $ScriptRegPath -Name "IsPowershell" -Value 0
                    Set-ItemProperty -Path $ScriptRegPath -Name "ExecTime" -Value 0
                    
                    Write-Log "Registered shutdown script: $($Script.Name)" "SUCCESS"
                    $ScriptIndex++
                }
                
                $Results.ShutdownConfigured = $true
                $Results.Actions += "Configured $($ShutdownScripts.Count) shutdown scripts in registry"
            }
        }
        
        # Create Group Policy INI file for script configuration
        Write-Log "Creating Group Policy scripts configuration file..."
        $GPScriptsPath = "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts"
        $GPScriptsIniPath = "$GPScriptsPath\psScripts.ini"
        
        if (!(Test-Path $GPScriptsPath)) {
            New-Item -Path $GPScriptsPath -ItemType Directory -Force | Out-Null
        }
        
        $IniContent = @"
[Startup]
0CmdLine=$StartupDestination\*.bat
0Parameters=

[Shutdown]  
0CmdLine=$ShutdownDestination\*.bat
0Parameters=
"@
        
        Set-Content -Path $GPScriptsIniPath -Value $IniContent -Force
        Write-Log "Created Group Policy scripts configuration: $GPScriptsIniPath" "SUCCESS"
        $Results.GroupPolicyConfigured = $true
        $Results.Actions += "Created Group Policy scripts configuration file"
        
        $Results.RegistryConfigured = $true
        
        return $Results
    }
    catch {
        Write-Log "Error configuring startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        $Results.Issues += "Error configuring scripts: $($_.Exception.Message)"
        return $Results
    }
}
#endregion

#region Installation Functions
function Install-CitrixVDA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VDAISOSourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$VDAISOPath,
        
        [Parameter(Mandatory=$false)]
        [string]$LogDir = "C:\Logs"
    )
    
    Write-LogHeader "Citrix VDA Installation from ISO"
    
    $Results = @{
        Success = $false
        RebootRequired = $false
        InstallPath = ""
        InstallLog = ""
        ExitCode = -1
        Issues = @()
        Actions = @()
        MountedDrive = $null
    }
    
    try {
        Write-Log "Installing Citrix VDA from ISO..."
        Write-Log "Source ISO path: $VDAISOSourcePath"
        Write-Log "Destination ISO path: $VDAISOPath"
        
        # Step 1: Copy VDA ISO from network source to local directory
        if (!(Copy-InstallationFile -SourcePath $VDAISOSourcePath -DestinationPath $VDAISOPath -ComponentName "VDA ISO")) {
            throw "Failed to copy VDA ISO from network source to local directory"
        }
        
        if (!(Test-Path $VDAISOPath)) {
            throw "VDA ISO not found at: $VDAISOPath after copy operation"
        }
        
        # Mount the ISO
        Write-Log "Mounting VDA ISO..."
        $MountResult = Mount-DiskImage -ImagePath $VDAISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        $Results.MountedDrive = "${DriveLetter}:"
        Write-Log "ISO mounted to drive: $($Results.MountedDrive)" "SUCCESS"
        
        # Find VDAServerSetup.exe on the mounted ISO
        $VDAInstaller = Get-ChildItem -Path $Results.MountedDrive -Name "VDAServerSetup.exe" -Recurse | Select-Object -First 1
        if (!$VDAInstaller) {
            throw "VDAServerSetup.exe not found on mounted ISO"
        }
        
        $VDAPath = Join-Path $Results.MountedDrive $VDAInstaller
        Write-Log "Found VDA installer: $VDAPath" "SUCCESS"
        
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
    finally {
        # Always unmount the ISO
        if ($Results.MountedDrive) {
            try {
                Write-Log "Unmounting VDA ISO from drive: $($Results.MountedDrive)"
                Dismount-DiskImage -ImagePath $VDAISOPath -ErrorAction SilentlyContinue
                Write-Log "VDA ISO unmounted successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to unmount VDA ISO: $($_.Exception.Message)" "WARN"
            }
        }
    }
}

function Install-PVSTargetDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PVSISOSourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$PVSISOPath
    )
    
    Write-LogHeader "PVS Target Device Installation from ISO"
    
    $Results = @{
        Success = $false
        RebootRequired = $false
        Skipped = $false
        ExitCode = -1
        Issues = @()
        Actions = @()
        MountedDrive = $null
    }
    
    try {
        if ([string]::IsNullOrEmpty($PVSISOSourcePath) -or [string]::IsNullOrEmpty($PVSISOPath)) {
            Write-Log "PVS Target Device installation skipped - source or destination path not provided"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Installing PVS Target Device from ISO..."
        Write-Log "Source ISO path: $PVSISOSourcePath"
        Write-Log "Destination ISO path: $PVSISOPath"
        
        # Step 1: Copy PVS ISO from network source to local directory
        if (!(Copy-InstallationFile -SourcePath $PVSISOSourcePath -DestinationPath $PVSISOPath -ComponentName "PVS ISO")) {
            Write-Log "Failed to copy PVS ISO from network source, skipping installation"
            $Results.Skipped = $true
            return $Results
        }
        
        # Mount the ISO
        Write-Log "Mounting PVS ISO..."
        $MountResult = Mount-DiskImage -ImagePath $PVSISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        $Results.MountedDrive = "${DriveLetter}:"
        Write-Log "ISO mounted to drive: $($Results.MountedDrive)" "SUCCESS"
        
        # Find PVS Agent installer on the mounted ISO
        $PVSInstaller = Get-ChildItem -Path $Results.MountedDrive -Name "*.msi" -Recurse | Where-Object { $_.Name -match "PVS.*Agent|Agent.*PVS" } | Select-Object -First 1
        if (!$PVSInstaller) {
            throw "PVS Agent installer (.msi) not found on mounted ISO"
        }
        
        $PVSPath = $PVSInstaller.FullName
        Write-Log "Found PVS installer: $PVSPath" "SUCCESS"
        
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
    finally {
        # Always unmount the ISO
        if ($Results.MountedDrive) {
            try {
                Write-Log "Unmounting PVS ISO from drive: $($Results.MountedDrive)"
                Dismount-DiskImage -ImagePath $PVSISOPath -ErrorAction SilentlyContinue
                Write-Log "PVS ISO unmounted successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to unmount PVS ISO: $($_.Exception.Message)" "WARN"
            }
        }
    }
}

function Install-WEMAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$WEMSourcePath,
        
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
        if ([string]::IsNullOrEmpty($WEMSourcePath) -or [string]::IsNullOrEmpty($WEMPath)) {
            Write-Log "WEM Agent installation skipped - source or destination path not provided"
            $Results.Skipped = $true
            return $Results
        }
        
        Write-Log "Installing WEM Agent..."
        Write-Log "Source installer path: $WEMSourcePath"
        Write-Log "Destination installer path: $WEMPath"
        
        # Step 1: Copy WEM installer from network source to local directory
        if (!(Copy-InstallationFile -SourcePath $WEMSourcePath -DestinationPath $WEMPath -ComponentName "WEM Agent")) {
            Write-Log "Failed to copy WEM Agent installer from network source, skipping installation"
            $Results.Skipped = $true
            return $Results
        }
        
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
                "MaxMpxCt" = Get-ConfigValue "MaxMpxCt" 800
                "MaxWorkItems" = Get-ConfigValue "MaxWorkItems" 2000
                "MaxRawWorkItems" = Get-ConfigValue "MaxRawWorkItems" 200
                "MaxFreeConnections" = Get-ConfigValue "MaxFreeConnections" 64
                "MinFreeConnections" = Get-ConfigValue "MinFreeConnections" 20
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
            
            # DNS resolver optimizations
            Set-ItemProperty -Path $TcpipParamsPath -Name "MaxHashTableBuckets" -Value 1024 -Type DWord -ErrorAction SilentlyContinue
            
            Write-Log "DNS resolver optimizations applied" "SUCCESS"
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
    <#
    .SYNOPSIS
        Copies startup and shutdown scripts from network location to local folders and registers them via Group Policy
        
    .DESCRIPTION
        Simplified script deployment that copies files and registers them via registry and INI files for both startup and shutdown
        
    .PARAMETER StartupSourcePath
        Network path containing startup scripts
        
    .PARAMETER StartupDestinationPath
        Local destination folder for startup scripts
        
    .PARAMETER ShutdownSourcePath
        Network path containing shutdown scripts
        
    .PARAMETER ShutdownDestinationPath
        Local destination folder for shutdown scripts
        
    .PARAMETER ScriptTypes
        Array of script file patterns to copy
        
    .PARAMETER Force
        Overwrite existing files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$StartupSourcePath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$StartupDestinationPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$ShutdownSourcePath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$ShutdownDestinationPath = "",
        
        [Parameter(Mandatory=$false)]
        [string[]]$ScriptTypes = @("*.ps1", "*.bat", "*.cmd", "*.vbs"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Startup and Shutdown Scripts Management"
    
    try {
        # Use config file values if parameters not provided
        if ($StartupSourcePath -eq "") {
            $StartupSourcePath = Get-ConfigValue "StartupScriptsSource" "\\fileserver\scripts\startup"
        }
        if ($StartupDestinationPath -eq "") {
            $StartupDestinationPath = Get-ConfigValue "StartupScriptsDestination" "C:\Scripts\Startup"
        }
        if ($ShutdownSourcePath -eq "") {
            $ShutdownSourcePath = Get-ConfigValue "ShutdownScriptsSource" "\\fileserver\scripts\shutdown"
        }
        if ($ShutdownDestinationPath -eq "") {
            $ShutdownDestinationPath = Get-ConfigValue "ShutdownScriptsDestination" "C:\Scripts\Shutdown"
        }
        
        Write-Log "Processing startup scripts from: $StartupSourcePath to: $StartupDestinationPath"
        Write-Log "Processing shutdown scripts from: $ShutdownSourcePath to: $ShutdownDestinationPath"
        
        $Results = @{
            Success = $true
            StartupFiles = @()
            ShutdownFiles = @()
            FailedFiles = @()
            RegisteredScripts = @()
            FailedRegistrations = @()
            TotalFiles = 0
            SuccessfulCopies = 0
        }
        
        # Process both startup and shutdown scripts
        $ScriptConfigs = @(
            @{ Type = "Startup"; Source = $StartupSourcePath; Destination = $StartupDestinationPath },
            @{ Type = "Shutdown"; Source = $ShutdownSourcePath; Destination = $ShutdownDestinationPath }
        )
        
        foreach ($Config in $ScriptConfigs) {
            Write-Log "Processing $($Config.Type) scripts..."
            
            # Validate source path (skip if empty)
            if ([string]::IsNullOrEmpty($Config.Source) -or $Config.Source -eq "\\fileserver\scripts\$($Config.Type.ToLower())") {
                Write-Log "Skipping $($Config.Type) scripts - no source configured" "WARN"
                continue
            }
            
            if (!(Test-Path $Config.Source)) {
                Write-Log "$($Config.Type) source path does not exist: $($Config.Source)" "WARN"
                continue
            }
            
            # Create destination directory
            try {
                if (!(Test-Path $Config.Destination)) {
                    New-Item -Path $Config.Destination -ItemType Directory -Force | Out-Null
                    Write-Log "Created $($Config.Type) destination directory: $($Config.Destination)" "SUCCESS"
                }
            }
            catch {
                Write-Log "Failed to create $($Config.Type) destination directory: $($_.Exception.Message)" "ERROR"
                continue
            }
            
            # Find all scripts
            $AllScripts = @()
            foreach ($ScriptType in $ScriptTypes) {
                try {
                    $Scripts = Get-ChildItem -Path $Config.Source -Filter $ScriptType -Recurse -ErrorAction SilentlyContinue
                    $AllScripts += $Scripts
                }
                catch {
                    Write-Log "Warning: Could not search for pattern $ScriptType in $($Config.Type): $($_.Exception.Message)" "WARN"
                }
            }
            
            Write-Log "Found $($AllScripts.Count) $($Config.Type) scripts"
            $Results.TotalFiles += $AllScripts.Count
            
            # Copy each script file
            foreach ($Script in $AllScripts) {
                try {
                    $RelativePath = $Script.FullName.Substring($Config.Source.Length).TrimStart('\')
                    $DestinationFile = Join-Path $Config.Destination $RelativePath
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
                            Type = $Config.Type
                            Source = $Script.FullName
                            Destination = $DestinationFile
                            Reason = "File exists"
                        }
                        continue
                    }
                    
                    Copy-Item -Path $Script.FullName -Destination $DestinationFile -Force:$Force -ErrorAction Stop
                    Write-Log "Copied $($Config.Type): $($Script.Name) -> $RelativePath" "SUCCESS"
                    
                    $FileInfo = @{
                        Name = $Script.Name
                        Type = $Config.Type
                        Source = $Script.FullName
                        Destination = $DestinationFile
                        Size = $Script.Length
                    }
                    
                    if ($Config.Type -eq "Startup") {
                        $Results.StartupFiles += $FileInfo
                    } else {
                        $Results.ShutdownFiles += $FileInfo
                    }
                    
                    $Results.SuccessfulCopies++
                }
                catch {
                    Write-Log "Failed to copy $($Config.Type) script $($Script.Name): $($_.Exception.Message)" "ERROR"
                    $Results.FailedFiles += @{
                        Name = $Script.Name
                        Type = $Config.Type
                        Source = $Script.FullName
                        Destination = $DestinationFile
                        Reason = $_.Exception.Message
                    }
                    $Results.Success = $false
                }
            }
        }
        
        # Register startup and shutdown scripts via Group Policy registry and INI files
        if ($Results.SuccessfulCopies -gt 0) {
            Write-Log "Registering scripts in Group Policy..."
            
            try {
                # Create Group Policy directories if they don't exist
                $GPMachineDir = "C:\Windows\System32\GroupPolicy\Machine"
                $GPScriptsDir = "$GPMachineDir\Scripts"
                $GPStartupDir = "$GPScriptsDir\Startup"
                $GPShutdownDir = "$GPScriptsDir\Shutdown"
                $GPPSScriptsIni = "$GPScriptsDir\psScripts.ini"
                
                if (!(Test-Path $GPMachineDir)) { New-Item -Path $GPMachineDir -ItemType Directory -Force | Out-Null }
                if (!(Test-Path $GPScriptsDir)) { New-Item -Path $GPScriptsDir -ItemType Directory -Force | Out-Null }
                if (!(Test-Path $GPStartupDir)) { New-Item -Path $GPStartupDir -ItemType Directory -Force | Out-Null }
                if (!(Test-Path $GPShutdownDir)) { New-Item -Path $GPShutdownDir -ItemType Directory -Force | Out-Null }
                
                # Process startup and shutdown scripts separately
                $ScriptTypes = @(
                    @{ Type = "Startup"; Files = $Results.StartupFiles; RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup" },
                    @{ Type = "Shutdown"; Files = $Results.ShutdownFiles; RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown" }
                )
                
                $IniContent = @()
                
                foreach ($ScriptType in $ScriptTypes) {
                    if ($ScriptType.Files.Count -gt 0) {
                        Write-Log "Registering $($ScriptType.Type) scripts..."
                        
                        # Create registry path if it doesn't exist
                        if (!(Test-Path $ScriptType.RegPath)) {
                            New-Item -Path $ScriptType.RegPath -Force | Out-Null
                        }
                        
                        # Get existing script count
                        $ExistingScripts = Get-ChildItem -Path $ScriptType.RegPath -ErrorAction SilentlyContinue
                        $StartIndex = $ExistingScripts.Count
                        
                        # Add INI section header
                        $IniContent += "[$($ScriptType.Type)]"
                        
                        foreach ($ScriptFile in $ScriptType.Files) {
                            try {
                                # Only register PowerShell and batch files
                                if ($ScriptFile.Name -match '\.(ps1|bat|cmd)$') {
                                    $ScriptIndex = $StartIndex++
                                    $ScriptKeyPath = "$($ScriptType.RegPath)\$ScriptIndex"
                                    
                                    # Create registry entry
                                    New-Item -Path $ScriptKeyPath -Force | Out-Null
                                    Set-ItemProperty -Path $ScriptKeyPath -Name "Script" -Value $ScriptFile.Destination -Type String
                                    Set-ItemProperty -Path $ScriptKeyPath -Name "Parameters" -Value "" -Type String
                                    Set-ItemProperty -Path $ScriptKeyPath -Name "IsPowershell" -Value $(if($ScriptFile.Name -match '\.ps1$'){1}else{0}) -Type DWord
                                    Set-ItemProperty -Path $ScriptKeyPath -Name "ExecTime" -Value 0 -Type QWord
                                    
                                    # Add to INI content
                                    $IniContent += "${ScriptIndex}CmdLine=$($ScriptFile.Destination)"
                                    $IniContent += "${ScriptIndex}Parameters="
                                    
                                    Write-Log "Registered $($ScriptType.Type) script: $($ScriptFile.Name)" "SUCCESS"
                                    $Results.RegisteredScripts += "$($ScriptType.Type): $($ScriptFile.Name)"
                                }
                            }
                            catch {
                                Write-Log "Failed to register $($ScriptType.Type) script $($ScriptFile.Name): $($_.Exception.Message)" "ERROR"
                                $Results.FailedRegistrations += "$($ScriptType.Type): $($ScriptFile.Name)"
                            }
                        }
                    }
                }
                
                # Write INI file
                if ($IniContent.Count -gt 0) {
                    try {
                        $IniContent | Out-File -FilePath $GPPSScriptsIni -Encoding ASCII -Force
                        Write-Log "Created Group Policy INI file: $GPPSScriptsIni" "SUCCESS"
                    }
                    catch {
                        Write-Log "Failed to create INI file: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
            catch {
                Write-Log "Failed to access Group Policy registry: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Scripts copy operation summary:"
        Write-Log "Total files found: $($Results.TotalFiles)"
        Write-Log "Successfully copied: $($Results.SuccessfulCopies)"
        Write-Log "Failed copies: $($Results.FailedFiles.Count)"
        Write-Log "Registered scripts: $($Results.RegisteredScripts.Count)"
        Write-Log "Startup scripts: $($Results.StartupFiles.Count)"
        Write-Log "Shutdown scripts: $($Results.ShutdownFiles.Count)"
        
        if ($Results.StartupFiles.Count -gt 0) {
            Write-Log "Successfully copied startup files:"
            foreach ($File in $Results.StartupFiles) {
                Write-Log "  ✓ $($File.Name) ($([math]::Round($File.Size/1KB, 2)) KB)" "SUCCESS"
            }
        }
        
        if ($Results.ShutdownFiles.Count -gt 0) {
            Write-Log "Successfully copied shutdown files:"
            foreach ($File in $Results.ShutdownFiles) {
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

function Invoke-CitrixOptimizer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OptimizerPath = "",
        
        [Parameter(Mandatory=$false)]
        [string]$SourceFolder = "",
        
        [Parameter(Mandatory=$false)]
        [string]$TemplateName = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$WaitForCompletion = $true
    )
    
    Write-LogHeader "Citrix Optimizer Execution"
    
    try {
        # Use config file values if parameters not provided
        if ($OptimizerPath -eq "") {
            $OptimizerPath = Get-ConfigValue "CitrixOptimizerPath" "C:\Temp\CitrixOptimizer.exe"
        }
        if ($SourceFolder -eq "") {
            $SourceFolder = Get-ConfigValue "CitrixOptimizerSourceFolder" "C:\Temp\CitrixOptimizer"
        }
        if ($TemplateName -eq "") {
            $TemplateName = Get-ConfigValue "CitrixOptimizerTemplate" "Windows_10_VDI.xml"
        }
        
        # Check if Citrix Optimizer should run
        $RunOptimizer = Get-ConfigValue "RunCitrixOptimizer" $true
        if (!$RunOptimizer) {
            Write-Log "Citrix Optimizer execution disabled in configuration" "INFO"
            return $true
        }
        
        Write-Log "Citrix Optimizer configuration:"
        Write-Log "  Optimizer Path: $OptimizerPath"
        Write-Log "  Source Folder: $SourceFolder"
        Write-Log "  Template: $TemplateName"
        
        # Validate Citrix Optimizer executable
        if (!(Test-Path $OptimizerPath)) {
            Write-Log "Citrix Optimizer executable not found: $OptimizerPath" "ERROR"
            Write-Log "Please ensure CitrixOptimizer.exe is available at the specified location" "ERROR"
            return $false
        }
        
        # Validate source folder
        if (!(Test-Path $SourceFolder)) {
            Write-Log "Citrix Optimizer source folder not found: $SourceFolder" "ERROR"
            Write-Log "Please ensure the Citrix Optimizer folder structure is available" "ERROR"
            return $false
        }
        
        # Look for template file
        $TemplatePath = Join-Path $SourceFolder "Templates\$TemplateName"
        if (!(Test-Path $TemplatePath)) {
            # Try alternative locations
            $AlternativeTemplates = @(
                Join-Path $SourceFolder $TemplateName,
                Join-Path $SourceFolder "templates\$TemplateName",
                "$SourceFolder\$TemplateName"
            )
            
            $TemplateFound = $false
            foreach ($AltPath in $AlternativeTemplates) {
                if (Test-Path $AltPath) {
                    $TemplatePath = $AltPath
                    $TemplateFound = $true
                    break
                }
            }
            
            if (!$TemplateFound) {
                Write-Log "Template file not found: $TemplateName" "ERROR"
                Write-Log "Searched locations:"
                Write-Log "  - $TemplatePath"
                foreach ($AltPath in $AlternativeTemplates) {
                    Write-Log "  - $AltPath"
                }
                
                # List available templates
                $TemplatesDir = Join-Path $SourceFolder "Templates"
                if (Test-Path $TemplatesDir) {
                    $AvailableTemplates = Get-ChildItem -Path $TemplatesDir -Filter "*.xml" -ErrorAction SilentlyContinue
                    if ($AvailableTemplates) {
                        Write-Log "Available templates:"
                        foreach ($Template in $AvailableTemplates) {
                            Write-Log "  - $($Template.Name)"
                        }
                    }
                }
                return $false
            }
        }
        
        Write-Log "Template found: $TemplatePath" "SUCCESS"
        
        # Prepare Citrix Optimizer command line arguments
        $Arguments = @(
            "-t", "`"$TemplatePath`""  # Template path
            "-o"                        # Output mode
        )
        
        Write-Log "Executing Citrix Optimizer..."
        Write-Log "Command: `"$OptimizerPath`" $($Arguments -join ' ')"
        
        # Execute Citrix Optimizer
        $ProcessInfo = @{
            FilePath = $OptimizerPath
            ArgumentList = $Arguments
            WorkingDirectory = $SourceFolder
            NoNewWindow = $true
            Wait = $WaitForCompletion
            PassThru = $true
        }
        
        $Process = Start-Process @ProcessInfo
        
        if ($WaitForCompletion) {
            Write-Log "Waiting for Citrix Optimizer to complete..."
            
            # Monitor process with timeout (30 minutes max)
            $TimeoutMinutes = 30
            $TimeoutSeconds = $TimeoutMinutes * 60
            $ElapsedSeconds = 0
            
            while (!$Process.HasExited -and $ElapsedSeconds -lt $TimeoutSeconds) {
                Start-Sleep -Seconds 10
                $ElapsedSeconds += 10
                
                if ($ElapsedSeconds % 60 -eq 0) {
                    $MinutesElapsed = $ElapsedSeconds / 60
                    Write-Log "Citrix Optimizer running... ($MinutesElapsed minutes elapsed)" "INFO"
                }
            }
            
            if (!$Process.HasExited) {
                Write-Log "Citrix Optimizer exceeded timeout of $TimeoutMinutes minutes" "ERROR"
                try {
                    $Process.Kill()
                    Write-Log "Process terminated due to timeout" "WARN"
                }
                catch {
                    Write-Log "Could not terminate process: $($_.Exception.Message)" "ERROR"
                }
                return $false
            }
            
            $ExitCode = $Process.ExitCode
            $ExecutionTime = [math]::Round(($Process.ExitTime - $Process.StartTime).TotalMinutes, 2)
            
            Write-Log "Citrix Optimizer completed in $ExecutionTime minutes" "INFO"
            Write-Log "Exit Code: $ExitCode"
            
            if ($ExitCode -eq 0) {
                Write-Log "Citrix Optimizer executed successfully" "SUCCESS"
                
                # Check for output files or logs
                $LogFiles = @(
                    Join-Path $SourceFolder "CitrixOptimizer.log",
                    Join-Path $env:TEMP "CitrixOptimizer.log",
                    Join-Path $SourceFolder "Logs\CitrixOptimizer.log"
                )
                
                foreach ($LogFile in $LogFiles) {
                    if (Test-Path $LogFile) {
                        Write-Log "Citrix Optimizer log available: $LogFile" "INFO"
                        
                        # Copy log to our log directory for reference
                        try {
                            $DestLogPath = Join-Path (Split-Path $Global:LogPath -Parent) "CitrixOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                            Copy-Item -Path $LogFile -Destination $DestLogPath -ErrorAction SilentlyContinue
                            Write-Log "Citrix Optimizer log copied to: $DestLogPath" "SUCCESS"
                        }
                        catch {
                            Write-Log "Could not copy Citrix Optimizer log: $($_.Exception.Message)" "WARN"
                        }
                        break
                    }
                }
                
                return $true
            }
            else {
                Write-Log "Citrix Optimizer failed with exit code: $ExitCode" "ERROR"
                return $false
            }
        }
        else {
            Write-Log "Citrix Optimizer started in background mode" "INFO"
            Write-Log "Process ID: $($Process.Id)" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Citrix Optimizer execution failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disable-CitrixServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$ServiceNames = @(),
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    Write-LogHeader "Citrix Services Management"
    
    try {
        # Check if service disabling is enabled
        $DisableServices = Get-ConfigValue "DisableCitrixServices" $false
        if (!$DisableServices) {
            Write-Log "Citrix service disabling is disabled in configuration" "INFO"
            return $true
        }
        
        # Use config file values if parameters not provided
        if ($ServiceNames.Count -eq 0) {
            $ServicesConfig = Get-ConfigValue "CitrixServicesToDisable" ""
            if ([string]::IsNullOrEmpty($ServicesConfig)) {
                Write-Log "No Citrix services specified for disabling in configuration" "INFO"
                return $true
            }
            $ServiceNames = $ServicesConfig.Split(",") | ForEach-Object { $_.Trim() }
        }
        
        if ($ServiceNames.Count -eq 0) {
            Write-Log "No Citrix services specified for disabling" "INFO"
            return $true
        }
        
        Write-Log "Citrix services to disable: $($ServiceNames -join ', ')"
        
        $Results = @{
            Success = $true
            ProcessedServices = 0
            DisabledServices = 0
            NotFoundServices = 0
            FailedServices = 0
            ServiceDetails = @()
        }
        
        foreach ($ServiceName in $ServiceNames) {
            $Results.ProcessedServices++
            
            $ServiceInfo = @{
                Name = $ServiceName
                DisplayName = ""
                OriginalStatus = ""
                OriginalStartType = ""
                CurrentStatus = ""
                CurrentStartType = ""
                Success = $false
                Message = ""
            }
            
            try {
                Write-Log "Processing service: $ServiceName"
                
                # Check if service exists
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if (!$Service) {
                    Write-Log "Service not found: $ServiceName" "WARN"
                    $ServiceInfo.Message = "Service not found"
                    $Results.NotFoundServices++
                    $Results.ServiceDetails += $ServiceInfo
                    continue
                }
                
                $ServiceInfo.DisplayName = $Service.DisplayName
                $ServiceInfo.OriginalStatus = $Service.Status
                
                # Get startup type from WMI for more detailed information
                try {
                    $WmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                    if ($WmiService) {
                        $ServiceInfo.OriginalStartType = $WmiService.StartMode
                    }
                }
                catch {
                    Write-Log "Could not retrieve startup type for $ServiceName via WMI" "DEBUG"
                }
                
                Write-Log "  Display Name: $($ServiceInfo.DisplayName)"
                Write-Log "  Current Status: $($ServiceInfo.OriginalStatus)"
                Write-Log "  Current Start Type: $($ServiceInfo.OriginalStartType)"
                
                # Stop the service if it's running
                if ($Service.Status -eq "Running") {
                    Write-Log "  Stopping service: $ServiceName"
                    try {
                        Stop-Service -Name $ServiceName -Force:$Force -ErrorAction Stop
                        Write-Log "  Service stopped successfully" "SUCCESS"
                    }
                    catch {
                        Write-Log "  Failed to stop service: $($_.Exception.Message)" "ERROR"
                        $ServiceInfo.Message = "Failed to stop: $($_.Exception.Message)"
                        $Results.FailedServices++
                        $Results.ServiceDetails += $ServiceInfo
                        $Results.Success = $false
                        continue
                    }
                }
                
                # Disable the service
                Write-Log "  Disabling service startup: $ServiceName"
                try {
                    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                    Write-Log "  Service startup disabled successfully" "SUCCESS"
                    
                    # Verify the change
                    $UpdatedService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                    if ($UpdatedService) {
                        $ServiceInfo.CurrentStatus = $UpdatedService.Status
                        
                        # Get updated startup type
                        try {
                            $UpdatedWmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                            if ($UpdatedWmiService) {
                                $ServiceInfo.CurrentStartType = $UpdatedWmiService.StartMode
                            }
                        }
                        catch {
                            $ServiceInfo.CurrentStartType = "Disabled"
                        }
                        
                        Write-Log "  Verification - Status: $($ServiceInfo.CurrentStatus), Start Type: $($ServiceInfo.CurrentStartType)" "INFO"
                    }
                    
                    $ServiceInfo.Success = $true
                    $ServiceInfo.Message = "Successfully disabled"
                    $Results.DisabledServices++
                }
                catch {
                    Write-Log "  Failed to disable service: $($_.Exception.Message)" "ERROR"
                    $ServiceInfo.Message = "Failed to disable: $($_.Exception.Message)"
                    $Results.FailedServices++
                    $Results.Success = $false
                }
                
                $Results.ServiceDetails += $ServiceInfo
            }
            catch {
                Write-Log "Error processing service $ServiceName`: $($_.Exception.Message)" "ERROR"
                $ServiceInfo.Message = "Processing error: $($_.Exception.Message)"
                $Results.FailedServices++
                $Results.ServiceDetails += $ServiceInfo
                $Results.Success = $false
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Citrix services management summary:"
        Write-Log "Total services processed: $($Results.ProcessedServices)"
        Write-Log "Successfully disabled: $($Results.DisabledServices)"
        Write-Log "Services not found: $($Results.NotFoundServices)"
        Write-Log "Failed operations: $($Results.FailedServices)"
        
        if ($Results.ServiceDetails.Count -gt 0) {
            Write-Log ""
            Write-Log "Service operation details:"
            foreach ($Detail in $Results.ServiceDetails) {
                $Status = if($Detail.Success) { "SUCCESS" } else { "FAILED" }
                $StatusIcon = if($Detail.Success) { "✓" } else { "✗" }
                Write-Log "  $StatusIcon $($Detail.Name) ($($Detail.DisplayName)): $($Detail.Message)" $(if($Detail.Success){"SUCCESS"}else{"ERROR"})
                
                if ($Detail.Success) {
                    Write-Log "    Before: $($Detail.OriginalStatus) / $($Detail.OriginalStartType)" "INFO"
                    Write-Log "    After:  $($Detail.CurrentStatus) / $($Detail.CurrentStartType)" "INFO"
                }
            }
        }
        
        if ($Results.NotFoundServices -gt 0) {
            Write-Log ""
            Write-Log "Note: Some services were not found. This is normal if certain Citrix components are not installed." "INFO"
        }
        
        if ($Results.DisabledServices -gt 0) {
            Write-Log "Successfully disabled $($Results.DisabledServices) Citrix service(s)" "SUCCESS"
        }
        
        if ($Results.FailedServices -gt 0) {
            Write-Log "Failed to disable $($Results.FailedServices) service(s)" "WARN"
        }
        
        return $Results.Success
    }
    catch {
        Write-Log "Citrix services management failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Configure-EventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogsLocation = "",
        
        [Parameter(Mandatory=$false)]
        [int]$MaxSizeMB = 0,
        
        [Parameter(Mandatory=$false)]
        [string[]]$LogsToRelocate = @()
    )
    
    Write-LogHeader "Event Logs Configuration"
    
    try {
        # Check if event logs configuration is enabled
        $ConfigureLogs = Get-ConfigValue "ConfigureEventLogs" $false
        if (!$ConfigureLogs) {
            Write-Log "Event logs configuration is disabled in configuration" "INFO"
            return $true
        }
        
        # Use config file values if parameters not provided
        if ([string]::IsNullOrEmpty($LogsLocation)) {
            $LogsLocation = Get-ConfigValue "EventLogsLocation" "D:\Logs\EventLogs"
        }
        if ($MaxSizeMB -eq 0) {
            $MaxSizeMB = Get-ConfigValue "EventLogsMaxSizeMB" 512
        }
        if ($LogsToRelocate.Count -eq 0) {
            $LogsConfig = Get-ConfigValue "EventLogsToRelocate" ""
            if (![string]::IsNullOrEmpty($LogsConfig)) {
                $LogsToRelocate = $LogsConfig.Split(",") | ForEach-Object { $_.Trim() }
            }
        }
        
        Write-Log "Event logs configuration:"
        Write-Log "  Target Location: $LogsLocation"
        Write-Log "  Max Size: $MaxSizeMB MB"
        Write-Log "  Logs to relocate: $($LogsToRelocate -join ', ')"
        
        # Create target directory
        try {
            if (!(Test-Path $LogsLocation)) {
                New-Item -Path $LogsLocation -ItemType Directory -Force | Out-Null
                Write-Log "Created event logs directory: $LogsLocation" "SUCCESS"
            }
            
            # Test write permissions
            $TestFile = Join-Path $LogsLocation "test_permissions.tmp"
            try {
                "test" | Out-File -FilePath $TestFile -ErrorAction Stop
                Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
                Write-Log "Write permissions verified for: $LogsLocation" "SUCCESS"
            }
            catch {
                Write-Log "No write permissions to: $LogsLocation" "ERROR"
                Write-Log "Error: $($_.Exception.Message)" "ERROR"
                return $false
            }
        }
        catch {
            Write-Log "Failed to create event logs directory: $($_.Exception.Message)" "ERROR"
            return $false
        }
        
        $Results = @{
            Success = $true
            ProcessedLogs = 0
            SuccessfulConfigurations = 0
            FailedConfigurations = 0
            LogDetails = @()
        }
        
        foreach ($LogName in $LogsToRelocate) {
            $Results.ProcessedLogs++
            
            $LogInfo = @{
                Name = $LogName
                OriginalLocation = ""
                NewLocation = ""
                OriginalMaxSize = 0
                NewMaxSize = $MaxSizeMB
                Success = $false
                Message = ""
            }
            
            try {
                Write-Log "Configuring event log: $LogName"
                
                # Get current log configuration
                try {
                    $CurrentLog = Get-WinEvent -ListLog $LogName -ErrorAction Stop
                    $LogInfo.OriginalLocation = $CurrentLog.LogFilePath
                    $LogInfo.OriginalMaxSize = [math]::Round($CurrentLog.MaximumSizeInBytes / 1MB, 0)
                    
                    Write-Log "  Current location: $($LogInfo.OriginalLocation)"
                    Write-Log "  Current max size: $($LogInfo.OriginalMaxSize) MB"
                }
                catch {
                    Write-Log "  Could not retrieve current configuration for $LogName`: $($_.Exception.Message)" "WARN"
                    $LogInfo.Message = "Could not retrieve current config: $($_.Exception.Message)"
                    $Results.FailedConfigurations++
                    $Results.LogDetails += $LogInfo
                    continue
                }
                
                # Construct new log file path
                $SafeLogName = $LogName -replace '[\\/:*?"<>|]', '_'
                $NewLogPath = Join-Path $LogsLocation "$SafeLogName.evtx"
                $LogInfo.NewLocation = $NewLogPath
                
                Write-Log "  New location: $NewLogPath"
                Write-Log "  New max size: $MaxSizeMB MB"
                
                # Configure the event log
                try {
                    # Use wevtutil to configure the log
                    $WevtutilArgs = @(
                        "sl",
                        "`"$LogName`"",
                        "/lfn:`"$NewLogPath`"",
                        "/ms:$($MaxSizeMB * 1024 * 1024)"
                    )
                    
                    Write-Log "  Executing: wevtutil $($WevtutilArgs -join ' ')" "DEBUG"
                    
                    $Process = Start-Process -FilePath "wevtutil.exe" -ArgumentList $WevtutilArgs -Wait -NoNewWindow -PassThru -RedirectStandardError "NUL"
                    
                    if ($Process.ExitCode -eq 0) {
                        Write-Log "  Event log configured successfully" "SUCCESS"
                        $LogInfo.Success = $true
                        $LogInfo.Message = "Successfully configured"
                        $Results.SuccessfulConfigurations++
                        
                        # Verify the configuration
                        try {
                            $UpdatedLog = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
                            if ($UpdatedLog) {
                                Write-Log "  Verification - New location: $($UpdatedLog.LogFilePath)" "INFO"
                                Write-Log "  Verification - New max size: $([math]::Round($UpdatedLog.MaximumSizeInBytes / 1MB, 0)) MB" "INFO"
                            }
                        }
                        catch {
                            Write-Log "  Could not verify configuration changes" "DEBUG"
                        }
                    }
                    else {
                        Write-Log "  Failed to configure event log (Exit code: $($Process.ExitCode))" "ERROR"
                        $LogInfo.Message = "wevtutil failed with exit code: $($Process.ExitCode)"
                        $Results.FailedConfigurations++
                        $Results.Success = $false
                    }
                }
                catch {
                    Write-Log "  Failed to execute wevtutil: $($_.Exception.Message)" "ERROR"
                    $LogInfo.Message = "Execution error: $($_.Exception.Message)"
                    $Results.FailedConfigurations++
                    $Results.Success = $false
                }
                
                $Results.LogDetails += $LogInfo
            }
            catch {
                Write-Log "Error processing event log $LogName`: $($_.Exception.Message)" "ERROR"
                $LogInfo.Message = "Processing error: $($_.Exception.Message)"
                $Results.FailedConfigurations++
                $Results.LogDetails += $LogInfo
                $Results.Success = $false
            }
        }
        
        # Summary report
        Write-Log ""
        Write-Log "Event logs configuration summary:"
        Write-Log "Total logs processed: $($Results.ProcessedLogs)"
        Write-Log "Successfully configured: $($Results.SuccessfulConfigurations)"
        Write-Log "Failed configurations: $($Results.FailedConfigurations)"
        
        if ($Results.LogDetails.Count -gt 0) {
            Write-Log ""
            Write-Log "Event log configuration details:"
            foreach ($Detail in $Results.LogDetails) {
                $StatusIcon = if($Detail.Success) { "✓" } else { "✗" }
                Write-Log "  $StatusIcon $($Detail.Name): $($Detail.Message)" $(if($Detail.Success){"SUCCESS"}else{"ERROR"})
                
                if ($Detail.Success) {
                    Write-Log "    Location: $($Detail.OriginalLocation) → $($Detail.NewLocation)" "INFO"
                    Write-Log "    Max Size: $($Detail.OriginalMaxSize) MB → $($Detail.NewMaxSize) MB" "INFO"
                }
            }
        }
        
        if ($Results.SuccessfulConfigurations -gt 0) {
            Write-Log "Successfully configured $($Results.SuccessfulConfigurations) event log(s)" "SUCCESS"
            Write-Log "Note: Some changes may require system restart to take full effect" "INFO"
        }
        
        if ($Results.FailedConfigurations -gt 0) {
            Write-Log "Failed to configure $($Results.FailedConfigurations) event log(s)" "WARN"
        }
        
        return $Results.Success
    }
    catch {
        Write-Log "Event logs configuration failed: $($_.Exception.Message)" "ERROR"
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

function Remove-DomainUserProfiles {
    <#
    .SYNOPSIS
        Removes domain user profiles from the system to ensure clean OS layer
    
    .DESCRIPTION
        Identifies and removes all domain user profiles while preserving local accounts
        and system profiles. Checks both standard C:\Users and redirected D:\Users
        locations. Used during OS layer preparation to remove any domain user profiles
        that may have been created during installation.
    
    .EXAMPLE
        $Result = Remove-DomainUserProfiles
        
    .OUTPUTS
        Returns hashtable with cleanup results and profile information
    #>
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Domain User Profile Cleanup"
    
    $Results = @{
        Success = $true
        ProfilesRemoved = 0
        RemovedProfiles = @()
        PreservedProfiles = @()
        Issues = @()
        TotalProfilesFound = 0
    }
    
    try {
        Write-Log "Scanning for user profiles on the system..."
        
        # Get all user profiles from registry
        $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $ProfileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue
        
        if (!$ProfileKeys) {
            Write-Log "No user profiles found in registry" "INFO"
            return $Results
        }
        
        $Results.TotalProfilesFound = $ProfileKeys.Count
        Write-Log "Found $($ProfileKeys.Count) user profiles in registry"
        
        foreach ($ProfileKey in $ProfileKeys) {
            try {
                $ProfilePath = $ProfileKey.PSChildName
                $ProfileData = Get-ItemProperty -Path $ProfileKey.PSPath -ErrorAction SilentlyContinue
                
                if (!$ProfileData -or !$ProfileData.ProfileImagePath) {
                    continue
                }
                
                $ProfileImagePath = $ProfileData.ProfileImagePath
                $ProfileName = Split-Path $ProfileImagePath -Leaf
                
                # Skip system profiles and local accounts
                $SystemProfiles = @(
                    'Administrator', 'DefaultAppPool', 'systemprofile', 'LocalService', 
                    'NetworkService', 'Default', 'Public', 'All Users', 'TEMP'
                )
                
                # Check if this is a system profile
                if ($SystemProfiles -contains $ProfileName) {
                    Write-Log "Preserving system profile: $ProfileName" "INFO"
                    $Results.PreservedProfiles += $ProfileName
                    continue
                }
                
                # Check if this is a local account (no domain prefix)
                if ($ProfileName -notmatch '\.') {
                    Write-Log "Preserving local account profile: $ProfileName" "INFO"
                    $Results.PreservedProfiles += $ProfileName
                    continue
                }
                
                # Check if profile directory exists
                if (!(Test-Path $ProfileImagePath)) {
                    Write-Log "Profile directory not found: $ProfileImagePath" "DEBUG"
                    continue
                }
                
                # This appears to be a domain profile - remove it
                Write-Log "Removing domain profile: $ProfileName" "INFO"
                Write-Log "  Profile path: $ProfileImagePath" "DEBUG"
                
                # Remove profile directory
                try {
                    Remove-Item -Path $ProfileImagePath -Recurse -Force -ErrorAction Stop
                    Write-Log "  Directory removed successfully" "SUCCESS"
                }
                catch {
                    Write-Log "  Warning: Could not remove directory: $($_.Exception.Message)" "WARN"
                    $Results.Issues += "Failed to remove directory for $ProfileName"
                }
                
                # Also check for redirected profiles in D:\Users
                $RedirectedProfilePath = "D:\Users\$ProfileName"
                if (Test-Path $RedirectedProfilePath) {
                    Write-Log "  Found redirected profile in D:\Users: $ProfileName" "INFO"
                    try {
                        Remove-Item -Path $RedirectedProfilePath -Recurse -Force -ErrorAction Stop
                        Write-Log "  Redirected profile directory removed successfully" "SUCCESS"
                    }
                    catch {
                        Write-Log "  Warning: Could not remove redirected profile: $($_.Exception.Message)" "WARN"
                        $Results.Issues += "Failed to remove redirected profile for $ProfileName"
                    }
                }
                
                # Remove registry entry
                try {
                    Remove-Item -Path $ProfileKey.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Log "  Registry entry removed successfully" "SUCCESS"
                }
                catch {
                    Write-Log "  Warning: Could not remove registry entry: $($_.Exception.Message)" "WARN"
                    $Results.Issues += "Failed to remove registry entry for $ProfileName"
                }
                
                $Results.ProfilesRemoved++
                $Results.RemovedProfiles += $ProfileName
                Write-Log "Domain profile '$ProfileName' removed successfully" "SUCCESS"
            }
            catch {
                Write-Log "Error processing profile $($ProfileKey.PSChildName): $($_.Exception.Message)" "ERROR"
                $Results.Issues += "Error processing profile: $($_.Exception.Message)"
            }
        }
        
        # Additional cleanup for any orphaned profile directories in D:\Users
        Write-Log "Checking for orphaned profile directories in D:\Users..." "INFO"
        if (Test-Path "D:\Users") {
            $DUserProfiles = Get-ChildItem -Path "D:\Users" -Directory -ErrorAction SilentlyContinue
            foreach ($DProfile in $DUserProfiles) {
                $DProfileName = $DProfile.Name
                
                # Skip system and local account directories
                $SystemProfiles = @(
                    'Administrator', 'DefaultAppPool', 'systemprofile', 'LocalService', 
                    'NetworkService', 'Default', 'Public', 'All Users', 'TEMP'
                )
                
                if ($SystemProfiles -contains $DProfileName -or $DProfileName -notmatch '\.') {
                    continue
                }
                
                # Check if this appears to be a domain profile directory
                if ($DProfileName -match '\.') {
                    Write-Log "Found orphaned domain profile directory: D:\Users\$DProfileName" "INFO"
                    try {
                        Remove-Item -Path $DProfile.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "  Orphaned profile directory removed: $DProfileName" "SUCCESS"
                    }
                    catch {
                        Write-Log "  Warning: Could not remove orphaned directory: $($_.Exception.Message)" "WARN"
                        $Results.Issues += "Failed to remove orphaned directory: $DProfileName"
                    }
                }
            }
        }
        
        Write-Log "Domain profile cleanup completed" "SUCCESS"
        Write-Log "  Total profiles found: $($Results.TotalProfilesFound)"
        Write-Log "  Domain profiles removed: $($Results.ProfilesRemoved)"
        Write-Log "  System/Local profiles preserved: $($Results.PreservedProfiles.Count)"
        Write-Log "  Profile locations checked: C:\Users and D:\Users"
        
        if ($Results.Issues.Count -gt 0) {
            Write-Log "Profile cleanup completed with $($Results.Issues.Count) issues" "WARN"
            foreach ($Issue in $Results.Issues) {
                Write-Log "  - $Issue" "WARN"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Critical error during domain profile cleanup: $($_.Exception.Message)" "ERROR"
        $Results.Success = $false
        $Results.Issues += "Critical error: $($_.Exception.Message)"
        return $Results
    }
}
#endregion

# Export functions for module use
Export-ModuleMember -Function *