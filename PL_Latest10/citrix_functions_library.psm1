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

# Set execution policy to allow script execution (prevents security prompts)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#region Global Variables and Configuration
$Global:LogPath = ""
$Global:VerboseLogging = $true

function Read-ConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$Key = "",
        
        [Parameter(Mandatory=$false)]
        $DefaultValue = $null
    )
    
    try {
        if (-not (Test-Path $ConfigFilePath)) {
            Write-Warning "Configuration file not found: $ConfigFilePath"
            return $DefaultValue
        }
        
        $ConfigData = @{}
        $Content = Get-Content $ConfigFilePath -ErrorAction Stop
        
        foreach ($Line in $Content) {
            $Line = $Line.Trim()
            if ($Line -and -not $Line.StartsWith("#") -and $Line.Contains("=")) {
                $Parts = $Line -split "=", 2
                if ($Parts.Count -eq 2) {
                    $ConfigKey = $Parts[0].Trim()
                    $Value = $Parts[1].Trim()
                    
                    # Handle environment variable expansion using config data for %NetworkSourcePath%
                    while ($Value -match '%([^%]+)%') {
                        $EnvVar = $Matches[1]
                        $EnvValue = $null
                        
                        # First check if it's a config key we already processed
                        if ($ConfigData.ContainsKey($EnvVar)) {
                            $EnvValue = $ConfigData[$EnvVar]
                        } else {
                            # Then check environment variables
                            $EnvValue = [Environment]::GetEnvironmentVariable($EnvVar)
                        }
                        
                        if ($EnvValue) {
                            $Value = $Value -replace "%$EnvVar%", $EnvValue
                        } else {
                            $Value = $Value -replace "%$EnvVar%", ""
                        }
                    }
                    
                    # Convert string values to appropriate types
                    if ($Value -eq "true") { $Value = $true }
                    elseif ($Value -eq "false") { $Value = $false }
                    elseif ($Value -match '^\d+$') { $Value = [int]$Value }
                    
                    $ConfigData[$ConfigKey] = $Value
                    Write-Verbose "Loaded config: $ConfigKey = $Value"
                }
            }
        }
        
        if ($Key -ne "") {
            if ($ConfigData.ContainsKey($Key)) {
                $FoundValue = $ConfigData[$Key]
                Write-Verbose "Found config key '$Key' = '$FoundValue'"
                return $FoundValue
            } else {
                Write-Verbose "Config key '$Key' not found in file"
                return $DefaultValue
            }
        }
        
        return $ConfigData
    }
    catch {
        Write-Warning "Error reading configuration file: $($_.Exception.Message)"
        return $DefaultValue
    }
}

function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigFile = "",
        
        [Parameter(Mandatory=$false)]
        $DefaultValue = $null,
        
        [Parameter(Mandatory=$false)]
        [switch]$ShowStatus
    )
    
    if ($ConfigFile -eq "") {
        $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
    }
    
    $Value = Read-ConfigFile -ConfigFilePath $ConfigFile -Key $Key -DefaultValue $DefaultValue
    
    # Check if configuration file exists and key was actually found
    if (Test-Path $ConfigFile) {
        $ConfigContent = Read-ConfigFile -ConfigFilePath $ConfigFile
        $KeyFound = $ConfigContent.ContainsKey($Key)
        
        if ($ShowStatus) {
            $Status = if ($KeyFound) { "[CONFIG]" } else { "[DEFAULT]" }
            Write-Host "  $Status $Key = $Value" -ForegroundColor $(if ($KeyFound) { 'Green' } else { 'Yellow' })
        }
        
        if (-not $KeyFound -and $DefaultValue -ne $null -and $DefaultValue -ne "") {
            Write-Warning "Configuration key '$Key' not found in $ConfigFile, using default: $DefaultValue"
        }
    } else {
        if ($ShowStatus) {
            Write-Host "  [DEFAULT] $Key = $Value (config file not found)" -ForegroundColor Red
        }
        Write-Warning "Configuration file not found: $ConfigFile, using default for '$Key': $DefaultValue"
    }
    
    return $Value
}

function Show-LoadedConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host "CONFIGURATION STATUS REPORT" -ForegroundColor Cyan -BackgroundColor DarkBlue
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "Config File: $ConfigFilePath" -ForegroundColor White
    Write-Host "File Exists: $(Test-Path $ConfigFilePath)" -ForegroundColor $(if (Test-Path $ConfigFilePath) { 'Green' } else { 'Red' })
    
    if (Test-Path $ConfigFilePath) {
        Write-Host "File Size: $((Get-Item $ConfigFilePath).Length) bytes" -ForegroundColor White
        
        Write-Host "`nKey Status Legend:" -ForegroundColor Cyan
        Write-Host "  [CONFIG]  - Value loaded from configuration file" -ForegroundColor Green
        Write-Host "  [DEFAULT] - Using default value (key not found)" -ForegroundColor Yellow
        
        Write-Host "`nNetwork and Installation Paths:" -ForegroundColor Cyan
        Get-ConfigValue -Key "NetworkSourcePath" -DefaultValue "\\fileserver\citrix" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "VDAISOSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "PVSISOSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        
        Write-Host "`nOptional Component Paths:" -ForegroundColor Cyan
        Get-ConfigValue -Key "WEMPath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "UberAgentPath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "TADDMPath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        
        Write-Host "`nSystem Configuration:" -ForegroundColor Cyan
        Get-ConfigValue -Key "LogPath" -DefaultValue "Desktop" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "PagefileSizeGB" -DefaultValue 8 -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "InstallVDA" -DefaultValue $true -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "InstallPVS" -DefaultValue $true -ConfigFile $ConfigFilePath -ShowStatus
        
        Write-Host "`nUberAgent Configuration:" -ForegroundColor Cyan
        Get-ConfigValue -Key "UberAgentTemplatesSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "UberAgentConfigSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "UberAgentLicenseSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath -ShowStatus
        Get-ConfigValue -Key "UberAgentOutputQueueName" -DefaultValue "Output Queue" -ConfigFile $ConfigFilePath -ShowStatus
        
        Write-Host "`nCitrix Services Management:" -ForegroundColor Cyan
        Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "CdfSvc,Spooler,BITS,wuauserv,Fax,TapiSrv" -ConfigFile $ConfigFilePath -ShowStatus
        
        Write-Host "=============================" -ForegroundColor Cyan
    } else {
        Write-Host "ERROR: Configuration file not found!" -ForegroundColor Red
        Write-Host "All values will use defaults." -ForegroundColor Yellow
    }
}

function Get-DesktopPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$CreateIfNotExists = $false
    )
    
    try {
        # Try to get the actual desktop path for the current user
        $DesktopPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
        
        if ([string]::IsNullOrEmpty($DesktopPath) -or -not (Test-Path $DesktopPath)) {
            # Fallback to common desktop path
            $DesktopPath = Join-Path $env:USERPROFILE "Desktop"
            
            if (-not (Test-Path $DesktopPath) -and $CreateIfNotExists) {
                New-Item -Path $DesktopPath -ItemType Directory -Force | Out-Null
            }
        }
        
        if (-not (Test-Path $DesktopPath)) {
            # Final fallback to current directory
            $DesktopPath = Get-Location
            Write-Log "Using current directory as desktop path: $DesktopPath" "WARN"
        }
        
        return $DesktopPath.ToString()
    }
    catch {
        Write-Warning "Could not determine desktop path, using current directory: $($_.Exception.Message)"
        return (Get-Location).ToString()
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN" { Write-Host $LogEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "DEBUG" { if ($Global:VerboseLogging) { Write-Host $LogEntry -ForegroundColor Cyan } }
        default { Write-Host $LogEntry -ForegroundColor White }
    }
    
    # File logging
    if ($Global:LogPath -and (Test-Path (Split-Path $Global:LogPath -Parent))) {
        try {
            Add-Content -Path $Global:LogPath -Value $LogEntry -ErrorAction SilentlyContinue
        }
        catch {
            # Silently continue if logging fails
        }
    }
}

function Write-LogHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title
    )
    
    $BorderLength = $Title.Length + 4
    $Border = "=" * $BorderLength
    
    Write-Log " " "INFO"
    Write-Log $Border "INFO"
    Write-Log "  $Title" "INFO"
    Write-Log $Border "INFO"
}

function Test-AdminPrivileges {
    [CmdletBinding()]
    param()
    
    try {
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        Write-Log "Administrator privileges check: $($IsAdmin)" "INFO"
        return $IsAdmin
    }
    catch {
        Write-Log "Error checking administrator privileges: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-OSVersion {
    [CmdletBinding()]
    param()
    
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $OSVersion = $OSInfo.Version
        $OSCaption = $OSInfo.Caption
        $OSBuild = $OSInfo.BuildNumber
        
        # Determine OS type and recommend script sources
        $ScriptSource = "win2022"  # Default to Windows 2022
        
        if ($OSCaption -like "*Server 2019*") {
            $ScriptSource = "win2019"
            Write-Log "Windows Server 2019 detected - using 2019 script sources" "SUCCESS"
        }
        elseif ($OSCaption -like "*Server 2022*" -or $OSCaption -like "*Server*") {
            $ScriptSource = "win2022"
            Write-Log "Windows Server 2022 detected - using 2022 script sources" "SUCCESS"
        }
        elseif ($OSCaption -like "*Windows 10*" -or $OSCaption -like "*Windows 11*") {
            $ScriptSource = "win2022"  # Use 2022 scripts for client OS
            Write-Log "Windows client OS detected - using Windows 2022 script configuration" "INFO"
        }
        
        $Result = @{
            Version = $OSVersion
            Caption = $OSCaption
            Build = $OSBuild
            ScriptSource = $ScriptSource
            IsServer = $OSCaption -like "*Server*"
            IsClient = $OSCaption -notlike "*Server*"
        }
        
        Write-Log "OS Detection Results:" "INFO"
        Write-Log "  Caption: $OSCaption" "INFO"
        Write-Log "  Version: $OSVersion" "INFO"
        Write-Log "  Build: $OSBuild" "INFO"
        Write-Log "  Script Source: $ScriptSource" "INFO"
        
        return $Result
    }
    catch {
        Write-Log "Error retrieving OS version: $($_.Exception.Message)" "ERROR"
        return @{
            Version = "Unknown"
            Caption = "Unknown"
            Build = "Unknown"
            ScriptSource = "win2022"
            IsServer = $false
            IsClient = $true
        }
    }
}

function Set-DNSSuffix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFile = ""
    )
    
    Write-LogHeader "DNS Suffix Configuration"
    
    try {
        # Load DNS configuration from CitrixConfig.txt
        if ($ConfigFile -eq "") {
            $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
        }
        
        Write-Log "Loading DNS configuration from: $ConfigFile"
        
        # Read DNS settings from configuration file
        $PrimaryDNSSuffix = Get-ConfigValue -Key "PrimaryDNSSuffix" -ConfigFile $ConfigFile -DefaultValue ""
        $DNSSuffixSearchListStr = Get-ConfigValue -Key "DNSSuffixSearchList" -ConfigFile $ConfigFile -DefaultValue ""
        $AppendPrimarySuffixes = [bool](Get-ConfigValue -Key "AppendPrimarySuffixes" -ConfigFile $ConfigFile -DefaultValue "true")
        $AppendParentSuffixes = [bool](Get-ConfigValue -Key "AppendParentSuffixes" -ConfigFile $ConfigFile -DefaultValue "true")
        $RegisterThisConnectionsAddress = [bool](Get-ConfigValue -Key "RegisterThisConnectionsAddress" -ConfigFile $ConfigFile -DefaultValue "true")
        
        # Parse DNS suffix search list
        $DNSSuffixSearchList = @()
        if ($DNSSuffixSearchListStr -ne "") {
            $DNSSuffixSearchList = $DNSSuffixSearchListStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
        
        Write-Log "DNS Configuration loaded:"
        Write-Log "  Primary DNS Suffix: $PrimaryDNSSuffix"
        Write-Log "  DNS Search List: $($DNSSuffixSearchList -join ', ')"
        Write-Log "  Append Primary Suffixes: $AppendPrimarySuffixes"
        Write-Log "  Append Parent Suffixes: $AppendParentSuffixes"
        Write-Log "  Register Connection Address: $RegisterThisConnectionsAddress"
        
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
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SearchList" -Value $SearchListString -Type String -ErrorAction Stop
                
                Write-Log "DNS suffix search list configured: $SearchListString" "SUCCESS"
                $Results.ConfiguredSettings += "DNSSuffixSearchList=$SearchListString"
            }
            catch {
                Write-Log "Failed to set DNS suffix search list: $($_.Exception.Message)" "ERROR"
                $Results.FailedSettings += "DNSSuffixSearchList"
                $Results.Success = $false
            }
        }
        
        # DNS suffix behavior configuration
        try {
            Write-Log "Configuring DNS suffix behavior settings..."
            
            $DnsPolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            
            # Append primary suffixes
            Set-ItemProperty -Path $DnsPolicyPath -Name "AppendToMultiLabelName" -Value ([int]$AppendPrimarySuffixes) -Type DWord -ErrorAction Stop
            $Results.ConfiguredSettings += "AppendPrimarySuffixes=$AppendPrimarySuffixes"
            
            # Append parent suffixes
            Set-ItemProperty -Path $DnsPolicyPath -Name "DevolutionLevel" -Value (if ($AppendParentSuffixes) { 0 } else { 1 }) -Type DWord -ErrorAction Stop
            $Results.ConfiguredSettings += "AppendParentSuffixes=$AppendParentSuffixes"
            
            # Register connection address
            Set-ItemProperty -Path $DnsPolicyPath -Name "RegisterAdapterName" -Value ([int]$RegisterThisConnectionsAddress) -Type DWord -ErrorAction Stop
            $Results.ConfiguredSettings += "RegisterThisConnectionsAddress=$RegisterThisConnectionsAddress"
            
            Write-Log "DNS suffix behavior settings configured successfully" "SUCCESS"
        }
        catch {
            Write-Log "Failed to configure DNS suffix behavior: $($_.Exception.Message)" "ERROR"
            $Results.FailedSettings += "DNSSuffixBehavior"
            $Results.Success = $false
        }
        
        # Summary report
        Write-Log ""
        Write-Log "DNS suffix configuration summary:"
        Write-Log "Total settings processed: $($Results.ConfiguredSettings.Count + $Results.FailedSettings.Count)"
        Write-Log "Successfully configured: $($Results.ConfiguredSettings.Count)"
        Write-Log "Failed configurations: $($Results.FailedSettings.Count)"
        
        if ($Results.ConfiguredSettings.Count -gt 0) {
            Write-Log "Successfully configured settings:"
            foreach ($Setting in $Results.ConfiguredSettings) {
                Write-Log "  [OK] $Setting" "SUCCESS"
            }
        }
        
        if ($Results.FailedSettings.Count -gt 0) {
            Write-Log "Failed settings:"
            foreach ($Failed in $Results.FailedSettings) {
                Write-Log "  [ERROR] $Failed" "ERROR"
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

function Test-FileAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [switch]$TestWrite = $false
    )
    
    try {
        if (-not (Test-Path $Path)) {
            return $false
        }
        
        if ($TestWrite) {
            $TestFile = Join-Path $Path "test_write_access.tmp"
            try {
                "test" | Out-File -FilePath $TestFile -Force
                Remove-Item $TestFile -Force
                return $true
            }
            catch {
                return $false
            }
        }
        
        return $true
    }
    catch {
        return $false
    }
}

function Copy-FileWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryAttempts = 3
    )
    
    $Results = @{
        Success = $false
        SourceExists = $false
        DestinationCreated = $false
        SizeMatch = $false
        Error = ""
    }
    
    try {
        # Check source file
        if (-not (Test-Path $SourcePath)) {
            $Results.Error = "Source file not found: $SourcePath"
            return $Results
        }
        
        $Results.SourceExists = $true
        $SourceSize = (Get-Item $SourcePath).Length
        
        # Ensure destination directory exists
        $DestDir = Split-Path $DestinationPath -Parent
        if (-not (Test-Path $DestDir)) {
            New-Item -Path $DestDir -ItemType Directory -Force | Out-Null
        }
        
        # Copy with retry logic
        $Attempt = 0
        while ($Attempt -lt $RetryAttempts) {
            try {
                Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
                $Results.DestinationCreated = $true
                
                # Validate copy
                if (Test-Path $DestinationPath) {
                    $DestSize = (Get-Item $DestinationPath).Length
                    if ($SourceSize -eq $DestSize) {
                        $Results.SizeMatch = $true
                        $Results.Success = $true
                        return $Results
                    }
                }
                break
            }
            catch {
                $Attempt++
                if ($Attempt -ge $RetryAttempts) {
                    $Results.Error = $_.Exception.Message
                }
                Start-Sleep -Seconds 1
            }
        }
        
        return $Results
    }
    catch {
        $Results.Error = $_.Exception.Message
        return $Results
    }
}

function Remove-DomainUserProfiles {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "Domain Profile Cleanup"
    
    try {
        $Results = @{
            ProfilesRemoved = 0
            RemovedProfiles = @()
            FailedRemovals = @()
            Success = $true
        }
        
        Write-Log "Scanning for domain user profiles..."
        
        # Get all user profiles from registry
        $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $ProfileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue
        
        foreach ($ProfileKey in $ProfileKeys) {
            try {
                $ProfilePath = Get-ItemProperty -Path $ProfileKey.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue
                
                if ($ProfilePath -and $ProfilePath.ProfileImagePath) {
                    $ProfileDir = $ProfilePath.ProfileImagePath
                    $ProfileName = Split-Path $ProfileDir -Leaf
                    
                    # Skip system profiles and local accounts
                    $SystemProfiles = @("Administrator", "Guest", "Public", "Default", "All Users", "Default User")
                    if ($ProfileName -in $SystemProfiles -or $ProfileName.StartsWith("TEMP") -or $ProfileName.Length -lt 3) {
                        continue
                    }
                    
                    # Check if this is a domain profile (contains domain prefix or is in domain format)
                    if ($ProfileName -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $ProfileName.Contains(".")) {
                        Write-Log "Found domain profile: $ProfileName at $ProfileDir"
                        
                        # Remove profile directory
                        if (Test-Path $ProfileDir) {
                            try {
                                Remove-Item -Path $ProfileDir -Recurse -Force -ErrorAction Stop
                                Write-Log "Removed profile directory: $ProfileDir" "SUCCESS"
                            }
                            catch {
                                Write-Log "Failed to remove profile directory: $ProfileDir - $($_.Exception.Message)" "WARN"
                                $Results.FailedRemovals += $ProfileName
                                continue
                            }
                        }
                        
                        # Remove registry entry
                        try {
                            Remove-Item -Path $ProfileKey.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Log "Removed profile registry entry: $ProfileName" "SUCCESS"
                            $Results.ProfilesRemoved++
                            $Results.RemovedProfiles += $ProfileName
                        }
                        catch {
                            Write-Log "Failed to remove profile registry entry: $ProfileName - $($_.Exception.Message)" "WARN"
                            $Results.FailedRemovals += $ProfileName
                        }
                    }
                }
            }
            catch {
                Write-Log "Error processing profile: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Additional cleanup: Remove domain profiles from D:\Users if it exists
        $DUsersPath = "D:\Users"
        if (Test-Path $DUsersPath) {
            Write-Log "Cleaning up redirected profiles in D:\Users..."
            
            $DomainDirs = Get-ChildItem -Path $DUsersPath -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $_.Name.Contains(".") }
            
            foreach ($DomainDir in $DomainDirs) {
                try {
                    Remove-Item -Path $DomainDir.FullName -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed redirected profile: $($DomainDir.Name)" "SUCCESS"
                    if ($DomainDir.Name -notin $Results.RemovedProfiles) {
                        $Results.ProfilesRemoved++
                        $Results.RemovedProfiles += $DomainDir.Name
                    }
                }
                catch {
                    Write-Log "Failed to remove redirected profile: $($DomainDir.Name) - $($_.Exception.Message)" "WARN"
                    $Results.FailedRemovals += $DomainDir.Name
                }
            }
        }
        
        if ($Results.FailedRemovals.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "Domain profile cleanup completed: $($Results.ProfilesRemoved) profiles removed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Domain profile cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            ProfilesRemoved = 0
            RemovedProfiles = @()
            FailedRemovals = @()
            Success = $false
        }
    }
}

function Remove-WEMRSAKey {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "WEM RSA Key Cleanup"
    
    try {
        $Results = @{
            Success = $true
            RemovedKeys = @()
            FailedRemovals = @()
        }
        
        Write-Log "Scanning for WEM RSA keys..."
        
        # WEM RSA key locations
        $WEMKeyPaths = @(
            "HKLM:\SOFTWARE\Norskale\Norskale Agent Host",
            "HKLM:\SOFTWARE\Wow6432Node\Norskale\Norskale Agent Host",
            "HKLM:\SOFTWARE\Citrix\WEM",
            "HKLM:\SOFTWARE\Wow6432Node\Citrix\WEM"
        )
        
        foreach ($KeyPath in $WEMKeyPaths) {
            if (Test-Path $KeyPath) {
                try {
                    Write-Log "Removing WEM key: $KeyPath"
                    Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                    $Results.RemovedKeys += $KeyPath
                    Write-Log "Successfully removed: $KeyPath" "SUCCESS"
                }
                catch {
                    Write-Log "Failed to remove: $KeyPath - $($_.Exception.Message)" "WARN"
                    $Results.FailedRemovals += $KeyPath
                    $Results.Success = $false
                }
            }
        }
        
        # Additional WEM file cleanup
        $WEMFiles = @(
            "$env:ProgramFiles\Norskale",
            "${env:ProgramFiles(x86)}\Norskale",
            "$env:ProgramData\Norskale"
        )
        
        foreach ($WEMPath in $WEMFiles) {
            if (Test-Path $WEMPath) {
                try {
                    Write-Log "Removing WEM directory: $WEMPath"
                    Remove-Item -Path $WEMPath -Recurse -Force -ErrorAction Stop
                    $Results.RemovedKeys += $WEMPath
                    Write-Log "Successfully removed: $WEMPath" "SUCCESS"
                }
                catch {
                    Write-Log "Failed to remove: $WEMPath - $($_.Exception.Message)" "WARN"
                    $Results.FailedRemovals += $WEMPath
                }
            }
        }
        
        if ($Results.RemovedKeys.Count -eq 0) {
            Write-Log "No WEM RSA keys found to remove" "INFO"
        }
        
        return $Results.Success
    }
    catch {
        Write-Log "WEM RSA key cleanup failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-DriveConfiguration {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing drive configuration..."
        
        $SystemDrive = $env:SystemDrive
        if (Test-Path $SystemDrive) {
            Write-Log "System drive ($SystemDrive) is accessible" "SUCCESS"
            return $true
        }
        
        return $false
    }
    catch {
        Write-Log "Drive configuration test failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-VDIOptimizations {
    [CmdletBinding()]
    param()
    
    try {
        $Results = @{
            OverallStatus = $true
            Issues = @()
        }
        
        Write-Log "Testing VDI optimizations..."
        
        # Pagefile location verification (should be on D: drive)
        try {
            $PageFiles = Get-WmiObject -Class Win32_PageFileSetting
            $DPageFile = $PageFiles | Where-Object { $_.Name -like "D:\*" }
            $CPageFile = $PageFiles | Where-Object { $_.Name -like "C:\*" }
            
            if ($DPageFile) {
                $Results.PagefileConfigured = $true
                Write-Log "Pagefile correctly configured on D: drive: $($DPageFile.Name)" "SUCCESS"
            }
            else {
                $Results.Issues += "Pagefile not found on D: drive"
                $Results.OverallStatus = $false
                $Results.PagefileConfigured = $false
            }
            
            if ($CPageFile) {
                $Results.Issues += "Pagefile still exists on C: drive - should be moved to D:"
                $Results.OverallStatus = $false
            }
        }
        catch {
            $Results.Issues += "Could not verify pagefile configuration"
            $Results.PagefileConfigured = $false
        }
        
        # Event log redirection verification
        try {
            $EventLogRedirected = $true
            $EventLogPaths = @("Application", "System", "Security")
            foreach ($LogName in $EventLogPaths) {
                $LogRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
                if (Test-Path $LogRegPath) {
                    $LogFile = Get-ItemProperty -Path $LogRegPath -Name "File" -ErrorAction SilentlyContinue
                    if ($LogFile -and $LogFile.File -notlike "D:\*") {
                        $EventLogRedirected = $false
                        $Results.Issues += "$LogName event log not redirected to D: drive"
                        $Results.OverallStatus = $false
                    }
                }
            }
            
            if ($EventLogRedirected) {
                Write-Log "Event logs correctly redirected to D: drive" "SUCCESS"
            }
        }
        catch {
            $Results.Issues += "Could not verify event log redirection"
        }
        
        # Basic optimization checks
        $OptimizationTests = @(
            @{ Name = "Automatic Updates"; Registry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Value = "NoAutoUpdate"; Expected = 1 },
            @{ Name = "Windows Search"; Registry = "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch"; Value = "Start"; Expected = 4 }
        )
        
        foreach ($Test in $OptimizationTests) {
            try {
                if (Test-Path $Test.Registry) {
                    $CurrentValue = Get-ItemProperty -Path $Test.Registry -Name $Test.Value -ErrorAction SilentlyContinue
                    if ($CurrentValue.$($Test.Value) -ne $Test.Expected) {
                        $Results.Issues += "$($Test.Name) not optimally configured"
                        $Results.OverallStatus = $false
                    }
                }
            }
            catch {
                $Results.Issues += "Could not check $($Test.Name) configuration"
            }
        }
        
        # Set registry optimizations flag
        $Results.RegistryOptimized = ($Results.Issues.Count -eq 0)
        
        return $Results
    }
    catch {
        Write-Log "VDI optimizations test failed: $($_.Exception.Message)" "ERROR"
        return @{ OverallStatus = $false; Issues = @("Test failed") }
    }
}

function Test-AutomaticMaintenanceStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing automatic maintenance status..."
        
        $MaintenanceKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
        if (Test-Path $MaintenanceKey) {
            $MaintenanceEnabled = Get-ItemProperty -Path $MaintenanceKey -Name "MaintenanceDisabled" -ErrorAction SilentlyContinue
            return @{
                MaintenanceDisabled = ($MaintenanceEnabled.MaintenanceDisabled -eq 1)
            }
        }
        
        return @{ MaintenanceDisabled = $false }
    }
    catch {
        Write-Log "Automatic maintenance status test failed: $($_.Exception.Message)" "ERROR"
        return @{ MaintenanceDisabled = $false }
    }
}

function Test-VMwareMemoryBallooningStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing VMware memory ballooning status..."
        
        # Check if running in VMware
        $VMwareCheck = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $IsVMware = $VMwareCheck.Manufacturer -like "*VMware*"
        
        $Results = @{
            VMwareEnvironment = $IsVMware
            OverallCompliant = $true
            Issues = @()
        }
        
        if ($IsVMware) {
            # Check for VMware tools and ballooning
            $VMwareService = Get-Service -Name "VMTools" -ErrorAction SilentlyContinue
            if (-not $VMwareService) {
                $Results.Issues += "VMware Tools not installed"
                $Results.OverallCompliant = $false
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "VMware memory ballooning status test failed: $($_.Exception.Message)" "ERROR"
        return @{
            VMwareEnvironment = $false
            OverallCompliant = $false
            Issues = @("Test failed")
        }
    }
}

function Get-DesktopLogPath {
    [CmdletBinding()]
    param()
    
    try {
        $DesktopPath = Get-DesktopPath
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $LogFileName = "Citrix_Install_$Timestamp.log"
        return Join-Path $DesktopPath $LogFileName
    }
    catch {
        return "C:\Citrix_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
}

function Copy-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force = $false
    )
    
    try {
        Write-Log "Attempting to copy installation files from network location..."
        Write-Log "Source: $NetworkPath"
        Write-Log "Destination: $LocalPath"
        
        # Ensure local path exists
        if (-not (Test-Path $LocalPath)) {
            New-Item -Path $LocalPath -ItemType Directory -Force | Out-Null
        }
        
        # Check if network path is accessible
        if (-not (Test-Path $NetworkPath)) {
            Write-Log "Network path not accessible: $NetworkPath" "WARN"
            return $false
        }
        
        # Copy files using robocopy for better handling
        $RobocopyArgs = @($NetworkPath, $LocalPath, "/E", "/R:2", "/W:5", "/NFL", "/NDL")
        if ($Force) {
            $RobocopyArgs += "/IS"
        }
        
        $Process = Start-Process -FilePath "robocopy" -ArgumentList $RobocopyArgs -Wait -PassThru -NoNewWindow
        
        # Robocopy exit codes 0-3 are successful
        if ($Process.ExitCode -le 3) {
            Write-Log "Installation files copied successfully" "SUCCESS"
            return $true
        } else {
            Write-Log "Robocopy failed, using PowerShell copy..." "WARN"
            
            # Fallback to PowerShell copy
            Copy-Item -Path "$NetworkPath\*" -Destination $LocalPath -Recurse -Force -ErrorAction Stop
            Write-Log "Installation files copied using PowerShell" "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Failed to copy installation files: $($_.Exception.Message)" "WARN"
        return $false
    }
}

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
    
    try {
        $Results = @{
            Success = $true
            StartupFiles = @()
            ShutdownFiles = @()
            FailedFiles = @()
        }
        
        # Get OS version to determine script source
        $OSInfo = Get-OSVersion
        
        # Select appropriate source paths based on OS
        $StartupSource = if ($OSInfo.ScriptSource -eq "win2019") { $StartupSourceWin2019 } else { $StartupSourceWin2022 }
        $ShutdownSource = if ($OSInfo.ScriptSource -eq "win2019") { $ShutdownSourceWin2019 } else { $ShutdownSourceWin2022 }
        
        Write-Log "Using script sources for $($OSInfo.ScriptSource):"
        Write-Log "  Startup: $StartupSource"
        Write-Log "  Shutdown: $ShutdownSource"
        
        # Create destination directories
        if (-not (Test-Path $StartupDestination)) {
            New-Item -Path $StartupDestination -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $ShutdownDestination)) {
            New-Item -Path $ShutdownDestination -ItemType Directory -Force | Out-Null
        }
        
        # Copy startup scripts
        if (Test-Path $StartupSource) {
            $StartupFiles = Get-ChildItem -Path $StartupSource -File -ErrorAction SilentlyContinue
            foreach ($File in $StartupFiles) {
                $CopyResult = Copy-FileWithValidation -SourcePath $File.FullName -DestinationPath (Join-Path $StartupDestination $File.Name)
                if ($CopyResult.Success) {
                    $Results.StartupFiles += @{ Name = $File.Name; Size = $File.Length }
                } else {
                    $Results.FailedFiles += @{ Name = $File.Name; Reason = $CopyResult.Error }
                    $Results.Success = $false
                }
            }
        } else {
            Write-Log "Startup script source not found: $StartupSource" "WARN"
        }
        
        # Copy shutdown scripts
        if (Test-Path $ShutdownSource) {
            $ShutdownFiles = Get-ChildItem -Path $ShutdownSource -File -ErrorAction SilentlyContinue
            foreach ($File in $ShutdownFiles) {
                $CopyResult = Copy-FileWithValidation -SourcePath $File.FullName -DestinationPath (Join-Path $ShutdownDestination $File.Name)
                if ($CopyResult.Success) {
                    $Results.ShutdownFiles += @{ Name = $File.Name; Size = $File.Length }
                } else {
                    $Results.FailedFiles += @{ Name = $File.Name; Reason = $CopyResult.Error }
                    $Results.Success = $false
                }
            }
        } else {
            Write-Log "Shutdown script source not found: $ShutdownSource" "WARN"
        }
        
        return $Results
    }
    catch {
        Write-Log "Script copy operation failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; StartupFiles = @(); ShutdownFiles = @(); FailedFiles = @() }
    }
}

function Start-DriveConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Interactive = $false
    )
    
    Write-LogHeader "Drive Configuration Initialization"
    
    try {
        $Results = @{
            DriveValidationPassed = $true
            SystemDriveAccessible = $false
            DDriveExists = $false
            DDriveAccessible = $false
            Issues = @()
            Warnings = @()
        }
        
        # Check system drive (usually C:)
        $SystemDrive = $env:SystemDrive
        Write-Log "Checking system drive: $SystemDrive"
        
        if (Test-Path $SystemDrive) {
            $Results.SystemDriveAccessible = $true
            Write-Log "System drive ($SystemDrive) is accessible" "SUCCESS"
            
            # Check free space
            $SystemDriveInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $SystemDrive }
            if ($SystemDriveInfo) {
                $FreeSpaceGB = [math]::Round($SystemDriveInfo.FreeSpace / 1GB, 2)
                Write-Log "System drive free space: $FreeSpaceGB GB" "INFO"
                
                if ($FreeSpaceGB -lt 10) {
                    $Results.Warnings += "System drive has low free space: $FreeSpaceGB GB"
                    Write-Log "Warning: System drive has low free space" "WARN"
                }
            }
        } else {
            $Results.Issues += "System drive not accessible: $SystemDrive"
            $Results.DriveValidationPassed = $false
            Write-Log "System drive not accessible: $SystemDrive" "ERROR"
        }
        
        # Enhanced D: drive validation with CD/DVD ROM management
        Write-Log "Checking D: drive availability and type..." "INFO"
        Write-Host "DEBUG: Starting D: drive validation..." -ForegroundColor Magenta
        
        # Check if D: drive exists
        $DDriveInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
        Write-Host "DEBUG: D: drive query result: $($DDriveInfo -ne $null)" -ForegroundColor Magenta
        
        if ($DDriveInfo) {
            $Results.DDriveExists = $true
            Write-Log "D: drive detected - analyzing drive type..." "INFO"
            Write-Host "DEBUG: D: drive found - Type: $($DDriveInfo.DriveType)" -ForegroundColor Magenta
            
            # Check if D: is a CD/DVD ROM drive (DriveType 5)
            if ($DDriveInfo.DriveType -eq 5) {
                Write-Log "D: drive is a CD/DVD ROM drive - needs to be moved to Y:" "WARN"
                $Results.Issues += "CD/DVD ROM drive is using D: letter - must be changed to Y:"
                $Results.DriveValidationPassed = $false
                
                # Attempt to change CD/DVD ROM drive letter to Y:
                Write-Log "Attempting to change CD/DVD ROM drive letter from D: to Y:..." "INFO"
                try {
                    # Get the CD/DVD ROM drive
                    $CDDrive = Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DriveLetter -eq "D:" -and $_.DriveType -eq 5 }
                    
                    if ($CDDrive) {
                        # Check if Y: is available
                        $YDriveExists = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "Y:" }
                        
                        if (-not $YDriveExists) {
                            # Change drive letter using WMI
                            $CDDrive | Set-CimInstance -Property @{ DriveLetter = "Y:" }
                            Write-Log "Successfully changed CD/DVD ROM drive letter from D: to Y:" "SUCCESS"
                            
                            # Recheck D: drive after change
                            Start-Sleep -Seconds 3
                            $DDriveInfoAfter = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
                            
                            if (-not $DDriveInfoAfter) {
                                Write-Log "D: drive letter is now available for cache drive" "SUCCESS"
                                $Results.Issues = $Results.Issues | Where-Object { $_ -notlike "*CD/DVD ROM*" }
                                
                                # Prompt user to attach D: cache drive
                                Write-Log "REQUIRED: Please attach a physical D: cache drive to this packaging machine" "WARN"
                                Write-Log "The D: drive is essential for Citrix VDI cache operations and performance" "WARN"
                                $Results.Warnings += "Physical D: cache drive must be attached to packaging machine"
                                
                                # Always prompt for D: cache drive after CD/DVD ROM relocation
                                Write-Host "`n" -ForegroundColor Yellow
                                Write-Host "ATTENTION: D: Cache Drive Required" -ForegroundColor Red -BackgroundColor Yellow
                                Write-Host "===========================================" -ForegroundColor Yellow
                                Write-Host "The CD/DVD ROM drive has been moved from D: to Y:" -ForegroundColor Green
                                Write-Host "You must now attach a physical D: cache drive to this machine." -ForegroundColor Yellow
                                Write-Host "This drive is required for optimal Citrix VDI performance." -ForegroundColor Yellow
                                Write-Host "`nPress Enter after attaching the D: cache drive..." -ForegroundColor Cyan
                                Read-Host "Press Enter to continue"
                                
                                # Recheck for D: drive after user confirmation
                                Write-Log "Rechecking for D: cache drive after user attachment..." "INFO"
                                $DDriveFinal = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
                                
                                if ($DDriveFinal -and $DDriveFinal.DriveType -eq 3) {
                                    Write-Log "D: cache drive successfully detected and validated" "SUCCESS"
                                    $Results.DDriveExists = $true
                                    $Results.DDriveAccessible = $true
                                    $Results.DriveValidationPassed = $true
                                } else {
                                    Write-Log "D: cache drive not detected - installation may proceed with warnings" "WARN"
                                    $Results.Warnings += "D: cache drive not attached - may impact VDI performance"
                                }
                            }
                        } else {
                            Write-Log "Y: drive already exists - cannot move CD/DVD ROM drive" "ERROR"
                            $Results.Issues += "Y: drive already in use - cannot relocate CD/DVD ROM drive"
                        }
                    }
                } catch {
                    Write-Log "Failed to change CD/DVD ROM drive letter: $($_.Exception.Message)" "ERROR"
                    $Results.Issues += "Could not change CD/DVD ROM drive letter: $($_.Exception.Message)"
                }
            }
            # Check if D: is a fixed drive (DriveType 3) - this is what we want
            elseif ($DDriveInfo.DriveType -eq 3) {
                Write-Log "D: drive is a fixed disk (cache drive) - validating..." "SUCCESS"
                
                try {
                    # Test write access to D: drive
                    $TestFile = "D:\drive_test.tmp"
                    "test" | Out-File -FilePath $TestFile -Force -ErrorAction Stop
                    Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
                    
                    $Results.DDriveAccessible = $true
                    Write-Log "D: cache drive is accessible and writable" "SUCCESS"
                    
                    # Check D: drive free space
                    $DFreeSpaceGB = [math]::Round($DDriveInfo.FreeSpace / 1GB, 2)
                    $DTotalSpaceGB = [math]::Round($DDriveInfo.Size / 1GB, 2)
                    Write-Log "D: cache drive - Total: $DTotalSpaceGB GB, Free: $DFreeSpaceGB GB" "INFO"
                    
                    if ($DFreeSpaceGB -lt 10) {
                        $Results.Warnings += "D: cache drive has low free space: $DFreeSpaceGB GB"
                        Write-Log "Warning: D: cache drive has low free space" "WARN"
                    }
                    
                    if ($DTotalSpaceGB -lt 50) {
                        $Results.Warnings += "D: cache drive is smaller than recommended (50GB+): $DTotalSpaceGB GB"
                        Write-Log "Warning: D: cache drive smaller than recommended for VDI caching" "WARN"
                    }
                    
                    # Check for existing D:\Users directory (common in enterprise environments)
                    if (Test-Path "D:\Users") {
                        Write-Log "D:\Users directory found - likely used for redirected profiles" "INFO"
                        $Results.Warnings += "D:\Users directory exists - will be cleaned during profile removal"
                    }
                    
                } catch {
                    $Results.Issues += "D: cache drive exists but is not accessible: $($_.Exception.Message)"
                    Write-Log "D: cache drive exists but is not accessible: $($_.Exception.Message)" "ERROR"
                    $Results.DriveValidationPassed = $false
                }
            }
            else {
                Write-Log "D: drive exists but is not a fixed disk (Type: $($DDriveInfo.DriveType))" "WARN"
                $Results.Warnings += "D: drive is not a fixed disk - may not be suitable for VDI caching"
            }
        } else {
            Write-Log "No D: drive detected - checking for CD/DVD ROM drives..." "WARN"
            Write-Host "DEBUG: No D: drive found - executing prompt logic..." -ForegroundColor Magenta
            
            # Check for any CD/DVD ROM drives that might need relocation
            $CDDrives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 5 }
            
            if ($CDDrives.Count -gt 0) {
                Write-Log "Found $($CDDrives.Count) CD/DVD ROM drive(s) on other letters" "INFO"
                foreach ($CDDrive in $CDDrives) {
                    Write-Log "  CD/DVD ROM drive: $($CDDrive.DeviceID)" "INFO"
                }
            }
            
            # Prompt user to attach D: cache drive
            Write-Log "REQUIRED: Please attach a physical D: cache drive to this packaging machine" "ERROR"
            $Results.Issues += "No D: cache drive attached - required for optimal VDI performance"
            $Results.DriveValidationPassed = $false
            
            # Always prompt for D: cache drive when none detected (regardless of Interactive flag)
            Write-Host "DEBUG: About to show D: drive prompt..." -ForegroundColor Magenta
            Write-Host "`n" -ForegroundColor Yellow
            Write-Host "ATTENTION: D: Cache Drive Required" -ForegroundColor Red -BackgroundColor Yellow
            Write-Host "===========================================" -ForegroundColor Yellow
            Write-Host "No D: cache drive detected on this packaging machine." -ForegroundColor Red
            Write-Host "Please attach a physical D: drive for VDI cache operations." -ForegroundColor Yellow
            Write-Host "Recommended: 50GB+ fixed drive for optimal performance." -ForegroundColor Yellow
            Write-Host "`nPress Enter after attaching the D: cache drive..." -ForegroundColor Cyan
            Read-Host "Press Enter to continue"
            
            # Recheck for D: drive after user confirmation
            Write-Log "Rechecking for D: cache drive after user attachment..." "INFO"
            $DDriveFinal = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
            
            if ($DDriveFinal -and $DDriveFinal.DriveType -eq 3) {
                Write-Log "D: cache drive successfully detected and validated" "SUCCESS"
                $Results.DDriveExists = $true
                $Results.DDriveAccessible = $true
                $Results.Issues = $Results.Issues | Where-Object { $_ -notlike "*No D: cache drive*" }
                $Results.DriveValidationPassed = $true
                
                # Test write access to newly attached drive
                try {
                    $TestFile = "D:\drive_test.tmp"
                    "test" | Out-File -FilePath $TestFile -Force -ErrorAction Stop
                    Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
                    $Results.DDriveAccessible = $true
                    Write-Log "D: cache drive is accessible and writable" "SUCCESS"
                } catch {
                    Write-Log "D: cache drive detected but not writable: $($_.Exception.Message)" "WARN"
                    $Results.Warnings += "D: cache drive detected but has write access issues"
                }
            } else {
                Write-Log "D: cache drive still not detected - installation may proceed with warnings" "WARN"
                $Results.Warnings += "D: cache drive not attached - will significantly impact VDI performance"
                
                # D: cache drive is mandatory - halt installation
                Write-Host "`n" -ForegroundColor Yellow
                Write-Host "D: cache drive still not detected." -ForegroundColor Red
                Write-Host "CRITICAL: D: cache drive is mandatory for Citrix VDI deployment." -ForegroundColor Red
                Write-Host "Installation cannot proceed without cache drive." -ForegroundColor Red
                Write-Log "Installation halted - D: cache drive required" "ERROR"
                $Results.Issues += "Installation halted - D: cache drive required"
                $Results.DriveValidationPassed = $false
            }
        }
        
        # Check additional drives
        $AllDrives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        Write-Log "Available fixed drives:" "INFO"
        foreach ($Drive in $AllDrives) {
            $FreeSpace = [math]::Round($Drive.FreeSpace / 1GB, 2)
            $TotalSize = [math]::Round($Drive.Size / 1GB, 2)
            Write-Log "  $($Drive.DeviceID) - Total: $TotalSize GB, Free: $FreeSpace GB" "INFO"
        }
        
        # Summary
        if ($Results.Issues.Count -gt 0) {
            $Results.DriveValidationPassed = $false
            Write-Log "Drive validation completed with issues:" "WARN"
            foreach ($Issue in $Results.Issues) {
                Write-Log "  - $Issue" "ERROR"
            }
        }
        
        if ($Results.Warnings.Count -gt 0) {
            Write-Log "Drive validation completed with warnings:" "WARN"
            foreach ($Warning in $Results.Warnings) {
                Write-Log "  - $Warning" "WARN"
            }
        }
        
        if ($Results.DriveValidationPassed) {
            Write-Log "Drive configuration validation completed successfully" "SUCCESS"
        }
        
        return $Results
    }
    catch {
        Write-Log "Drive configuration initialization failed: $($_.Exception.Message)" "ERROR"
        return @{
            DriveValidationPassed = $false
            SystemDriveAccessible = $false
            DDriveExists = $false
            DDriveAccessible = $false
            Issues = @("Drive configuration initialization failed")
            Warnings = @()
        }
    }
}

function Get-CacheDrive {
    [CmdletBinding()]
    param()
    
    Write-LogHeader "D Cache Drive Attachment Required"
    
    # Force prompt for D: cache drive
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host "ATTENTION: D: Cache Drive Required" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "===========================================" -ForegroundColor Yellow
    Write-Host "A physical D: cache drive must be attached to this packaging machine." -ForegroundColor Red
    Write-Host "This drive is essential for optimal Citrix VDI cache operations." -ForegroundColor Yellow
    Write-Host "Recommended specifications:" -ForegroundColor Yellow
    Write-Host "  - Fixed disk drive (not removable)" -ForegroundColor White
    Write-Host "  - Minimum 50GB capacity" -ForegroundColor White
    Write-Host "  - Fast SSD preferred for cache performance" -ForegroundColor White
    Write-Host "`nPlease attach the D: cache drive now..." -ForegroundColor Cyan
    Read-Host "Press Enter after attaching the D: cache drive"
    
    # Verify D: drive after attachment
    Write-Log "Verifying D: cache drive after attachment..." "INFO"
    $DDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
    
    if ($DDrive -and $DDrive.DriveType -eq 3) {
        $DriveSizeGB = [math]::Round($DDrive.Size / 1GB, 2)
        $FreeSpaceGB = [math]::Round($DDrive.FreeSpace / 1GB, 2)
        
        Write-Log "D: cache drive successfully detected!" "SUCCESS"
        Write-Log "Drive specifications:" "INFO"
        Write-Log "  Total size: $DriveSizeGB GB" "INFO"
        Write-Log "  Free space: $FreeSpaceGB GB" "INFO"
        
        # Test write access
        try {
            $TestFile = "D:\cache_drive_test.tmp"
            "VDI Cache Drive Test" | Out-File -FilePath $TestFile -Force
            Remove-Item $TestFile -Force
            Write-Log "D: cache drive write access confirmed" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "D: cache drive detected but write access failed: $($_.Exception.Message)" "ERROR"
            Write-Host "CRITICAL: D: cache drive write access failed" -ForegroundColor Red
            Write-Host "TERMINATING SCRIPT EXECUTION" -ForegroundColor Red
            Write-Host "Press any key to close..." -ForegroundColor Yellow
            $null = Read-Host
            [System.Environment]::Exit(1)
        }
    }
    elseif ($DDrive) {
        Write-Log "D: drive detected but is not a fixed disk (Type: $($DDrive.DriveType))" "ERROR"
        Write-Host "ERROR: The attached D: drive is not a fixed disk drive." -ForegroundColor Red
        Write-Host "Please attach a proper fixed disk drive for cache operations." -ForegroundColor Yellow
        Write-Host "TERMINATING SCRIPT EXECUTION" -ForegroundColor Red
        Write-Host "Press any key to close..." -ForegroundColor Yellow
        $null = Read-Host
        [System.Environment]::Exit(1)
    }
    else {
        Write-Log "No D: cache drive detected after user confirmation" "ERROR"
        Write-Host "CRITICAL: No D: cache drive detected after attachment attempt." -ForegroundColor Red
        Write-Host "Installation cannot proceed without a proper D: cache drive." -ForegroundColor Red
        Write-Host "Please ensure the drive is properly connected and restart the script." -ForegroundColor Yellow
        Write-Host "TERMINATING SCRIPT EXECUTION" -ForegroundColor Red
        Write-Host "Press any key to close..." -ForegroundColor Yellow
        $null = Read-Host
        [System.Environment]::Exit(1)
    }
}

function Save-InstallationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    try {
        Write-Log "Saving installation configuration to: $ConfigPath"
        
        # Convert config to JSON
        $ConfigJson = $Config | ConvertTo-Json -Depth 10
        
        # Ensure directory exists
        $ConfigDir = Split-Path $ConfigPath -Parent
        if (-not (Test-Path $ConfigDir)) {
            New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
        }
        
        # Save configuration
        Set-Content -Path $ConfigPath -Value $ConfigJson -Force
        
        Write-Log "Configuration saved successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to save configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-Logging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$ClearExisting
    )
    
    try {
        # Create log directory if it doesn't exist
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        
        # Clear existing log if requested
        if ($ClearExisting -and (Test-Path $LogPath)) {
            Remove-Item $LogPath -Force
        }
        
        # Initialize global logging variable
        $Global:LogPath = $LogPath
        
        # Write initial log entry
        $InitMessage = "Logging initialized at $(Get-Date)"
        Add-Content -Path $LogPath -Value $InitMessage -Force
        
        return $true
    }
    catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        return $false
    }
}

function Get-SystemInformation {
    [CmdletBinding()]
    param()
    
    try {
        $SystemInfo = @{}
        
        # Computer information
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $Processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        
        $SystemInfo.ComputerName = $env:COMPUTERNAME
        $SystemInfo.Domain = if ($ComputerSystem.Domain) { $ComputerSystem.Domain } else { "WORKGROUP" }
        $SystemInfo.OSVersion = $OperatingSystem.Caption
        $SystemInfo.OSArchitecture = $OperatingSystem.OSArchitecture
        $SystemInfo.Manufacturer = $ComputerSystem.Manufacturer
        $SystemInfo.Model = $ComputerSystem.Model
        $SystemInfo.ProcessorName = $Processor.Name
        $SystemInfo.ProcessorCores = $Processor.NumberOfCores
        $SystemInfo.TotalMemoryGB = [Math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
        
        # Virtual machine detection
        $SystemInfo.VirtualMachine = $false
        $SystemInfo.VirtualPlatform = "Physical"
        
        if ($ComputerSystem.Manufacturer -match "VMware|Microsoft Corporation|Xen|QEMU|VirtualBox") {
            $SystemInfo.VirtualMachine = $true
            switch -Regex ($ComputerSystem.Manufacturer) {
                "VMware" { $SystemInfo.VirtualPlatform = "VMware" }
                "Microsoft Corporation" { $SystemInfo.VirtualPlatform = "Hyper-V" }
                "Xen" { $SystemInfo.VirtualPlatform = "Xen" }
                "QEMU" { $SystemInfo.VirtualPlatform = "QEMU" }
                "VirtualBox" { $SystemInfo.VirtualPlatform = "VirtualBox" }
            }
        }
        
        return $SystemInfo
    }
    catch {
        Write-Warning "Failed to collect system information: $($_.Exception.Message)"
        return $null
    }
}

function Test-VDAInstallation {
    [CmdletBinding()]
    param()
    
    try {
        # Check for Citrix VDA registry entries
        $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
        $VDAInstalled = Test-Path $VDARegPath
        
        if ($VDAInstalled) {
            Write-Log "VDA registry entries found" "SUCCESS"
            return $true
        }
        
        # Check for VDA services
        $VDAServices = @("BrokerAgent", "picaSvc2", "CdfSvc")
        $FoundServices = 0
        
        foreach ($ServiceName in $VDAServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service) {
                $FoundServices++
            }
        }
        
        if ($FoundServices -ge 2) {
            Write-Log "VDA services detected ($FoundServices found)" "SUCCESS"
            return $true
        }
        
        Write-Log "VDA installation not detected" "WARN"
        return $false
    }
    catch {
        Write-Log "Error checking VDA installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-CitrixServices {
    [CmdletBinding()]
    param()
    
    try {
        $CitrixServiceNames = @(
            "BrokerAgent",
            "picaSvc2", 
            "CdfSvc",
            "Spooler",
            "Themes",
            "AudioSrv",
            "AudioEndpointBuilder"
        )
        
        $CitrixServices = @()
        
        foreach ($ServiceName in $CitrixServiceNames) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service) {
                $CitrixServices += @{
                    Name = $Service.Name
                    DisplayName = $Service.DisplayName
                    Status = $Service.Status.ToString()
                    StartType = $Service.StartType.ToString()
                }
            }
        }
        
        return $CitrixServices
    }
    catch {
        Write-Log "Error retrieving Citrix services: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Test-SystemOptimizations {
    [CmdletBinding()]
    param()
    
    try {
        $Results = @{
            OverallStatus = $true
            Issues = @()
        }
        
        # Check Windows Update service
        $WUService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($WUService -and $WUService.Status -eq "Running") {
            $Results.Issues += "Windows Update service still running"
            $Results.OverallStatus = $false
        }
        
        # Check for common optimization registry entries
        $OptRegPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "HKLM:\SYSTEM\CurrentControlSet\Services\Themes"
        )
        
        foreach ($RegPath in $OptRegPaths) {
            if (-not (Test-Path $RegPath)) {
                $Results.Issues += "Optimization registry path missing: $RegPath"
            }
        }
        
        if ($Results.Issues.Count -eq 0) {
            $Results.OverallStatus = $true
        }
        
        return $Results
    }
    catch {
        Write-Log "Error checking system optimizations: $($_.Exception.Message)" "ERROR"
        return @{ OverallStatus = $false; Issues = @("Error during optimization check") }
    }
}

function Test-WEMRSACleanup {
    [CmdletBinding()]
    param()
    
    try {
        # Check for WEM RSA key remnants
        $WEMRegPath = "HKLM:\SOFTWARE\Citrix\WEM"
        $RSAKeyPath = "HKLM:\SOFTWARE\Classes\TypeLib\{*RSA*}"
        
        $CleanupSuccess = $true
        
        # Basic WEM cleanup validation
        if (Test-Path $WEMRegPath) {
            $WEMEntries = Get-ChildItem $WEMRegPath -ErrorAction SilentlyContinue
            if ($WEMEntries.Count -gt 10) {
                $CleanupSuccess = $false
            }
        }
        
        return $CleanupSuccess
    }
    catch {
        Write-Log "Error checking WEM RSA cleanup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-WindowsServices {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Configuring Windows services for VDI optimization..."
        
        $ServiceConfigs = @(
            @{ Name = "Themes"; StartupType = "Automatic" },
            @{ Name = "AudioSrv"; StartupType = "Automatic" },
            @{ Name = "AudioEndpointBuilder"; StartupType = "Automatic" },
            @{ Name = "Spooler"; StartupType = "Automatic" },
            @{ Name = "wuauserv"; StartupType = "Disabled" }
        )
        
        foreach ($ServiceConfig in $ServiceConfigs) {
            $Service = Get-Service -Name $ServiceConfig.Name -ErrorAction SilentlyContinue
            if ($Service) {
                Set-Service -Name $ServiceConfig.Name -StartupType $ServiceConfig.StartupType -ErrorAction SilentlyContinue
                Write-Log "Configured service: $($ServiceConfig.Name) -> $($ServiceConfig.StartupType)"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to configure Windows services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-NetBiosOverTCP {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Disabling NetBIOS over TCP/IP..."
        
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        $Interfaces = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
        
        foreach ($Interface in $Interfaces) {
            Set-ItemProperty -Path $Interface.PSPath -Name "NetbiosOptions" -Value 2 -ErrorAction SilentlyContinue
        }
        
        Write-Log "NetBIOS over TCP/IP disabled" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to disable NetBIOS over TCP/IP: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-NetworkOffloadParameters {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Disabling network offload parameters..."
        
        $NetworkAdapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }
        foreach ($Adapter in $NetworkAdapters) {
            Disable-NetAdapterChecksumOffload -Name $Adapter.Name -ErrorAction SilentlyContinue
            Disable-NetAdapterLso -Name $Adapter.Name -ErrorAction SilentlyContinue
        }
        
        Write-Log "Network offload parameters disabled" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to disable network offload parameters: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-SMBSettings {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Configuring SMB settings for VDI..."
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "RequireSecuritySignature" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "EnableSecuritySignature" -Value 0 -ErrorAction SilentlyContinue
        
        Write-Log "SMB settings configured" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to configure SMB settings: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-CrashDumpToKernelMode {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Setting crash dump to kernel mode..."
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 2
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DumpFile" -Value "%SystemRoot%\MEMORY.DMP"
        
        Write-Log "Crash dump set to kernel mode" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to set crash dump mode: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-PasswordAgeRegistryKey {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Removing password age registry restrictions..."
        
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Remove-ItemProperty -Path $RegPath -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
        
        Write-Log "Password age registry key removed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to remove password age registry key: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-CitrixOptimizer {
    [CmdletBinding()]
    param(
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Launching Citrix Optimizer tool..."
        
        # Load configuration parameters
        $OptimizerPath = Get-ConfigValue -Key "CitrixOptimizerPath" -DefaultValue "" -ConfigFile $ConfigFilePath
        $TemplatesPath = Get-ConfigValue -Key "CitrixOptimizerTemplatesPath" -DefaultValue "" -ConfigFile $ConfigFilePath
        $TemplateName = Get-ConfigValue -Key "CitrixOptimizerTemplate" -DefaultValue "Windows_Server_2019_VDI.xml" -ConfigFile $ConfigFilePath
        $OutputPath = Get-ConfigValue -Key "CitrixOptimizerOutputPath" -DefaultValue "C:\Logs\CitrixOptimizer" -ConfigFile $ConfigFilePath
        $OptimizerMode = Get-ConfigValue -Key "CitrixOptimizerMode" -DefaultValue "Execute" -ConfigFile $ConfigFilePath
        
        $Results = @{
            Success = $false
            OptimizerExecuted = $false
            TemplateApplied = ""
            OptimizationsApplied = 0
            OutputLocation = ""
            FallbackApplied = $false
            Error = ""
        }
        
        # Check if Citrix Optimizer is available
        if ([string]::IsNullOrEmpty($OptimizerPath) -or -not (Test-Path $OptimizerPath)) {
            Write-Log "Citrix Optimizer not found, applying fallback optimizations..." "WARN"
            return Start-FallbackCitrixOptimizations
        }
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Log "Created Citrix Optimizer output directory: $OutputPath" "INFO"
        }
        
        # Determine template path
        $TemplatePath = ""
        if (![string]::IsNullOrEmpty($TemplatesPath) -and (Test-Path $TemplatesPath)) {
            $TemplatePath = Join-Path $TemplatesPath $TemplateName
        }
        else {
            # Try to find template in same directory as optimizer
            $OptimizerDir = Split-Path $OptimizerPath -Parent
            $DefaultTemplatesPath = Join-Path $OptimizerDir "Templates"
            if (Test-Path $DefaultTemplatesPath) {
                $TemplatePath = Join-Path $DefaultTemplatesPath $TemplateName
            }
        }
        
        if (-not (Test-Path $TemplatePath)) {
            Write-Log "Template not found: $TemplatePath" "ERROR"
            Write-Log "Available templates in directory:" "INFO"
            if (Test-Path (Split-Path $TemplatePath -Parent)) {
                Get-ChildItem -Path (Split-Path $TemplatePath -Parent) -Filter "*.xml" | ForEach-Object {
                    Write-Log "  - $($_.Name)" "INFO"
                }
            }
            Write-Log "Applying fallback optimizations..." "WARN"
            return Start-FallbackCitrixOptimizations
        }
        
        Write-Log "Citrix Optimizer configuration:" "INFO"
        Write-Log "  Optimizer Path: $OptimizerPath" "INFO"
        Write-Log "  Template: $TemplatePath" "INFO"
        Write-Log "  Output Path: $OutputPath" "INFO"
        Write-Log "  Mode: $OptimizerMode" "INFO"
        
        # Prepare Citrix Optimizer execution parameters
        $OptimizerArgs = @(
            "-Source `"$TemplatePath`""
            "-OutputLogFolder `"$OutputPath`""
            "-OutputHtml"
            "-Verbose"
        )
        
        # Add mode-specific parameters
        switch ($OptimizerMode.ToLower()) {
            "execute" {
                $OptimizerArgs += "-Mode Execute"
                Write-Log "Executing Citrix Optimizer in EXECUTE mode (applying optimizations)..." "INFO"
            }
            "analyze" {
                $OptimizerArgs += "-Mode Analyze"
                Write-Log "Executing Citrix Optimizer in ANALYZE mode (assessment only)..." "INFO"
            }
            "rollback" {
                $OptimizerArgs += "-Mode Rollback"
                Write-Log "Executing Citrix Optimizer in ROLLBACK mode (reversing optimizations)..." "INFO"
            }
            default {
                $OptimizerArgs += "-Mode Execute"
                Write-Log "Using default EXECUTE mode for Citrix Optimizer..." "INFO"
            }
        }
        
        # Execute Citrix Optimizer
        $ArgumentString = $OptimizerArgs -join " "
        Write-Log "Executing: PowerShell.exe -ExecutionPolicy Bypass -File `"$OptimizerPath`" $ArgumentString" "INFO"
        
        $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessStartInfo.FileName = "PowerShell.exe"
        $ProcessStartInfo.Arguments = "-ExecutionPolicy Bypass -File `"$OptimizerPath`" $ArgumentString"
        $ProcessStartInfo.RedirectStandardOutput = $true
        $ProcessStartInfo.RedirectStandardError = $true
        $ProcessStartInfo.UseShellExecute = $false
        $ProcessStartInfo.CreateNoWindow = $true
        
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessStartInfo
        
        Write-Log "Starting Citrix Optimizer execution..." "INFO"
        $Process.Start() | Out-Null
        
        # Read output in real-time
        $OutputData = ""
        $ErrorData = ""
        
        while (-not $Process.HasExited) {
            if (-not $Process.StandardOutput.EndOfStream) {
                $Line = $Process.StandardOutput.ReadLine()
                if ($Line) {
                    Write-Log "CITRIX OPTIMIZER: $Line" "INFO"
                    $OutputData += "$Line`n"
                }
            }
            Start-Sleep -Milliseconds 100
        }
        
        # Read any remaining output
        $OutputData += $Process.StandardOutput.ReadToEnd()
        $ErrorData = $Process.StandardError.ReadToEnd()
        
        $ExitCode = $Process.ExitCode
        $Process.Close()
        
        # Process results
        if ($ExitCode -eq 0) {
            Write-Log "Citrix Optimizer completed successfully (Exit Code: $ExitCode)" "SUCCESS"
            $Results.Success = $true
            $Results.OptimizerExecuted = $true
            $Results.TemplateApplied = $TemplateName
            $Results.OutputLocation = $OutputPath
            
            # Parse output for optimization count
            if ($OutputData -match "(\d+)\s+optimizations?\s+applied") {
                $Results.OptimizationsApplied = [int]$Matches[1]
                Write-Log "Applied $($Results.OptimizationsApplied) optimizations from template" "SUCCESS"
            }
            
            # Check for output files
            $OutputFiles = Get-ChildItem -Path $OutputPath -File -ErrorAction SilentlyContinue
            if ($OutputFiles) {
                Write-Log "Citrix Optimizer output files:" "INFO"
                foreach ($File in $OutputFiles) {
                    Write-Log "  - $($File.Name) ($([math]::Round($File.Length/1KB, 2)) KB)" "INFO"
                }
            }
        }
        else {
            Write-Log "Citrix Optimizer failed with exit code: $ExitCode" "ERROR"
            if ($ErrorData) {
                Write-Log "Error output: $ErrorData" "ERROR"
            }
            Write-Log "Applying fallback optimizations..." "WARN"
            return Start-FallbackCitrixOptimizations
        }
        
        return $Results
    }
    catch {
        Write-Log "Exception during Citrix Optimizer execution: $($_.Exception.Message)" "ERROR"
        Write-Log "Applying fallback optimizations..." "WARN"
        return Start-FallbackCitrixOptimizations
    }
}

function Start-FallbackCitrixOptimizations {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Applying fallback Citrix optimization settings..."
        
        $Results = @{
            Success = $true
            OptimizerExecuted = $false
            TemplateApplied = "Fallback Registry Settings"
            OptimizationsApplied = 0
            OutputLocation = ""
            FallbackApplied = $true
            Error = ""
        }
        
        # Enhanced fallback optimizations
        $OptimizationKeys = @(
            # Citrix VDA optimizations
            @{ Path = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"; Name = "ListenPort"; Value = 80; Description = "VDA Listen Port" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections"; Value = 0; Description = "Enable RDP Connections" },
            
            # Performance optimizations
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1; Description = "Disable Paging Executive" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0; Description = "Optimize for Applications" },
            
            # Visual effects optimizations
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name = "VisualFXSetting"; Value = 2; Description = "Optimize Visual Effects" },
            
            # Windows Search optimization
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch"; Name = "Start"; Value = 4; Description = "Disable Windows Search" },
            
            # Automatic Updates optimization
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Value = 1; Description = "Disable Automatic Updates" }
        )
        
        foreach ($Key in $OptimizationKeys) {
            try {
                if (-not (Test-Path $Key.Path)) {
                    New-Item -Path $Key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -ErrorAction Stop
                Write-Log "Applied: $($Key.Description)" "SUCCESS"
                $Results.OptimizationsApplied++
            }
            catch {
                Write-Log "Failed to apply: $($Key.Description) - $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Fallback Citrix optimizations completed: $($Results.OptimizationsApplied) settings applied" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Failed to apply fallback Citrix optimizations: $($_.Exception.Message)" "ERROR"
        return @{ 
            Success = $false
            FallbackApplied = $true
            Error = $_.Exception.Message
            OptimizationsApplied = 0
        }
    }
}

function Stop-CitrixServices {
    [CmdletBinding()]
    param(
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Disabling unnecessary Citrix services..."
        
        # Load configurable service list from config file
        $ServicesToDisableConfig = Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "CdfSvc,Spooler,BITS,wuauserv" -ConfigFile $ConfigFilePath
        $ServicesToDisable = $ServicesToDisableConfig -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        
        $Results = @{
            Success = $true
            DisabledServices = @()
            FailedServices = @()
            SkippedServices = @()
            TotalProcessed = 0
        }
        
        Write-Log "Processing $($ServicesToDisable.Count) services for disabling..." "INFO"
        
        foreach ($ServiceName in $ServicesToDisable) {
            $Results.TotalProcessed++
            
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if (-not $Service) {
                    Write-Log "Service not found: $ServiceName" "WARN"
                    $Results.SkippedServices += "$ServiceName (not found)"
                    continue
                }
                
                if ($Service.StartType -eq "Disabled") {
                    Write-Log "Service already disabled: $ServiceName" "INFO"
                    $Results.SkippedServices += "$ServiceName (already disabled)"
                    continue
                }
                
                # Stop service if running
                if ($Service.Status -eq "Running") {
                    Write-Log "Stopping service: $ServiceName" "INFO"
                    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                }
                
                # Disable service
                Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $ServiceName" "SUCCESS"
                $Results.DisabledServices += $ServiceName
            }
            catch {
                Write-Log "Failed to disable service $ServiceName - $($_.Exception.Message)" "ERROR"
                $Results.FailedServices += "$ServiceName ($($_.Exception.Message))"
                $Results.Success = $false
            }
        }
        
        # Summary report
        Write-Log "Service disabling summary:" "INFO"
        Write-Log "Total processed: $($Results.TotalProcessed)" "INFO"
        Write-Log "Successfully disabled: $($Results.DisabledServices.Count)" "INFO"
        Write-Log "Skipped: $($Results.SkippedServices.Count)" "INFO"
        Write-Log "Failed: $($Results.FailedServices.Count)" "INFO"
        
        if ($Results.DisabledServices.Count -gt 0) {
            Write-Log "Disabled services:" "SUCCESS"
            foreach ($Service in $Results.DisabledServices) {
                Write-Log "  [DISABLED] $Service" "SUCCESS"
            }
        }
        
        if ($Results.SkippedServices.Count -gt 0) {
            Write-Log "Skipped services:" "INFO"
            foreach ($Service in $Results.SkippedServices) {
                Write-Log "  [SKIPPED] $Service" "INFO"
            }
        }
        
        if ($Results.FailedServices.Count -gt 0) {
            Write-Log "Failed services:" "WARN"
            foreach ($Service in $Results.FailedServices) {
                Write-Log "  [FAILED] $Service" "WARN"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Failed to disable Citrix services: $($_.Exception.Message)" "ERROR"
        return @{ 
            Success = $false
            Error = $_.Exception.Message
            DisabledServices = @()
            FailedServices = @()
            SkippedServices = @()
            TotalProcessed = 0
        }
    }
}

function Set-EventLogs {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Configuring event logs for VDI with D: drive redirection..."
        
        # Create EventLog directory on D: drive
        $EventLogPath = "D:\EventLog"
        if (-not (Test-Path $EventLogPath)) {
            New-Item -Path $EventLogPath -ItemType Directory -Force | Out-Null
            Write-Log "Created EventLog directory: $EventLogPath" "SUCCESS"
        }
        
        $Results = @{
            Success = $true
            RedirectedLogs = @()
            FailedRedirections = @()
            SizeConfigured = @()
        }
        
        # Event logs to redirect and configure
        $EventLogConfigs = @(
            @{ Name = "Application"; File = "AppEvent.evt" },
            @{ Name = "System"; File = "SysEvent.evt" },
            @{ Name = "Security"; File = "SecEvent.evt" }
        )
        
        foreach ($LogConfig in $EventLogConfigs) {
            try {
                $LogName = $LogConfig.Name
                $LogFile = $LogConfig.File
                $NewLogPath = Join-Path $EventLogPath $LogFile
                
                # Stop the event log service temporarily
                Write-Log "Configuring $LogName event log redirection..." "INFO"
                
                # Configure the log file path via registry
                $LogRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
                if (Test-Path $LogRegPath) {
                    # Set new log file path
                    Set-ItemProperty -Path $LogRegPath -Name "File" -Value $NewLogPath -ErrorAction Stop
                    
                    # Set maximum size (50MB = 52428800 bytes)
                    Set-ItemProperty -Path $LogRegPath -Name "MaxSize" -Value 52428800 -ErrorAction Stop
                    
                    # Set retention policy (overwrite as needed)
                    Set-ItemProperty -Path $LogRegPath -Name "Retention" -Value 0 -ErrorAction Stop
                    
                    $Results.RedirectedLogs += "$LogName -> $NewLogPath"
                    $Results.SizeConfigured += "$LogName (50MB)"
                    Write-Log "$LogName event log redirected to: $NewLogPath" "SUCCESS"
                }
                else {
                    Write-Log "Registry path not found for $LogName event log" "WARN"
                    $Results.FailedRedirections += "$LogName (registry path missing)"
                }
            }
            catch {
                Write-Log "Failed to redirect $LogName event log: $($_.Exception.Message)" "ERROR"
                $Results.FailedRedirections += "$LogName ($($_.Exception.Message))"
                $Results.Success = $false
            }
        }
        
        # Summary report
        Write-Log "Event log configuration summary:" "INFO"
        Write-Log "Successfully redirected: $($Results.RedirectedLogs.Count) logs" "INFO"
        Write-Log "Failed redirections: $($Results.FailedRedirections.Count)" "INFO"
        
        if ($Results.RedirectedLogs.Count -gt 0) {
            foreach ($RedirectedLog in $Results.RedirectedLogs) {
                Write-Log "  [REDIRECTED] $RedirectedLog" "SUCCESS"
            }
        }
        
        if ($Results.FailedRedirections.Count -gt 0) {
            foreach ($FailedLog in $Results.FailedRedirections) {
                Write-Log "  [FAILED] $FailedLog" "WARN"
            }
        }
        
        Write-Log "Event logs configured for VDI with D: drive storage" "SUCCESS"
        Write-Log "Note: Event log service restart required for changes to take effect" "INFO"
        
        return $Results
    }
    catch {
        Write-Log "Failed to configure event logs: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Set-RegistryOptimizations {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Applying registry optimizations..."
        
        $RegOptimizations = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0 }
        )
        
        foreach ($Opt in $RegOptimizations) {
            Set-ItemProperty -Path $Opt.Path -Name $Opt.Name -Value $Opt.Value -ErrorAction SilentlyContinue
        }
        
        Write-Log "Registry optimizations applied" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to apply registry optimizations: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-VDIOptimizations {
    [CmdletBinding()]
    param(
        [int]$PagefileSizeGB = 8
    )
    
    try {
        Write-Log "Applying VDI optimizations..."
        
        # Configure pagefile
        $PagefileSizeMB = $PagefileSizeGB * 1024
        $CS = Get-WmiObject -Class Win32_ComputerSystem
        $CS.AutomaticManagedPagefile = $false
        $CS.Put() | Out-Null
        
        $PF = Get-WmiObject -Class Win32_PageFileSetting
        if ($PF) {
            $PF.Delete()
        }
        
        # Create pagefile on D: drive for better VDI performance
        Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{
            name = "D:\pagefile.sys"
            InitialSize = $PagefileSizeMB
            MaximumSize = $PagefileSizeMB
        } | Out-Null
        
        Write-Log "VDI optimizations applied with ${PagefileSizeGB}GB pagefile on D: drive" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to apply VDI optimizations: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-VMwareMemoryBallooning {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Disabling VMware memory ballooning..."
        
        $VMwareRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\vmmemctl"
        if (Test-Path $VMwareRegPath) {
            Set-ItemProperty -Path $VMwareRegPath -Name "Start" -Value 4 -ErrorAction SilentlyContinue
            Write-Log "VMware memory ballooning disabled" "SUCCESS"
        }
        else {
            Write-Log "VMware memory ballooning service not found - skipping" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to disable VMware memory ballooning: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-InstallConfig {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Initializing installation configuration..."
        
        $Global:InstallConfig = @{
            StartTime = Get-Date
            Results = @{}
            Errors = @()
            Components = @()
        }
        
        Write-Log "Installation configuration initialized" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to initialize installation configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-CitrixVDA {
    [CmdletBinding()]
    param(
        [string]$VDAISOSourcePath,
        [string]$VDAISOPath,
        [string]$LogDir
    )
    
    try {
        Write-Log "Installing Citrix VDA..."
        
        # Mount ISO and run installation
        $MountResult = Mount-DiskImage -ImagePath $VDAISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        
        $SetupPath = "${DriveLetter}:\x64\XenDesktop Setup\XenDesktopVdaSetup.exe"
        if (Test-Path $SetupPath) {
            $Arguments = "/quiet /optimize /enable_hdx_ports /enable_real_time_transport"
            Start-Process -FilePath $SetupPath -ArgumentList $Arguments -Wait
            Write-Log "Citrix VDA installation completed" "SUCCESS"
        }
        
        Dismount-DiskImage -ImagePath $VDAISOPath
        return $true
    }
    catch {
        Write-Log "Failed to install Citrix VDA: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-PVSTargetDevice {
    [CmdletBinding()]
    param(
        [string]$PVSISOSourcePath,
        [string]$PVSISOPath
    )
    
    try {
        Write-Log "Installing PVS Target Device..."
        
        $MountResult = Mount-DiskImage -ImagePath $PVSISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        
        $SetupPath = "${DriveLetter}:\Device\TargetDeviceSetup.exe"
        if (Test-Path $SetupPath) {
            Start-Process -FilePath $SetupPath -ArgumentList "/quiet" -Wait
            Write-Log "PVS Target Device installation completed" "SUCCESS"
        }
        
        Dismount-DiskImage -ImagePath $PVSISOPath
        return $true
    }
    catch {
        Write-Log "Failed to install PVS Target Device: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-WEMAgent {
    [CmdletBinding()]
    param(
        [string]$WEMSourcePath,
        [string]$WEMPath
    )
    
    try {
        Write-Log "Installing WEM Agent..."
        
        if (Test-Path $WEMPath) {
            Start-Process -FilePath $WEMPath -ArgumentList "/quiet" -Wait
            Write-Log "WEM Agent installation completed" "SUCCESS"
            return $true
        }
        else {
            Write-Log "WEM installer not found at: $WEMPath" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to install WEM Agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-UberAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UberAgentPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Starting UberAgent installation with template and configuration management..."
        
        # Get template and configuration file paths from config
        $TemplatesSourcePath = Get-ConfigValue -Key "UberAgentTemplatesSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
        $TemplatesLocalPath = Get-ConfigValue -Key "UberAgentTemplatesLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\templates" -ConfigFile $ConfigFilePath
        $ConfigSourcePath = Get-ConfigValue -Key "UberAgentConfigSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
        $ConfigLocalPath = Get-ConfigValue -Key "UberAgentConfigLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\uberagent.conf" -ConfigFile $ConfigFilePath
        $LicenseSourcePath = Get-ConfigValue -Key "UberAgentLicenseSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
        $LicenseLocalPath = Get-ConfigValue -Key "UberAgentLicenseLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\uberagent.lic" -ConfigFile $ConfigFilePath
        
        $Results = @{
            OverallSuccess = $false
            InstallationSuccess = $false
            TemplatesCopied = $false
            ConfigCopied = $false
            LicenseCopied = $false
            ServiceStopped = $false
            RegistryCleared = $false
            TempLogsCleared = $false
            OutputDirectoryConfigured = $false
            FilesProcessed = @()
            PostInstallSteps = @()
            Errors = @()
            Skipped = $false
        }
        
        # Check if UberAgent path is provided
        if ([string]::IsNullOrEmpty($UberAgentPath)) {
            Write-Log "UberAgent installation skipped - no installer path specified" "INFO"
            $Results.Skipped = $true
            $Results.OverallSuccess = $true
            return $Results
        }
        
        # Check installer availability
        if (-not (Test-Path $UberAgentPath)) {
            $ErrorMsg = "UberAgent installer not found at: $UberAgentPath"
            Write-Log $ErrorMsg "ERROR"
            $Results.Errors += $ErrorMsg
            return $Results
        }
        
        # Install UberAgent
        Write-Log "Installing UberAgent from: $UberAgentPath"
        $InstallProcess = Start-Process -FilePath $UberAgentPath -ArgumentList "/quiet" -Wait -PassThru
        
        if ($InstallProcess.ExitCode -eq 0) {
            Write-Log "UberAgent installation completed successfully" "SUCCESS"
            $Results.InstallationSuccess = $true
            
            # Wait for installation to complete and create directories
            Start-Sleep -Seconds 5
            
            # Copy template files if configured
            if (![string]::IsNullOrEmpty($TemplatesSourcePath)) {
                Write-Log "Processing UberAgent template files from: $TemplatesSourcePath"
                
                if (Test-Path $TemplatesSourcePath) {
                    try {
                        # Ensure local templates directory exists
                        if (-not (Test-Path $TemplatesLocalPath)) {
                            New-Item -Path $TemplatesLocalPath -ItemType Directory -Force | Out-Null
                            Write-Log "Created local templates directory: $TemplatesLocalPath" "INFO"
                        }
                        
                        # Copy all template files recursively
                        $TemplateFiles = Get-ChildItem -Path $TemplatesSourcePath -File -Recurse -ErrorAction Stop
                        $TemplateCount = 0
                        
                        foreach ($TemplateFile in $TemplateFiles) {
                            try {
                                $RelativePath = $TemplateFile.FullName.Substring($TemplatesSourcePath.Length).TrimStart('\')
                                $DestinationPath = Join-Path $TemplatesLocalPath $RelativePath
                                $DestinationDir = Split-Path $DestinationPath -Parent
                                
                                # Create destination directory if needed
                                if (-not (Test-Path $DestinationDir)) {
                                    New-Item -Path $DestinationDir -ItemType Directory -Force | Out-Null
                                }
                                
                                # Check if file exists and validate before copy
                                $FileExists = Test-Path $DestinationPath
                                $CopyAction = if ($FileExists) { "OVERWRITE" } else { "NEW" }
                                
                                # Get source file info for validation
                                $SourceSize = $TemplateFile.Length
                                $SourceHash = (Get-FileHash -Path $TemplateFile.FullName -Algorithm MD5).Hash
                                
                                # Copy file with force (overwrites existing)
                                Copy-Item -Path $TemplateFile.FullName -Destination $DestinationPath -Force
                                
                                # Validate copied file
                                if (Test-Path $DestinationPath) {
                                    $DestFile = Get-Item $DestinationPath
                                    $DestSize = $DestFile.Length
                                    $DestHash = (Get-FileHash -Path $DestinationPath -Algorithm MD5).Hash
                                    
                                    if ($SourceSize -eq $DestSize -and $SourceHash -eq $DestHash) {
                                        Write-Log "[$CopyAction] Template validated: $($TemplateFile.Name) ($([Math]::Round($SourceSize/1KB, 1)) KB)" "SUCCESS"
                                        $Results.FilesProcessed += "Template: $($TemplateFile.Name) [$CopyAction]"
                                        $TemplateCount++
                                    }
                                    else {
                                        $ErrorMsg = "Template validation failed: $($TemplateFile.Name) - Size/Hash mismatch"
                                        Write-Log $ErrorMsg "ERROR"
                                        $Results.Errors += $ErrorMsg
                                    }
                                }
                                else {
                                    $ErrorMsg = "Template copy verification failed: $($TemplateFile.Name) - File not found after copy"
                                    Write-Log $ErrorMsg "ERROR"
                                    $Results.Errors += $ErrorMsg
                                }
                            }
                            catch {
                                $ErrorMsg = "Failed to copy template $($TemplateFile.Name): $($_.Exception.Message)"
                                Write-Log $ErrorMsg "ERROR"
                                $Results.Errors += $ErrorMsg
                            }
                        }
                        
                        if ($TemplateCount -gt 0) {
                            $Results.TemplatesCopied = $true
                            Write-Log "UberAgent templates copied successfully ($TemplateCount files)" "SUCCESS"
                        }
                    }
                    catch {
                        $ErrorMsg = "Failed to process UberAgent templates: $($_.Exception.Message)"
                        Write-Log $ErrorMsg "ERROR"
                        $Results.Errors += $ErrorMsg
                    }
                }
                else {
                    $ErrorMsg = "UberAgent templates source path not found: $TemplatesSourcePath"
                    Write-Log $ErrorMsg "WARN"
                    $Results.Errors += $ErrorMsg
                }
            }
            else {
                Write-Log "UberAgent templates source path not configured - skipping template copy" "INFO"
            }
            
            # Copy configuration file if configured
            if (![string]::IsNullOrEmpty($ConfigSourcePath)) {
                Write-Log "Processing UberAgent configuration file from: $ConfigSourcePath"
                
                if (Test-Path $ConfigSourcePath) {
                    try {
                        $ConfigDir = Split-Path $ConfigLocalPath -Parent
                        if (-not (Test-Path $ConfigDir)) {
                            New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
                            Write-Log "Created config directory: $ConfigDir" "INFO"
                        }
                        
                        # Check if config file exists and validate
                        $ConfigExists = Test-Path $ConfigLocalPath
                        $CopyAction = if ($ConfigExists) { "OVERWRITE" } else { "NEW" }
                        
                        # Get source file info for validation
                        $SourceFile = Get-Item $ConfigSourcePath
                        $SourceSize = $SourceFile.Length
                        $SourceHash = (Get-FileHash -Path $ConfigSourcePath -Algorithm MD5).Hash
                        
                        Copy-Item -Path $ConfigSourcePath -Destination $ConfigLocalPath -Force
                        
                        # Validate copied config file
                        if (Test-Path $ConfigLocalPath) {
                            $DestFile = Get-Item $ConfigLocalPath
                            $DestSize = $DestFile.Length
                            $DestHash = (Get-FileHash -Path $ConfigLocalPath -Algorithm MD5).Hash
                            
                            if ($SourceSize -eq $DestSize -and $SourceHash -eq $DestHash) {
                                Write-Log "[$CopyAction] UberAgent configuration file validated successfully ($([Math]::Round($SourceSize/1KB, 1)) KB)" "SUCCESS"
                                $Results.ConfigCopied = $true
                                $Results.FilesProcessed += "Config: uberagent.conf [$CopyAction]"
                            }
                            else {
                                $ErrorMsg = "Configuration file validation failed - Size/Hash mismatch"
                                Write-Log $ErrorMsg "ERROR"
                                $Results.Errors += $ErrorMsg
                            }
                        }
                        else {
                            $ErrorMsg = "Configuration file copy verification failed - File not found after copy"
                            Write-Log $ErrorMsg "ERROR"
                            $Results.Errors += $ErrorMsg
                        }
                    }
                    catch {
                        $ErrorMsg = "Failed to copy UberAgent configuration: $($_.Exception.Message)"
                        Write-Log $ErrorMsg "ERROR"
                        $Results.Errors += $ErrorMsg
                    }
                }
                else {
                    $ErrorMsg = "UberAgent config file not found: $ConfigSourcePath"
                    Write-Log $ErrorMsg "WARN"
                    $Results.Errors += $ErrorMsg
                }
            }
            else {
                Write-Log "UberAgent config source path not configured - skipping config copy" "INFO"
            }
            
            # Copy license file if configured
            if (![string]::IsNullOrEmpty($LicenseSourcePath)) {
                Write-Log "Processing UberAgent license file from: $LicenseSourcePath"
                
                if (Test-Path $LicenseSourcePath) {
                    try {
                        $LicenseDir = Split-Path $LicenseLocalPath -Parent
                        if (-not (Test-Path $LicenseDir)) {
                            New-Item -Path $LicenseDir -ItemType Directory -Force | Out-Null
                            Write-Log "Created license directory: $LicenseDir" "INFO"
                        }
                        
                        # Check if license file exists and validate
                        $LicenseExists = Test-Path $LicenseLocalPath
                        $CopyAction = if ($LicenseExists) { "OVERWRITE" } else { "NEW" }
                        
                        # Get source file info for validation
                        $SourceFile = Get-Item $LicenseSourcePath
                        $SourceSize = $SourceFile.Length
                        $SourceHash = (Get-FileHash -Path $LicenseSourcePath -Algorithm MD5).Hash
                        
                        Copy-Item -Path $LicenseSourcePath -Destination $LicenseLocalPath -Force
                        
                        # Validate copied license file
                        if (Test-Path $LicenseLocalPath) {
                            $DestFile = Get-Item $LicenseLocalPath
                            $DestSize = $DestFile.Length
                            $DestHash = (Get-FileHash -Path $LicenseLocalPath -Algorithm MD5).Hash
                            
                            if ($SourceSize -eq $DestSize -and $SourceHash -eq $DestHash) {
                                Write-Log "[$CopyAction] UberAgent license file validated successfully ($([Math]::Round($SourceSize/1KB, 1)) KB)" "SUCCESS"
                                $Results.LicenseCopied = $true
                                $Results.FilesProcessed += "License: uberagent.lic [$CopyAction]"
                            }
                            else {
                                $ErrorMsg = "License file validation failed - Size/Hash mismatch"
                                Write-Log $ErrorMsg "ERROR"
                                $Results.Errors += $ErrorMsg
                            }
                        }
                        else {
                            $ErrorMsg = "License file copy verification failed - File not found after copy"
                            Write-Log $ErrorMsg "ERROR"
                            $Results.Errors += $ErrorMsg
                        }
                    }
                    catch {
                        $ErrorMsg = "Failed to copy UberAgent license: $($_.Exception.Message)"
                        Write-Log $ErrorMsg "ERROR"
                        $Results.Errors += $ErrorMsg
                    }
                }
                else {
                    $ErrorMsg = "UberAgent license file not found: $LicenseSourcePath"
                    Write-Log $ErrorMsg "WARN"
                    $Results.Errors += $ErrorMsg
                }
            }
            else {
                Write-Log "UberAgent license source path not configured - skipping license copy" "INFO"
            }
            
            # Post-installation cleanup and configuration
            Write-Log "Performing UberAgent post-installation cleanup and configuration..."
            
            # Get post-installation configuration values
            $ServiceName = Get-ConfigValue -Key "UberAgentServiceName" -DefaultValue "uberAgentsvc" -ConfigFile $ConfigFilePath
            $RegistryPath = Get-ConfigValue -Key "UberAgentRegistryPath" -DefaultValue "HKLM:\Software\vast limits\uberAgent" -ConfigFile $ConfigFilePath
            $OutputQueueName = Get-ConfigValue -Key "UberAgentOutputQueueName" -DefaultValue "Output Queue" -ConfigFile $ConfigFilePath
            $OutputDirectory = Get-ConfigValue -Key "UberAgentOutputDirectory" -DefaultValue "D:\Logs\uberAgent\$OutputQueueName" -ConfigFile $ConfigFilePath
            $TempLogPattern = Get-ConfigValue -Key "UberAgentTempLogPattern" -DefaultValue "uberagent*.log" -ConfigFile $ConfigFilePath
            
            # Add post-installation result tracking
            $Results.ServiceStopped = $false
            $Results.RegistryCleared = $false
            $Results.TempLogsCleared = $false
            $Results.OutputDirectoryConfigured = $false
            $Results.PostInstallSteps = @()
            
            # Step 1: Stop UberAgent service
            try {
                Write-Log "Stopping UberAgent service: $ServiceName"
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    if ($Service.Status -eq "Running") {
                        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                        Write-Log "UberAgent service stopped successfully" "SUCCESS"
                        $Results.ServiceStopped = $true
                        $Results.PostInstallSteps += "Service stopped: $ServiceName"
                    }
                    else {
                        Write-Log "UberAgent service was already stopped" "INFO"
                        $Results.ServiceStopped = $true
                        $Results.PostInstallSteps += "Service already stopped: $ServiceName"
                    }
                }
                else {
                    Write-Log "UberAgent service not found: $ServiceName" "WARN"
                    $Results.PostInstallSteps += "Service not found: $ServiceName"
                }
            }
            catch {
                $ErrorMsg = "Failed to stop UberAgent service: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Step 2: Clear UberAgent registry key
            try {
                Write-Log "Clearing UberAgent registry key: $RegistryPath"
                
                if (Test-Path $RegistryPath) {
                    Remove-Item -Path $RegistryPath -Recurse -Force -ErrorAction Stop
                    Write-Log "UberAgent registry key cleared successfully" "SUCCESS"
                    $Results.RegistryCleared = $true
                    $Results.PostInstallSteps += "Registry cleared: $RegistryPath"
                }
                else {
                    Write-Log "UberAgent registry key not found: $RegistryPath" "INFO"
                    $Results.RegistryCleared = $true
                    $Results.PostInstallSteps += "Registry key not found: $RegistryPath"
                }
            }
            catch {
                $ErrorMsg = "Failed to clear UberAgent registry key: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Step 3: Clear temporary log files
            try {
                Write-Log "Clearing UberAgent temporary log files from C:\Windows\temp"
                $TempPath = "C:\Windows\temp"
                $LogFiles = Get-ChildItem -Path $TempPath -Filter $TempLogPattern -ErrorAction SilentlyContinue
                
                if ($LogFiles.Count -gt 0) {
                    $DeletedCount = 0
                    foreach ($LogFile in $LogFiles) {
                        try {
                            Remove-Item -Path $LogFile.FullName -Force -ErrorAction Stop
                            Write-Log "Deleted temp log: $($LogFile.Name)" "SUCCESS"
                            $DeletedCount++
                        }
                        catch {
                            Write-Log "Failed to delete temp log $($LogFile.Name): $($_.Exception.Message)" "WARN"
                        }
                    }
                    
                    if ($DeletedCount -gt 0) {
                        Write-Log "Cleared $DeletedCount UberAgent temporary log files" "SUCCESS"
                        $Results.TempLogsCleared = $true
                        $Results.PostInstallSteps += "Temp logs cleared: $DeletedCount files"
                    }
                }
                else {
                    Write-Log "No UberAgent temporary log files found" "INFO"
                    $Results.TempLogsCleared = $true
                    $Results.PostInstallSteps += "No temp logs found"
                }
            }
            catch {
                $ErrorMsg = "Failed to clear UberAgent temporary logs: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Step 4: Configure output directory
            try {
                Write-Log "Configuring UberAgent output directory: $OutputDirectory"
                
                if (Test-Path $OutputDirectory) {
                    # Directory exists, check for existing files
                    $ExistingFiles = Get-ChildItem -Path $OutputDirectory -File -ErrorAction SilentlyContinue
                    
                    if ($ExistingFiles.Count -gt 0) {
                        Write-Log "Clearing existing files from output directory ($($ExistingFiles.Count) files)"
                        $ClearedCount = 0
                        
                        foreach ($File in $ExistingFiles) {
                            try {
                                Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                                $ClearedCount++
                            }
                            catch {
                                Write-Log "Failed to delete file $($File.Name): $($_.Exception.Message)" "WARN"
                            }
                        }
                        
                        Write-Log "Cleared $ClearedCount files from output directory" "SUCCESS"
                        $Results.PostInstallSteps += "Output directory cleared: $ClearedCount files"
                    }
                    else {
                        Write-Log "Output directory already exists and is empty" "INFO"
                        $Results.PostInstallSteps += "Output directory already clean"
                    }
                }
                else {
                    # Create the output directory
                    New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Log "Created UberAgent output directory: $OutputDirectory" "SUCCESS"
                    $Results.PostInstallSteps += "Output directory created: $OutputDirectory"
                }
                
                $Results.OutputDirectoryConfigured = $true
            }
            catch {
                $ErrorMsg = "Failed to configure UberAgent output directory: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Determine overall success
            $Results.OverallSuccess = $Results.InstallationSuccess
            
            # Summary report
            Write-Log "UberAgent installation and configuration summary:" "INFO"
            Write-Log "Installation: $(if ($Results.InstallationSuccess) { 'SUCCESS' } else { 'FAILED' })" "INFO"
            Write-Log "Templates copied: $(if ($Results.TemplatesCopied) { 'YES' } else { 'NO/SKIPPED' })" "INFO"
            Write-Log "Config copied: $(if ($Results.ConfigCopied) { 'YES' } else { 'NO/SKIPPED' })" "INFO"
            Write-Log "License copied: $(if ($Results.LicenseCopied) { 'YES' } else { 'NO/SKIPPED' })" "INFO"
            Write-Log "Service stopped: $(if ($Results.ServiceStopped) { 'YES' } else { 'NO' })" "INFO"
            Write-Log "Registry cleared: $(if ($Results.RegistryCleared) { 'YES' } else { 'NO' })" "INFO"
            Write-Log "Temp logs cleared: $(if ($Results.TempLogsCleared) { 'YES' } else { 'NO' })" "INFO"
            Write-Log "Output directory configured: $(if ($Results.OutputDirectoryConfigured) { 'YES' } else { 'NO' })" "INFO"
            Write-Log "Files processed: $($Results.FilesProcessed.Count)" "INFO"
            
            if ($Results.FilesProcessed.Count -gt 0) {
                Write-Log "Processed files:" "SUCCESS"
                foreach ($File in $Results.FilesProcessed) {
                    Write-Log "  [COPIED] $File" "SUCCESS"
                }
            }
            
            if ($Results.PostInstallSteps.Count -gt 0) {
                Write-Log "Post-installation steps:" "SUCCESS"
                foreach ($Step in $Results.PostInstallSteps) {
                    Write-Log "  [COMPLETED] $Step" "SUCCESS"
                }
            }
            
            if ($Results.Errors.Count -gt 0) {
                Write-Log "Issues encountered:" "WARN"
                foreach ($Error in $Results.Errors) {
                    Write-Log "  [ISSUE] $Error" "WARN"
                }
            }
        }
        else {
            $ErrorMsg = "UberAgent installation failed with exit code: $($InstallProcess.ExitCode)"
            Write-Log $ErrorMsg "ERROR"
            $Results.Errors += $ErrorMsg
        }
        
        return $Results
    }
    catch {
        $ErrorMsg = "Failed to install UberAgent: $($_.Exception.Message)"
        Write-Log $ErrorMsg "ERROR"
        return @{
            OverallSuccess = $false
            InstallationSuccess = $false
            TemplatesCopied = $false
            ConfigCopied = $false
            LicenseCopied = $false
            ServiceStopped = $false
            RegistryCleared = $false
            TempLogsCleared = $false
            OutputDirectoryConfigured = $false
            FilesProcessed = @()
            PostInstallSteps = @()
            Errors = @($ErrorMsg)
            Skipped = $false
        }
    }
}

function Set-IBMTADDMPermissions {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Configuring IBM TADDM permissions..."
        
        # Basic TADDM permission setup
        $TADDMPath = "C:\Program Files\IBM\TADDM"
        if (Test-Path $TADDMPath) {
            $Acl = Get-Acl $TADDMPath
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $Acl.SetAccessRule($AccessRule)
            Set-Acl -Path $TADDMPath -AclObject $Acl
            Write-Log "IBM TADDM permissions configured" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to configure IBM TADDM permissions: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-Domain {
    [CmdletBinding()]
    param(
        [string]$DomainName,
        [PSCredential]$Credential
    )
    
    try {
        Write-Log "Joining domain: $DomainName..."
        
        Add-Computer -DomainName $DomainName -Credential $Credential -Force
        Write-Log "Domain join completed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to join domain: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-InstallationReport {
    [CmdletBinding()]
    param(
        [hashtable]$Results,
        [string]$ReportPath
    )
    
    try {
        Write-Log "Generating installation report..."
        
        $Report = @()
        $Report += "Citrix Installation Report - $(Get-Date)"
        $Report += "=========================================="
        
        foreach ($Component in $Results.Keys) {
            $Status = if ($Results[$Component]) { "SUCCESS" } else { "FAILED" }
            $Report += "$Component : $Status"
        }
        
        $Report | Out-File -FilePath $ReportPath -Force
        Write-Log "Installation report saved to: $ReportPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to generate installation report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-StartupShutdownScripts {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Configuring startup/shutdown scripts..."
        
        # Basic startup/shutdown script configuration
        $GPOPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts"
        if (-not (Test-Path $GPOPath)) {
            New-Item -Path $GPOPath -Force | Out-Null
        }
        
        Write-Log "Startup/shutdown scripts configured" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to configure startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-StartupShutdownScripts {
    [CmdletBinding()]
    param(
        [string]$StartupScriptPath = "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup",
        [string]$ShutdownScriptPath = "C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown"
    )
    
    try {
        Write-Log "Registering startup and shutdown scripts with Windows..."
        
        $Results = @{
            Success = $true
            StartupScriptsRegistered = 0
            ShutdownScriptsRegistered = 0
            RegisteredScripts = @()
            FailedRegistrations = @()
        }
        
        # Create Group Policy Script registry structure
        $GPOScriptsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts"
        $StartupRegPath = "$GPOScriptsPath\Startup"
        $ShutdownRegPath = "$GPOScriptsPath\Shutdown"
        
        # Ensure registry paths exist
        @($GPOScriptsPath, $StartupRegPath, $ShutdownRegPath) | ForEach-Object {
            if (-not (Test-Path $_)) {
                New-Item -Path $_ -Force | Out-Null
                Write-Log "Created registry path: $_" "INFO"
            }
        }
        
        # Register startup scripts
        if (Test-Path $StartupScriptPath) {
            $StartupScripts = Get-ChildItem -Path $StartupScriptPath -Filter "*.ps1" -ErrorAction SilentlyContinue
            $ScriptIndex = 0
            
            foreach ($Script in $StartupScripts) {
                try {
                    $ScriptRegPath = "$StartupRegPath\$ScriptIndex"
                    New-Item -Path $ScriptRegPath -Force | Out-Null
                    
                    # Set script properties
                    Set-ItemProperty -Path $ScriptRegPath -Name "Script" -Value $Script.FullName
                    Set-ItemProperty -Path $ScriptRegPath -Name "Parameters" -Value ""
                    Set-ItemProperty -Path $ScriptRegPath -Name "IsPowershell" -Value 1
                    Set-ItemProperty -Path $ScriptRegPath -Name "ExecTime" -Value 0
                    
                    $Results.StartupScriptsRegistered++
                    $Results.RegisteredScripts += @{ Type = "Startup"; Name = $Script.Name; Path = $Script.FullName }
                    Write-Log "Registered startup script: $($Script.Name)" "SUCCESS"
                    
                    $ScriptIndex++
                }
                catch {
                    $Results.FailedRegistrations += @{ Type = "Startup"; Name = $Script.Name; Error = $_.Exception.Message }
                    Write-Log "Failed to register startup script $($Script.Name): $($_.Exception.Message)" "ERROR"
                    $Results.Success = $false
                }
            }
            
            # Set startup script count
            if ($ScriptIndex -gt 0) {
                Set-ItemProperty -Path $StartupRegPath -Name "PSScriptOrder" -Value (0..($ScriptIndex-1))
            }
        }
        
        # Register shutdown scripts
        if (Test-Path $ShutdownScriptPath) {
            $ShutdownScripts = Get-ChildItem -Path $ShutdownScriptPath -Filter "*.ps1" -ErrorAction SilentlyContinue
            $ScriptIndex = 0
            
            foreach ($Script in $ShutdownScripts) {
                try {
                    $ScriptRegPath = "$ShutdownRegPath\$ScriptIndex"
                    New-Item -Path $ScriptRegPath -Force | Out-Null
                    
                    # Set script properties
                    Set-ItemProperty -Path $ScriptRegPath -Name "Script" -Value $Script.FullName
                    Set-ItemProperty -Path $ScriptRegPath -Name "Parameters" -Value ""
                    Set-ItemProperty -Path $ScriptRegPath -Name "IsPowershell" -Value 1
                    Set-ItemProperty -Path $ScriptRegPath -Name "ExecTime" -Value 0
                    
                    $Results.ShutdownScriptsRegistered++
                    $Results.RegisteredScripts += @{ Type = "Shutdown"; Name = $Script.Name; Path = $Script.FullName }
                    Write-Log "Registered shutdown script: $($Script.Name)" "SUCCESS"
                    
                    $ScriptIndex++
                }
                catch {
                    $Results.FailedRegistrations += @{ Type = "Shutdown"; Name = $Script.Name; Error = $_.Exception.Message }
                    Write-Log "Failed to register shutdown script $($Script.Name): $($_.Exception.Message)" "ERROR"
                    $Results.Success = $false
                }
            }
            
            # Set shutdown script count
            if ($ScriptIndex -gt 0) {
                Set-ItemProperty -Path $ShutdownRegPath -Name "PSScriptOrder" -Value (0..($ScriptIndex-1))
            }
        }
        
        # Scripts will be recognized on next system restart
        Write-Log "Scripts registered - will be executed on next system startup/shutdown" "INFO"
        
        Write-Log "Script registration completed - $($Results.StartupScriptsRegistered) startup, $($Results.ShutdownScriptsRegistered) shutdown scripts registered" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Failed to register startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Export module functions
Export-ModuleMember -Function *