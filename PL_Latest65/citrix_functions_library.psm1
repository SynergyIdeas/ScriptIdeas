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
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
} catch {
    # Ignore execution policy errors in non-Windows environments
}

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
        # Ensure absolute path
        if (-not [System.IO.Path]::IsPathRooted($ConfigFilePath)) {
            $ConfigFilePath = Join-Path $PSScriptRoot $ConfigFilePath
        }
        
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
    
    try {
        if ($ConfigFile -eq "") {
            # Try multiple locations for the config file
            $PossiblePaths = @(
                "CitrixConfig.txt",                              # Current directory
                ".\CitrixConfig.txt",                           # Explicit current directory
                (Join-Path $PSScriptRoot "CitrixConfig.txt"),   # Module directory
                (Join-Path (Get-Location) "CitrixConfig.txt")   # Working directory
            )
            
            $ConfigFile = $null
            foreach ($Path in $PossiblePaths) {
                if (Test-Path $Path) {
                    $ConfigFile = $Path
                    break
                }
            }
            
            if (-not $ConfigFile) {
                $ConfigFile = "CitrixConfig.txt"  # Use default for error message
            }
        }
        
        if (-not (Test-Path $ConfigFile)) {
            Write-Warning "Configuration file not found: $ConfigFile, using default for '$Key': $DefaultValue"
            return $DefaultValue
        }
        
        # First pass: collect all config values for variable expansion
        $ConfigContent = Get-Content $ConfigFile
        $ConfigData = @{}
        
        foreach ($Line in $ConfigContent) {
            if ($Line -and -not $Line.StartsWith("#") -and $Line.Contains("=")) {
                $Parts = $Line -split "=", 2
                if ($Parts.Count -eq 2) {
                    $ConfigKey = $Parts[0].Trim()
                    $ConfigValue = $Parts[1].Trim()
                    $ConfigData[$ConfigKey] = $ConfigValue
                }
            }
        }
        
        # Second pass: find the requested key and expand variables
        $Value = $DefaultValue
        $KeyFound = $false
        
        if ($ConfigData.ContainsKey($Key)) {
            $Value = $ConfigData[$Key]
            $KeyFound = $true
            
            # Handle variable expansion for %VariableName% patterns
            while ($Value -match '%([^%]+)%') {
                $VarName = $Matches[1]
                $VarValue = $null
                
                # Check if it's another config key
                if ($ConfigData.ContainsKey($VarName)) {
                    $VarValue = $ConfigData[$VarName]
                } else {
                    # Check environment variables
                    $VarValue = [Environment]::GetEnvironmentVariable($VarName)
                }
                
                if ($VarValue) {
                    $Value = $Value -replace "%$VarName%", $VarValue
                } else {
                    # Remove unresolved variables
                    $Value = $Value -replace "%$VarName%", ""
                }
            }
            
            # Convert string values to appropriate types
            if ($Value -eq "true") { $Value = $true }
            elseif ($Value -eq "false") { $Value = $false }
            elseif ($Value -match '^\d+$') { $Value = [int]$Value }
        }
        
        if ($ShowStatus) {
            $Status = if ($KeyFound) { "[CONFIG]" } else { "[DEFAULT]" }
            Write-Host "  $Status $Key = $Value" -ForegroundColor $(if ($KeyFound) { 'Green' } else { 'Yellow' })
        }
        
        return $Value
    }
    catch {
        Write-Warning "Error in Get-ConfigValue for key '$Key': $($_.Exception.Message)"
        return $DefaultValue
    }
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
        [switch]$CreateIfNotExists
    )
    
    try {
        # Try multiple methods to get desktop path
        $DesktopPath = $null
        
        # Method 1: .NET SpecialFolder
        try {
            $DesktopPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
            if (![string]::IsNullOrEmpty($DesktopPath) -and (Test-Path $DesktopPath)) {
                return $DesktopPath
            }
        }
        catch { }
        
        # Method 2: Registry lookup
        try {
            $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            $DesktopPath = (Get-ItemProperty -Path $RegPath -Name "Desktop" -ErrorAction SilentlyContinue).Desktop
            if (![string]::IsNullOrEmpty($DesktopPath) -and (Test-Path $DesktopPath)) {
                return $DesktopPath
            }
        }
        catch { }
        
        # Method 3: Environment variable
        $DesktopPath = "$env:USERPROFILE\Desktop"
        if (Test-Path $DesktopPath) {
            return $DesktopPath
        }
        
        # Method 4: Create desktop if it doesn't exist
        if ($CreateIfNotExists) {
            try {
                New-Item -Path $DesktopPath -ItemType Directory -Force | Out-Null
                return $DesktopPath
            }
            catch { }
        }
        
        # Method 5: Public desktop
        $PublicDesktop = "$env:PUBLIC\Desktop"
        if (Test-Path $PublicDesktop) {
            return $PublicDesktop
        }
        
        # Final fallback
        return $env:TEMP
    }
    catch {
        return $env:TEMP
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
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = "CitrixConfig.txt"
    )
    
    # Check if detailed logging is enabled
    $DetailedLogging = $true
    try {
        $DetailedLogging = [bool](Get-ConfigValue -Key "DetailedLogging" -DefaultValue "true" -ConfigFile $ConfigFilePath)
    } catch {
        # If config reading fails, default to detailed logging
        $DetailedLogging = $true
    }
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN" { Write-Host $LogEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "DEBUG" { if ($Global:VerboseLogging -or $DetailedLogging) { Write-Host $LogEntry -ForegroundColor Cyan } }
        default { Write-Host $LogEntry -ForegroundColor White }
    }
    
    # File logging - ensure log file is created (only if detailed logging is enabled)
    if ($Global:LogPath -and $DetailedLogging) {
        try {
            # Ensure log directory exists
            $LogDir = Split-Path $Global:LogPath -Parent
            if (-not (Test-Path $LogDir)) {
                New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
            }
            
            # Write to log file
            $LogEntry | Out-File -FilePath $Global:LogPath -Append -Force
        }
        catch {
            # If logging fails, try to create log on desktop as fallback
            try {
                $FallbackLogPath = "$env:USERPROFILE\Desktop\Citrix_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                $LogEntry | Out-File -FilePath $FallbackLogPath -Append -Force
                $Global:LogPath = $FallbackLogPath
            }
            catch {
                # Final fallback - continue without file logging
            }
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

function Write-LogMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Level = "INFO"
    )
    
    Write-Log "  - $Message" $Level
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
        $OSInfo = Get-WmiOrCimInstance -ClassName Win32_OperatingSystem
        $OSVersion = $OSInfo.Version
        $OSCaption = $OSInfo.Caption
        $OSBuild = $OSInfo.BuildNumber
        
        # Determine OS type and recommend script sources
        $ScriptSource = "win2022"  # Default to Windows 2022
        
        if ($OSCaption -like "*Server 2019*") {
            $ScriptSource = "win2019"
        }
        elseif ($OSCaption -like "*Server 2022*" -or $OSCaption -like "*Server*") {
            $ScriptSource = "win2022"
        }
        elseif ($OSCaption -like "*Windows Server*") {
            $ScriptSource = "win2022"  # Use 2022 scripts for server OS
        }
        
        $Result = @{
            Version = $OSVersion
            Caption = $OSCaption
            Build = $OSBuild
            ScriptSource = $ScriptSource
            IsServer = $OSCaption -like "*Server*"
            IsClient = $OSCaption -notlike "*Server*"
        }
        
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
        Write-Log " "
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
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
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

function Set-EventLogRedirection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Redirecting Windows event logs to cache drive..." "INFO"
        
        # Get cache drive letter and event logs path from config
        $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
        $EventLogsPath = Get-ConfigValue -Key "EventLogsPath" -DefaultValue "EventLogs" -ConfigFile $ConfigFilePath
        $LogsPath = "${CacheDriveLetter}:\${EventLogsPath}"
        if (-not (Test-Path $LogsPath)) {
            New-Item -Path $LogsPath -ItemType Directory -Force | Out-Null
            Write-Log "Created event logs directory: $LogsPath" "INFO"
        }
        
        # Event logs to redirect
        $EventLogs = @("Application", "System", "Security")
        $RedirectedCount = 0
        
        foreach ($LogName in $EventLogs) {
            try {
                $LogRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
                $NewLogPath = "${LogsPath}\${LogName}.evtx"
                
                if (Test-Path $LogRegPath) {
                    Set-ItemProperty -Path $LogRegPath -Name "File" -Value $NewLogPath -Force
                    Write-Log "Redirected $LogName event log to $NewLogPath" "SUCCESS"
                    $RedirectedCount++
                }
            }
            catch {
                Write-Log "Failed to redirect ${LogName} event log: $($_.Exception.Message)" "WARN"
            }
        }
        
        if ($RedirectedCount -eq $EventLogs.Count) {
            Write-Log "All event logs successfully redirected to cache drive" "SUCCESS"
            return $true
        } else {
            Write-Log "Event log redirection partially completed ($RedirectedCount/$($EventLogs.Count))" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Event log redirection failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-UserProfileRedirection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Configuring user profile redirection to cache drive..." "INFO"
        
        # Get cache drive letter and user profiles path from config
        $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
        $UserProfilesPath = Get-ConfigValue -Key "UserProfilesPath" -DefaultValue "Profiles" -ConfigFile $ConfigFilePath
        $ProfilesPath = "${CacheDriveLetter}:\${UserProfilesPath}"
        if (-not (Test-Path $ProfilesPath)) {
            New-Item -Path $ProfilesPath -ItemType Directory -Force | Out-Null
            Write-Log "Created profiles directory: $ProfilesPath" "INFO"
        }
        
        # Configure user profile redirection registry settings
        $ProfileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        
        try {
            # Set default user profile path to cache drive
            Set-ItemProperty -Path $ProfileRegPath -Name "DefaultUserProfile" -Value $ProfilesPath -Force
            Set-ItemProperty -Path $ProfileRegPath -Name "ProfilesDirectory" -Value $ProfilesPath -Force
            
            Write-Log "User profile redirection configured to $ProfilesPath" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to configure profile redirection registry: $($_.Exception.Message)" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "User profile redirection failed: $($_.Exception.Message)" "ERROR"
        return $false
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



function Get-DesktopLogPath {
    [CmdletBinding()]
    param(
        [string]$LogFileName = ""
    )
    
    try {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        if ([string]::IsNullOrEmpty($LogFileName)) {
            $LogFileName = "Citrix_Install_$Timestamp.log"
        }
        
        # Try to get desktop path and create log file
        $DesktopPath = Get-DesktopPath -CreateIfNotExists
        $FullLogPath = Join-Path $DesktopPath $LogFileName
        
        # Immediately create the log file to ensure it exists
        try {
            "# Citrix Installation Log - Created $(Get-Date)" | Out-File -FilePath $FullLogPath -Force
            
            # Verify the file was created
            if (Test-Path $FullLogPath) {
                Write-Host "Log file created successfully: $FullLogPath" -ForegroundColor Green
                return $FullLogPath
            }
        }
        catch {
            Write-Host "Failed to create desktop log: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Fallback to temp directory with immediate creation
        $TempLogPath = "$env:TEMP\$LogFileName"
        try {
            "# Citrix Installation Log - Created $(Get-Date)" | Out-File -FilePath $TempLogPath -Force
            Write-Host "Using temp directory for log: $TempLogPath" -ForegroundColor Yellow
            return $TempLogPath
        }
        catch {
            Write-Host "Failed to create any log file: $($_.Exception.Message)" -ForegroundColor Red
            # Final fallback - return a valid path even if we can't create the file
            return "/tmp/$LogFileName"
        }
    }
    catch {
        Write-Host "Critical error in log path creation: $($_.Exception.Message)" -ForegroundColor Red
        # Emergency fallback - ensure we always return a string
        $FallbackLog = "Citrix_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        return "/tmp/$FallbackLog"
    }
}

function Copy-AllInstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FilesToCopy,
        
        [Parameter(Mandatory=$true)]
        [string]$TempDirectory
    )
    
    try {
        Write-Log "Starting simple file copy to temp directory..."
        
        # Ensure temp directory exists
        if (-not (Test-Path $TempDirectory)) {
            New-Item -Path $TempDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created temp directory: $TempDirectory"
        }
        
        $Results = @{
            Success = $true
            CopiedFiles = @()
            FailedFiles = @()
            TotalFiles = 0
            SuccessfulCopies = 0
        }
        
        # Copy each file
        foreach ($FileInfo in $FilesToCopy.GetEnumerator()) {
            $SourcePath = $FileInfo.Value.Source
            $DestinationPath = $FileInfo.Value.Destination
            $FileType = $FileInfo.Key
            
            $Results.TotalFiles++
            
            if ([string]::IsNullOrEmpty($SourcePath)) {
                Write-Log "Skipping $FileType - no source path specified" "INFO"
                continue
            }
            
            Write-Log "Copying $FileType..."
            Write-Log "  From: $SourcePath"
            Write-Log "  To: $DestinationPath"
            
            # Check source exists
            if (-not (Test-Path $SourcePath)) {
                Write-Log "Source file not found: $SourcePath" "ERROR"
                $Results.FailedFiles += @{
                    Type = $FileType
                    Source = $SourcePath
                    Destination = $DestinationPath
                    Error = "Source file not found"
                }
                $Results.Success = $false
                continue
            }
            
            # Simple copy operation
            try {
                Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
                
                # Validate copy
                if (Test-Path $DestinationPath) {
                    Write-Log "$FileType copied successfully" "SUCCESS"
                    $Results.CopiedFiles += @{
                        Type = $FileType
                        Source = $SourcePath
                        Destination = $DestinationPath
                    }
                    $Results.SuccessfulCopies++
                } else {
                    throw "Destination file not created"
                }
            }
            catch {
                Write-Log "Failed to copy ${FileType}: $($_.Exception.Message)" "ERROR"
                $Results.FailedFiles += @{
                    Type = $FileType
                    Source = $SourcePath
                    Destination = $DestinationPath
                    Error = $_.Exception.Message
                }
                $Results.Success = $false
            }
        }
        
        # Summary
        Write-Log "File copy summary: $($Results.SuccessfulCopies)/$($Results.TotalFiles) files copied successfully"
        
        return $Results
    }
    catch {
        Write-Log "File copy operation failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            CopiedFiles = @()
            FailedFiles = @()
            TotalFiles = 0
            SuccessfulCopies = 0
            Error = $_.Exception.Message
        }
    }
}

function Test-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FilePaths
    )
    
    try {
        Write-Log "Validating all installation files exist in temp directory..."
        
        $Results = @{
            AllValid = $true
            ValidFiles = @()
            MissingFiles = @()
            TotalFiles = $FilePaths.Count
        }
        
        foreach ($FilePath in $FilePaths) {
            if ([string]::IsNullOrEmpty($FilePath)) {
                continue
            }
            
            if (Test-Path $FilePath) {
                $FileSize = (Get-Item $FilePath).Length
                Write-Log "FOUND: $(Split-Path $FilePath -Leaf) ($([math]::Round($FileSize/1MB, 2)) MB)" "SUCCESS"
                $Results.ValidFiles += $FilePath
            } else {
                Write-Log "MISSING: $FilePath" "ERROR"
                $Results.MissingFiles += $FilePath
                $Results.AllValid = $false
            }
        }
        
        if ($Results.AllValid) {
            Write-Log "All installation files validated successfully" "SUCCESS"
        } else {
            Write-Log "Missing $($Results.MissingFiles.Count) installation files" "ERROR"
        }
        
        return $Results
    }
    catch {
        Write-Log "File validation failed: $($_.Exception.Message)" "ERROR"
        return @{
            AllValid = $false
            ValidFiles = @()
            MissingFiles = @()
            TotalFiles = 0
            Error = $_.Exception.Message
        }
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
        
        Write-Log "Using script sources for $($OSInfo.ScriptSource):" "INFO"
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
        [switch]$Interactive
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
            $SystemDriveInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $SystemDrive }
            if ($SystemDriveInfo) {
                $FreeSpaceGB = [math]::Round($SystemDriveInfo.FreeSpace / 1GB, 2)
                Write-Log "System drive free space: $FreeSpaceGB GB" "INFO"
                
                # Check for VDA installation minimum requirement (2GB)
                if ($FreeSpaceGB -lt 2) {
                    $Results.Issues += "Insufficient disk space for VDA installation: $FreeSpaceGB GB (minimum 2GB required)"
                    $Results.DriveValidationPassed = $false
                    Write-Log "ERROR: Insufficient disk space for VDA installation - $FreeSpaceGB GB available, 2GB minimum required" "ERROR"
                } elseif ($FreeSpaceGB -lt 10) {
                    $Results.Warnings += "System drive has low free space: $FreeSpaceGB GB (recommended 10GB+)"
                    Write-Log "Warning: System drive has low free space for optimal performance" "WARN"
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
        $DDriveInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
        Write-Host "DEBUG: D: drive query result: $($null -ne $DDriveInfo)" -ForegroundColor Magenta
        
        if ($DDriveInfo) {
            $Results.DDriveExists = $true
            Write-Log "D: drive detected - analyzing drive type..." "INFO"
            Write-Host "DEBUG: D: drive found - Type: $($DDriveInfo.DriveType)" -ForegroundColor Magenta
            
            # Check if D: is a CD/DVD ROM drive (DriveType 5)
            if ($DDriveInfo.DriveType -eq 5) {
                # Get target drive letter from config
                $CDDVMTargetDrive = Get-ConfigValue -Key "CDDVMTargetDrive" -DefaultValue "Y" -ConfigFile $ConfigFilePath
                
                Write-Log "D: drive is a CD/DVD ROM drive - needs to be moved to ${CDDVMTargetDrive}" "WARN"
                $Results.Issues += "CD/DVD ROM drive is using D: letter - must be changed to ${CDDVMTargetDrive}"
                $Results.DriveValidationPassed = $false
                
                Write-Host "Attention: CD/DVD ROM drive detected on D:" -ForegroundColor Yellow
                # Attempt to change CD/DVD ROM drive letter to configured target
                Write-Log "Attempting to change CD/DVD ROM drive letter from D: to ${CDDVMTargetDrive}..." "INFO"
                try {
                    # Use diskpart for reliable drive letter change across all PowerShell versions
                    Write-Log "Using diskpart to change CD/DVD ROM drive letter..." "INFO"
                    
                    # Create diskpart script
                    $DiskpartScript = @"
list volume
select volume D:
assign letter=${CDDVMTargetDrive}
"@
                    
                    $ScriptPath = "$env:TEMP\change_cddvd_drive.txt"
                    $DiskpartScript | Out-File -FilePath $ScriptPath -Encoding ASCII
                    
                    # Execute diskpart
                    $null = diskpart /s $ScriptPath 2>&1
                    
                    # Clean up script file
                    if (Test-Path $ScriptPath) {
                        Remove-Item $ScriptPath -Force -ErrorAction SilentlyContinue
                    }
                    
                    # Check if target drive is available first
                    $TargetDriveExists = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "${CDDVMTargetDrive}:" }
                    
                    if (-not $TargetDriveExists) {
                        Write-Log "Successfully changed CD/DVD ROM drive letter from D: to ${CDDVMTargetDrive}" "SUCCESS"
                        
                        # Recheck D: drive after change
                        Start-Sleep -Seconds 3
                        $DDriveInfoAfter = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
                        
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
                            Write-Host "The CD/DVD ROM drive has been moved from D: to ${CDDVMTargetDrive}" -ForegroundColor Green
                            Write-Host "You must now attach a physical D: cache drive to this machine." -ForegroundColor Yellow
                            Write-Host "This drive is required for optimal Citrix VDI performance." -ForegroundColor Yellow
                            Write-Host "`nPress Enter after attaching the D: cache drive..." -ForegroundColor Cyan
                            Read-Host "Press Enter to continue"
                            
                            # Recheck for D: drive after user confirmation
                            Write-Log "Rechecking for D: cache drive after user attachment..." "INFO"
                            $DDriveFinal = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
                            
                            if ($DDriveFinal -and $DDriveFinal.DriveType -eq 3) {
                                Write-Log "D: cache drive successfully detected and validated" "SUCCESS"
                                $Results.DDriveExists = $true
                                $Results.DDriveAccessible = $true
                                $Results.DriveValidationPassed = $true
                            } else {
                                Write-Log "D: cache drive not detected - installation may proceed with warnings" "WARN"
                                $Results.Warnings += "D: cache drive not attached - may impact VDI performance"
                            }
                        } else {
                            Write-Log "D: drive still detected after diskpart operation - may need manual intervention" "WARN"
                            $Results.Warnings += "CD/DVD ROM drive letter change may have failed"
                        }
                    } else {
                        Write-Log "${CDDVMTargetDrive} drive already exists - cannot move CD/DVD ROM drive" "ERROR"
                        $Results.Issues += "${CDDVMTargetDrive} drive already in use - cannot relocate CD/DVD ROM drive"
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
                    Write-Log "D cache drive - Total: $DTotalSpaceGB GB, Free: $DFreeSpaceGB GB" "INFO"
                    
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
           $CDDrives = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 5 }
           
           if ($CDDrives.Count -gt 0) {
               Write-Log "Found $($CDDrives.Count) CD/DVD ROM drive(s) on other letters" "INFO"
               foreach ($CDDrive in $CDDrives) {
                   Write-Log "  CD/DVD ROM drive: $($CDDrive.DeviceID)" "INFO"
               }
           }
           
           # Check if virtual cache drive was already created in Stage 1
           Write-Host "DEBUG: Checking if D: drive exists after potential virtual creation..." -ForegroundColor Magenta
           $DDriveExistsNow = Test-Path "D:\"
           Write-Host "DEBUG: D: drive exists check result: $DDriveExistsNow" -ForegroundColor Magenta
           
           if ($DDriveExistsNow) {
               Write-Host "D: drive found - skipping virtual cache drive creation (already exists)" -ForegroundColor Green
               Write-Log "D: drive detected - virtual cache drive creation successful or D: drive manually attached" "SUCCESS"
               $Results.DDriveExists = $true
               $Results.DDriveAccessible = $true
               $Results.DriveValidationPassed = $true
               return $Results
           }
           
           # Check if virtual cache drive is configured
           $UseVirtualCache = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "false")
           
           if ($UseVirtualCache) {
               Write-Host "Virtual cache drive configured but D: not found - attempting creation..." -ForegroundColor Cyan
               Write-Log "Virtual cache drive mode detected - creating VHDX cache drive..." "INFO"
               
               $VirtualCacheResult = New-VirtualCacheDrive
               
               if ($VirtualCacheResult.Success) {
                   Write-Host "Virtual cache drive created successfully!" -ForegroundColor Green
                   Write-Log "Virtual cache drive created: D: ($($VirtualCacheResult.DriveInfo.SizeMB) MB)" "SUCCESS"
                   $Results.DDriveExists = $true
                   $Results.DDriveAccessible = $true
                   $Results.DriveValidationPassed = $true
                   return $Results
               } else {
                   Write-Host "Virtual cache drive creation failed - falling back to physical drive prompt" -ForegroundColor Yellow
                   foreach ($Error in $VirtualCacheResult.Errors) {
                       Write-Log "Virtual cache error: $Error" "ERROR"
                   }
               }
           } else {
               Write-Host "DEBUG: Virtual cache drive is disabled in configuration" -ForegroundColor Yellow
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
           $DDriveFinal = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
           
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
       $AllDrives = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
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
   $DDrive = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
   
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
       # Ensure we have a valid log path - fallback to desktop if needed
       if ([string]::IsNullOrEmpty($LogPath) -or $LogPath -eq (Get-DesktopPath)) {
           $LogPath = Get-DesktopLogPath
       }
       
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
       
       # Write initial log entry directly to ensure file creation
       $InitMessage = "=== Citrix Installation Logging Started at $(Get-Date) ==="
       $InitMessage | Out-File -FilePath $LogPath -Append -Force
       
       # Verify the log file exists and is writable
       if (Test-Path $LogPath) {
           Write-Host "Logging successfully initialized to: $LogPath" -ForegroundColor Green
       }
       else {
           Write-Host "WARNING: Log file was not created at: $LogPath" -ForegroundColor Red
       }
       
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
       $ComputerSystem = Get-WmiOrCimInstance -ClassName Win32_ComputerSystem
       $OperatingSystem = Get-WmiOrCimInstance -ClassName Win32_OperatingSystem
       $Processor = Get-WmiOrCimInstance -ClassName Win32_Processor | Select-Object -First 1
       
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
       Write-Log "Configuring Windows services..."
       
       $ServiceConfigs = @(
           @{ Name = "Spooler"; StartupType = "Manual" },
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
           Write-Log "Citrix Optimizer not found - skipping VDI optimizations as requested" "WARN"
           $Results.Success = $false
           $Results.Error = "Citrix Optimizer not available"
           return $Results
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
           Write-Log "Skipping VDI optimizations - template not available" "WARN"
           $Results.Success = $false
           $Results.Error = "Template not found: $TemplatePath"
           return $Results
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
           Write-Log "VDI optimizations skipped due to Citrix Optimizer failure" "ERROR"
           $Results.Success = $false
           $Results.Error = "Citrix Optimizer failed with exit code: $ExitCode"
       }
       
       return $Results
   }
   catch {
       Write-Log "Exception during Citrix Optimizer execution: $($_.Exception.Message)" "ERROR"
       Write-Log "VDI optimizations skipped due to exception" "ERROR"
       $Results.Success = $false
       $Results.Error = $_.Exception.Message
       return $Results
   }
}

# Critical missing functions identified in analysis - adding compatibility and missing core functions

function Get-WmiOrCimInstance {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$ClassName,
       
       [Parameter(Mandatory=$false)]
       [string]$Filter = "",
       
       [Parameter(Mandatory=$false)]
       [string]$Property = ""
   )
   
   try {
       # Try CIM first (newer, preferred)
       if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
           if ($Filter) {
               return Get-CimInstance -ClassName $ClassName -Filter $Filter
           } else {
               return Get-CimInstance -ClassName $ClassName
           }
       }
   }
   catch {
       # Fall back to WMI
   }
   
   # Use WMI as fallback
   if ($Filter) {
       return Get-WmiObject -ClassName $ClassName -Filter $Filter
   } else {
       return Get-WmiObject -ClassName $ClassName
   }
}

function Test-SafePath {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [AllowEmptyString()]
       [string]$Path,
       
       [Parameter(Mandatory=$false)]
       [switch]$CreateIfMissing
   )
   
   try {
       # Handle null or empty
       if ([string]::IsNullOrWhiteSpace($Path)) {
           return $false
       }
       
       # Sanitize path
       $CleanPath = $Path.Trim()
       
       # Handle UNC paths
       if ($CleanPath.StartsWith("\\")) {
           # Validate UNC path format
           if ($CleanPath -match '^\\\\[^\\]+\\[^\\]+') {
               # Test UNC path accessibility
               try {
                   $null = Get-Item -Path $CleanPath -ErrorAction Stop
                   return $true
               }
               catch {
                   return $false
               }
           }
           return $false
       }
       
       # Handle local paths
       $CleanPath = $CleanPath.Replace('\\\\', '\')
       
       # Test path
       if (Test-Path -Path $CleanPath) {
           return $true
       }
       elseif ($CreateIfMissing) {
           try {
               New-Item -Path $CleanPath -ItemType Directory -Force | Out-Null
               return $true
           }
           catch {
               return $false
           }
       }
       
       return $false
   }
   catch {
       return $false
   }
}

function Initialize-LoggingSystem {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$LogPath
   )
   
   try {
       # Ensure log directory exists
       $LogDir = Split-Path $LogPath -Parent
       if (-not (Test-Path $LogDir)) {
           New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
       }
       
       # Initialize global log path
       $Global:LogPath = $LogPath
       
       # Write initial entry
       $InitMessage = "=== Logging System Initialized at $(Get-Date) ==="
       $InitMessage | Out-File -FilePath $LogPath -Force
       
       Write-Host "Logging initialized: $LogPath" -ForegroundColor Green
       return $true
   }
   catch {
       Write-Host "Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
       return $false
   }
}



function Set-PageFile {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [int]$SizeGB = 8,
       
       [Parameter(Mandatory=$false)]
       [string]$DriveLetter = "C"
   )
   
   try {
       Write-Log "Configuring pagefile on ${DriveLetter} drive with ${SizeGB}GB..." "INFO"
       
       # Disable automatic pagefile management
       # Use registry method directly to avoid WMI compatibility issues
       try {
           Write-Log "Disabling automatic pagefile management via registry" "INFO"
           Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value ""
       } catch {
           Write-Log "Registry pagefile management failed: $($_.Exception.Message)" "WARN"
       }
       
       # Remove existing pagefiles using registry method
       try {
           Write-Log "Clearing existing pagefile settings via registry" "INFO"
           Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value @()
       } catch {
           Write-Log "Failed to clear existing pagefiles: $($_.Exception.Message)" "WARN"
       }
       
       # Create new pagefile
       $PageFileSizeMB = $SizeGB * 1024
       try {
           $PagefileEntry = "${DriveLetter}:\pagefile.sys $PageFileSizeMB $PageFileSizeMB"
           Write-Log "Setting pagefile via registry: $PagefileEntry" "INFO"
           Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value $PagefileEntry
       } catch {
           Write-Log "Registry pagefile creation failed: $($_.Exception.Message)" "ERROR"
           throw "Unable to create pagefile using registry method"
       }
       
       Write-Log "Pagefile configured successfully: ${DriveLetter}\pagefile.sys (${SizeGB}GB)" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to configure pagefile: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Clear-EventLogs {
   [CmdletBinding()]
   param()
   
   try {
       Write-Log "Clearing Windows event logs..." "INFO"
       
       $Logs = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 }
       $ClearedCount = 0
       
       foreach ($Log in $Logs) {
           try {
               [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($Log.LogName)
               $ClearedCount++
           }
           catch {
               # Some logs cannot be cleared, skip silently
           }
       }
       
       Write-Log "Cleared $ClearedCount event logs" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to clear event logs: $($_.Exception.Message)" "ERROR"
       return $false
   }
}



function Disable-WindowsUpdates {
   [CmdletBinding()]
   param()
   
   try {
       Write-Log "Disabling Windows Updates..." "INFO"
       
       # Registry settings to disable Windows Updates
       $UpdateKeys = @(
           @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Value = 1 },
           @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions"; Value = 1 },
           @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"; Name = "AUOptions"; Value = 1 }
       )
       
       foreach ($Key in $UpdateKeys) {
           if (-not (Test-Path $Key.Path)) {
               New-Item -Path $Key.Path -Force | Out-Null
           }
           Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -Force
       }
       
       # Stop and disable Windows Update service
       Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
       Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
       
       Write-Log "Windows Updates disabled successfully" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to disable Windows Updates: $($_.Exception.Message)" "ERROR"
       return $false
   }
}



function Set-TimeZone {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$TimeZoneId = "Eastern Standard Time"
   )
   
   try {
       Write-Log "Setting timezone to: $TimeZoneId" "INFO"
       
       if (Get-Command Set-TimeZone -ErrorAction SilentlyContinue) {
           Set-TimeZone -Id $TimeZoneId
       } else {
           # Fallback for older systems
           tzutil /s $TimeZoneId
       }
       
       Write-Log "Timezone set successfully" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to set timezone: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Join-Domain {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$DomainName,
       
       [Parameter(Mandatory=$true)]
       [PSCredential]$Credential,
       
       [Parameter(Mandatory=$false)]
       [string]$OUPath = ""
   )
   
   try {
       Write-Log "Joining domain: $DomainName" "INFO"
       
       $JoinParams = @{
           DomainName = $DomainName
           Credential = $Credential
           Force = $true
       }
       
       if (![string]::IsNullOrEmpty($OUPath)) {
           $JoinParams.OUPath = $OUPath
       }
       
       Add-Computer @JoinParams
       
       Write-Log "Successfully joined domain: $DomainName" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to join domain: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Set-LocalUserPassword {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Username,
       
       [Parameter(Mandatory=$true)]
       [SecureString]$UserPassword
   )
   
   try {
       Write-Log "Setting password for local user: $Username" "INFO"
       
       $User = Get-LocalUser -Name $Username -ErrorAction Stop
       $User | Set-LocalUser -Password $UserPassword
       
       Write-Log "Password set successfully for user: $Username" "SUCCESS"
       return $true
   }
   catch {
       Write-Log "Failed to set password for user $Username : $($_.Exception.Message)" "ERROR"
       return $false
   }
}



function Set-RegistryValue {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Path,
       
       [Parameter(Mandatory=$true)]
       [string]$Name,
       
       [Parameter(Mandatory=$true)]
       $Value,
       
       [Parameter(Mandatory=$false)]
       [string]$Type = "String"
   )
   
   try {
       if (-not (Test-Path $Path)) {
           New-Item -Path $Path -Force | Out-Null
       }
       
       Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
       return $true
   }
   catch {
       Write-Log "Failed to set registry value ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Get-RegistryValue {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Path,
       
       [Parameter(Mandatory=$true)]
       [string]$Name,
       
       [Parameter(Mandatory=$false)]
       $DefaultValue = $null
   )
   
   try {
       if (Test-Path $Path) {
           $Value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
           return $Value.$Name
       }
       return $DefaultValue
   }
   catch {
       return $DefaultValue
   }
}

function Test-RegistryPath {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Path
   )
   
   return Test-Path $Path
}

function New-RegistryPath {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Path
   )
   
   try {
       if (-not (Test-Path $Path)) {
           New-Item -Path $Path -Force | Out-Null
           return $true
       }
       return $true
   }
   catch {
       Write-Log "Failed to create registry path ${Path}: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Remove-RegistryValue {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$Path,
       
       [Parameter(Mandatory=$true)]
       [string]$Name
   )
   
   try {
       if (Test-Path $Path) {
           Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
           return $true
       }
       return $true
   }
   catch {
       Write-Log "Failed to remove registry value ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
       return $false
   }
}

function Install-CitrixVDA {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting Citrix VDA installation..." "INFO"
       
       $VDAInstallerPath = Get-ConfigValue -Key "VDAInstallerPath" -DefaultValue "C:\Temp\VDA.iso" -ConfigFile $ConfigFilePath
       
       if (Test-Path $VDAInstallerPath) {
           $Result = Install-VDAFromISO -ConfigFilePath $ConfigFilePath
           return $Result
       } else {
           Write-Log "VDA installer not found: $VDAInstallerPath" "ERROR"
           return @{
               Success = $false
               Error = "VDA installer not found"
           }
       }
   }
   catch {
       Write-Log "VDA installation failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Install-CitrixPVSTarget {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting Citrix PVS Target installation..." "INFO"
       
       $PVSInstallerPath = Get-ConfigValue -Key "PVSInstallerPath" -DefaultValue "C:\Temp\PVS.iso" -ConfigFile $ConfigFilePath
       
       if (Test-Path $PVSInstallerPath) {
           $Result = Install-PVSFromISO -ConfigFilePath $ConfigFilePath
           return $Result
       } else {
           Write-Log "PVS installer not found: $PVSInstallerPath" "ERROR"
           return @{
               Success = $false
               Error = "PVS installer not found"
           }
       }
   }
   catch {
       Write-Log "PVS Target installation failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Install-CitrixWEMAgent {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting Citrix WEM Agent installation..." "INFO"
       
       $WEMSourcePath = Get-ConfigValue -Key "WEMAgentSource" -DefaultValue "" -ConfigFile $ConfigFilePath
       $WEMLocalPath = Get-ConfigValue -Key "WEMAgentLocal" -DefaultValue "C:\Temp\WEMAgent.msi" -ConfigFile $ConfigFilePath
       
       if (![string]::IsNullOrEmpty($WEMSourcePath)) {
           $Result = Add-WEMAgent -WEMSourcePath $WEMSourcePath -WEMPath $WEMLocalPath -ConfigFilePath $ConfigFilePath
           return $Result
       } else {
           Write-Log "WEM Agent installation skipped - no source configured" "INFO"
           return @{
               Success = $true
               Skipped = $true
           }
       }
   }
   catch {
       Write-Log "WEM Agent installation failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Install-IBMTADDMAgent {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting IBM TADDM Agent installation..." "INFO"
       
       $EnableIBMTADDM = [bool](Get-ConfigValue -Key "EnableIBMTADDMInstallation" -DefaultValue "false" -ConfigFile $ConfigFilePath)
       
       if ($EnableIBMTADDM) {
           $TADDMPath = Get-ConfigValue -Key "IBMTADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
           
           if (Test-Path $TADDMPath) {
               Write-Log "Executing IBM TADDM installation from: $TADDMPath" "INFO"
               $Process = Start-Process -FilePath $TADDMPath -Wait -PassThru
               
               if ($Process.ExitCode -eq 0) {
                   Write-Log "IBM TADDM installation completed successfully" "SUCCESS"
                   return @{ Success = $true }
               } else {
                   Write-Log "IBM TADDM installation failed with exit code: $($Process.ExitCode)" "ERROR"
                   return @{ Success = $false; Error = "Exit code: $($Process.ExitCode)" }
               }
           } else {
               Write-Log "IBM TADDM installer not found: $TADDMPath" "WARN"
               return @{ Success = $true; Skipped = $true }
           }
       } else {
           Write-Log "IBM TADDM installation skipped - disabled in configuration" "INFO"
           return @{ Success = $true; Skipped = $true }
       }
   }
   catch {
       Write-Log "IBM TADDM installation failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Set-IBMTADDMSCMPermissions {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Configuring IBM TADDM SCM permissions..." "INFO"
       
       $EnableSCMConfig = [bool](Get-ConfigValue -Key "EnableIBMTADDMSCMConfig" -DefaultValue "false" -ConfigFile $ConfigFilePath)
       
       if ($EnableSCMConfig) {
           $SCMPath = Get-ConfigValue -Key "IBMTADDMSCMPath" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager" -ConfigFile $ConfigFilePath
           $CurrentSDDLBat = Get-ConfigValue -Key "IBMTADDMCurrentSDDLBat" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager\currentsddl.bat" -ConfigFile $ConfigFilePath
           $SCMConfigBat = Get-ConfigValue -Key "IBMTADDMSCMConfigBat" -DefaultValue "C:\IBM\TADDM\sc_sdset_scmanager\sc_sdset_scmanager.bat" -ConfigFile $ConfigFilePath
           
           $Result = Set-IBMTADDMSCMPermissions -SCMPath $SCMPath -CurrentSDDLBat $CurrentSDDLBat -SCMConfigBat $SCMConfigBat
           return $Result
       } else {
           Write-Log "IBM TADDM SCM configuration skipped - disabled in configuration" "INFO"
           return @{ Success = $true; Skipped = $true }
       }
   }
   catch {
       Write-Log "IBM TADDM SCM permissions configuration failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Install-CitrixOptimizer {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Installing Citrix Optimizer..." "INFO"
       
       # This function would handle downloading/installing Citrix Optimizer itself
       # For now, just validate if it's available
       $OptimizerPath = Get-ConfigValue -Key "CitrixOptimizerPath" -DefaultValue "" -ConfigFile $ConfigFilePath
       
       if (![string]::IsNullOrEmpty($OptimizerPath) -and (Test-Path $OptimizerPath)) {
           Write-Log "Citrix Optimizer found at: $OptimizerPath" "SUCCESS"
           return @{ Success = $true }
       } else {
           Write-Log "Citrix Optimizer not found or not configured" "WARN"
           return @{ Success = $false; Error = "Citrix Optimizer not available" }
       }
   }
   catch {
       Write-Log "Citrix Optimizer installation check failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function Optimize-CitrixVDI {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting Citrix VDI optimization..." "INFO"
       
       # Call the main Citrix Optimizer function
       $Result = Start-CitrixOptimizer -ConfigFilePath $ConfigFilePath
       return $Result
   }
   catch {
       Write-Log "Citrix VDI optimization failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

function New-VirtualCacheDrive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$DriveLetter = $null,
        
        [Parameter(Mandatory=$false)]
        [int]$SizeMB = -1,
        
        [Parameter(Mandatory=$false)]
        [string]$VolumeLabel = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$VHDXPath = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Creating virtual cache drive..." "INFO"
        
        # Read ALL values from config file first
        if ([string]::IsNullOrEmpty($ConfigFilePath) -or $ConfigFilePath -eq ".\CitrixConfig.txt") {
            # Try to find the config file in script root if relative path
            $ScriptRoot = $PSScriptRoot
            if ([string]::IsNullOrEmpty($ScriptRoot)) {
                $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
            }
            $ConfigFilePath = Join-Path $ScriptRoot "CitrixConfig.txt"
        }
        
        # Read configuration values - use config file values unless explicitly passed as parameters
        if ([string]::IsNullOrEmpty($DriveLetter)) {
            $DriveLetter = Get-ConfigValue -Key "VirtualCacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
        }
        
        if ($SizeMB -eq -1) {
            $SizeMB = [int](Get-ConfigValue -Key "VirtualCacheDriveSizeMB" -DefaultValue "500" -ConfigFile $ConfigFilePath)
        }
        
        if ([string]::IsNullOrEmpty($VolumeLabel)) {
            $VolumeLabel = Get-ConfigValue -Key "VirtualCacheDriveLabel" -DefaultValue "Cache" -ConfigFile $ConfigFilePath
        }
        
        if ([string]::IsNullOrEmpty($VHDXPath)) {
            $VHDXPath = Get-ConfigValue -Key "VirtualCacheDrivePath" -DefaultValue "C:\Temp\CACHE.VHDX" -ConfigFile $ConfigFilePath
        }
        
        $Results = @{
            Success = $false
            DriveAssigned = $false
            VHDXPath = ""
            DriveLetter = ""
            SizeMB = 0
            Method = "VHDX Virtual Drive"
            DriveInfo = $null
            Errors = @()
        }
        
        # Use the values read from config
        $CacheDriveSizeMB = $SizeMB
        $CacheVHDXPath = $VHDXPath
        
        Write-Log "Virtual cache drive configuration:" "INFO"
        Write-Log "  Drive Letter: $DriveLetter" "INFO"
        Write-Log "  Size: $CacheDriveSizeMB MB" "INFO"
        Write-Log "  Volume Label: $VolumeLabel" "INFO"
        Write-Log "  VHDX Path: $CacheVHDXPath" "INFO"
        
        # Check if drive letter is already in use
        if (Test-Path "${DriveLetter}:\") {
            Write-Log "Drive ${DriveLetter}: already exists - checking if it's our virtual drive" "WARN"
            
            # Check if it's already our VHDX
            if (Test-Path $CacheVHDXPath) {
                Write-Log "Virtual cache drive already exists at $CacheVHDXPath" "INFO"
                $Results.Success = $true
                $Results.DriveAssigned = $true
                $Results.VHDXPath = $CacheVHDXPath
                $Results.DriveLetter = $DriveLetter
                $Results.SizeMB = $CacheDriveSizeMB
                return $Results
            } else {
                $Results.Errors += "Drive ${DriveLetter}: is already in use by another device"
                Write-Log "Drive ${DriveLetter}: is already in use - cannot create virtual cache drive" "ERROR"
                return $Results
            }
        }
        
        # Create VHDX file using diskpart
        Write-Log "Creating VHDX file: $CacheVHDXPath (${CacheDriveSizeMB}MB)" "INFO"
        
        try {
            # Ensure the directory exists for the VHDX file
            $VHDXDir = Split-Path -Path $CacheVHDXPath -Parent
            if (-not (Test-Path $VHDXDir)) {
                New-Item -Path $VHDXDir -ItemType Directory -Force | Out-Null
                Write-Log "Created directory for VHDX: $VHDXDir" "INFO"
            }
            
            # Ensure we have a full path (diskpart requires full paths)
            if (-not [System.IO.Path]::IsPathRooted($CacheVHDXPath)) {
                $CacheVHDXPath = [System.IO.Path]::GetFullPath($CacheVHDXPath)
            }
            
            # Validate the path doesn't contain invalid characters
            $InvalidChars = [System.IO.Path]::GetInvalidPathChars()
            foreach ($char in $InvalidChars) {
                if ($CacheVHDXPath.Contains($char)) {
                    throw "Path contains invalid character: '$char'"
                }
            }
            
            # Create diskpart script
            $DiskpartScript = @"
create vdisk file="$CacheVHDXPath" maximum=$CacheDriveSizeMB type=expandable
select vdisk file="$CacheVHDXPath"
attach vdisk
create partition primary
active
format fs=ntfs label="$VolumeLabel" quick
assign letter=$DriveLetter
exit
"@
            
            Write-Log "Executing diskpart to create virtual cache drive..." "INFO"
            $ScriptFile = [System.IO.Path]::Combine($env:TEMP, "create_vhdx_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt")
            
            # Write script with ASCII encoding to avoid issues
            [System.IO.File]::WriteAllText($ScriptFile, $DiskpartScript, [System.Text.Encoding]::ASCII)
            
            # Execute diskpart with better error capture
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "diskpart.exe"
            $ProcessInfo.Arguments = "/s `"$ScriptFile`""
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.CreateNoWindow = $true
            
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            
            $Process.Start() | Out-Null
            
         
            $Process.WaitForExit()
            
            $ExitCode = $Process.ExitCode
            
            # Clean up script file
            Remove-Item $ScriptFile -Force -ErrorAction SilentlyContinue
            
            if ($ExitCode -eq 0) {
                Write-Log "VHDX created successfully using diskpart" "SUCCESS"
            } else {
                # Provide more detailed error information based on exit code
                $ErrorMessage = switch ($ExitCode) {
                    -2147024809 { "Invalid parameter - check path and drive letter" }
                    5 { "Access denied - requires administrator privileges" }
                    32 { "File in use - VHDX file may be locked" }
                    default { "Unknown error" }
                }
                throw "Diskpart failed with exit code $ExitCode (0x$([Convert]::ToString($ExitCode, 16))): $ErrorMessage"
            }
            
        } catch {
            $Results.Errors += "Failed to create VHDX: $($_.Exception.Message)"
            Write-Log "Failed to create VHDX file: $($_.Exception.Message)" "ERROR"
            return $Results
        }
        
        # Verify the drive is accessible after diskpart creation
        Start-Sleep -Seconds 3
        if (Test-Path "${DriveLetter}:\") {
            try {
                $DriveInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "${DriveLetter}:" }
                
                $Results.Success = $true
                $Results.DriveAssigned = $true
                $Results.VHDXPath = $CacheVHDXPath
                $Results.DriveLetter = $DriveLetter
                $Results.SizeMB = [math]::Round($DriveInfo.Size / 1MB, 0)
                $Results.DriveInfo = @{
                    SizeMB = [math]::Round($DriveInfo.Size / 1MB, 0)
                    FreeSpaceMB = [math]::Round($DriveInfo.FreeSpace / 1MB, 0)
                    FileSystem = $DriveInfo.FileSystem
                    VolumeLabel = $DriveInfo.VolumeName
                }
                
                Write-Log "Virtual cache drive created successfully: ${DriveLetter}: ($($Results.SizeMB)MB)" "SUCCESS"
            } catch {
                # Fallback to basic validation
                $Results.Success = $true
                $Results.DriveAssigned = $true
                $Results.VHDXPath = $CacheVHDXPath
                $Results.DriveLetter = $DriveLetter
                $Results.SizeMB = $CacheDriveSizeMB
                Write-Log "Virtual cache drive created successfully: ${DriveLetter}: (basic validation)" "SUCCESS"
            }
        } else {
            $Results.Errors += "Virtual drive created but not accessible"
            Write-Log "Virtual drive created but not accessible at ${DriveLetter}:" "ERROR"
        }
        
        return $Results
    }
    catch {
        Write-Log "Virtual cache drive creation failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            DriveAssigned = $false
            VHDXPath = ""
            DriveLetter = ""
            SizeMB = 0
            Method = "VHDX Virtual Drive"
            DriveInfo = $null
            Errors = @("Critical error: $($_.Exception.Message)")
        }
    }
}




function Test-VirtualCacheDrive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$DriveLetter = "D"
    )
    
    try {
        # Check if drive exists
        if (-not (Test-Path "${DriveLetter}:\")) {
            return $false
        }
        
        # Check if it's a virtual drive by looking for VHDX file
        $VHDXPath = "C:\Temp\DCACHE.VHDX"
        if (Test-Path $VHDXPath) {
            Write-Log "Virtual cache drive detected: $VHDXPath" "INFO"
            return $true
        }
        
        return $false
    }
    catch {
        return $false
    }
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "Operation"
    )
    
    $Attempt = 0
    $LastError = $null
    
    while ($Attempt -lt $MaxAttempts) {
        $Attempt++
        try {
            Write-Log "Attempting $OperationName (attempt $Attempt of $MaxAttempts)..." "INFO"
            return & $ScriptBlock
        }
        catch {
            $LastError = $_
            if ($Attempt -lt $MaxAttempts) {
                Write-Log "$OperationName attempt $Attempt failed, retrying in $DelaySeconds seconds..." "WARN"
                Start-Sleep -Seconds $DelaySeconds
            } else {
                Write-Log "$OperationName failed after $MaxAttempts attempts" "ERROR"
            }
        }
    }
    
    throw $LastError
}

function Test-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    $ValidationResults = @{
        Valid = $true
        Issues = @()
        Warnings = @()
        ConfigPath = $ConfigFilePath
    }
    
    try {
        # Check if config file exists
        if (-not (Test-Path $ConfigFilePath)) {
            $ValidationResults.Valid = $false
            $ValidationResults.Issues += "Configuration file not found: $ConfigFilePath"
            return $ValidationResults
        }
        
        # Check required keys
        $RequiredKeys = @(
            "NetworkSourcePath",
            "VDAISOSourcePath",
            "PVSISOSourcePath"
        )
        
        foreach ($Key in $RequiredKeys) {
            $Value = Get-ConfigValue -Key $Key -ConfigFile $ConfigFilePath
            if ([string]::IsNullOrWhiteSpace($Value)) {
                $ValidationResults.Valid = $false
                $ValidationResults.Issues += "Missing required configuration: $Key"
            }
        }
        
        # Validate critical paths if they exist
        $PathKeys = @(
            "NetworkSourcePath",
            "VDAISOSourcePath", 
            "PVSISOSourcePath",
            "WEMAgentSource",
            "UberAgentSource"
        )
        
        foreach ($Key in $PathKeys) {
            $Path = Get-ConfigValue -Key $Key -ConfigFile $ConfigFilePath
            if (![string]::IsNullOrWhiteSpace($Path) -and !(Test-SafePath -Path $Path)) {
                $ValidationResults.Warnings += "Path not accessible: $Key = $Path"
            }
        }
        
        Write-Log "Configuration validation completed: $($ValidationResults.Issues.Count) issues, $($ValidationResults.Warnings.Count) warnings" "INFO"
        return $ValidationResults
    }
    catch {
        $ValidationResults.Valid = $false
        $ValidationResults.Issues += "Configuration validation failed: $($_.Exception.Message)"
        return $ValidationResults
    }
}

function Write-ProgressHelper {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [int]$Id = 1
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -Id $Id
    Write-Log "$Activity - $Status ($PercentComplete%)" "INFO"
}



function Test-ValidInput {
    [CmdletBinding()]
    param(
        [string]$UserInput,
        [string]$Pattern,
        [string[]]$AllowedValues
    )
    
    if ($AllowedValues) {
        return $UserInput -in $AllowedValues
    }
    
    if ($Pattern) {
        return $UserInput -match $Pattern
    }
    
    return $true
}



# Fallback optimization function removed per user request - all VDI optimizations handled exclusively by Citrix Optimizer

function Stop-CitrixServices {
    [CmdletBinding()]
    param(
        [string]$ConfigFilePath = ".\CitrixConfig.txt",
        [string]$ServiceOverride = ""
    )
    
    try {
        Write-Log "Disabling unnecessary Citrix services..."
        
        # Load configurable service list from config file or use override
        if ($ServiceOverride -ne "") {
            $ServicesToDisableConfig = $ServiceOverride
        } else {
            $ServicesToDisableConfig = Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "wuauserv" -ConfigFile $ConfigFilePath
        }
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
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = "CitrixConfig.txt"
    )
    
    try {
        Write-Log "Applying registry optimizations..."
        
        # Base registry optimizations
        $RegOptimizations = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0 }
        )
        
        # Add VDA Multiple Monitor Hook optimizations if enabled
        $EnableVDAMultiMonitorHook = [bool](Get-ConfigValue -Key "EnableVDAMultiMonitorHook" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        if ($EnableVDAMultiMonitorHook) {
            $VDALogonUIWidth = [int](Get-ConfigValue -Key "VDALogonUIWidth" -DefaultValue "800" -ConfigFile $ConfigFilePath)
            $VDALogonUIHeight = [int](Get-ConfigValue -Key "VDALogonUIHeight" -DefaultValue "600" -ConfigFile $ConfigFilePath)
            
            Write-Log "Adding VDA Multiple Monitor Hook registry optimizations" "INFO"
            Write-Log "  LogonUI Width: $VDALogonUIWidth" "INFO"
            Write-Log "  LogonUI Height: $VDALogonUIHeight" "INFO"
            
            $RegOptimizations += @(
                @{ Path = "HKLM:\Software\Wow6432node\Citrix\CtxHook\AppInit_DLLS\Multiple Monitor Hook"; Name = "LogonUIWidth"; Value = $VDALogonUIWidth; Type = "DWORD" },
                @{ Path = "HKLM:\Software\Wow6432node\Citrix\CtxHook\AppInit_DLLS\Multiple Monitor Hook"; Name = "LogonUIHeight"; Value = $VDALogonUIHeight; Type = "DWORD" }
            )
        } else {
            Write-Log "VDA Multiple Monitor Hook optimizations disabled in configuration" "INFO"
        }
        
        foreach ($Opt in $RegOptimizations) {
            try {
                # Ensure the registry path exists
                if (-not (Test-Path $Opt.Path)) {
                    New-Item -Path $Opt.Path -Force | Out-Null
                    Write-Log "Created registry path: $($Opt.Path)" "INFO"
                }
                
                # Set registry value with appropriate type
                if ($Opt.Type -eq "DWORD") {
                    Set-ItemProperty -Path $Opt.Path -Name $Opt.Name -Value $Opt.Value -Type DWord -ErrorAction Stop
                    Write-Log "Set DWORD registry value: $($Opt.Path)\$($Opt.Name) = $($Opt.Value)" "SUCCESS"
                } else {
                    Set-ItemProperty -Path $Opt.Path -Name $Opt.Name -Value $Opt.Value -ErrorAction Stop
                    Write-Log "Set registry value: $($Opt.Path)\$($Opt.Name) = $($Opt.Value)" "SUCCESS"
                }
            }
            catch {
                Write-Log "Failed to set registry value $($Opt.Path)\$($Opt.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Registry optimizations applied" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to apply registry optimizations: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# VDI optimizations removed - handled exclusively by Citrix Optimizer

function Set-PagefileConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$PagefileSizeGB = 8,
        
        [Parameter(Mandatory=$false)]
        [string]$CacheDriveLetter = ""
    )
    
    try {
        # Determine pagefile location based on cache drive parameter
        if (-not [string]::IsNullOrEmpty($CacheDriveLetter) -and (Test-Path "${CacheDriveLetter}:\")) {
            $PagefileLocation = "${CacheDriveLetter}:\pagefile.sys"
            Write-Log "Configuring pagefile on cache drive: ${CacheDriveLetter}:"
        } else {
            $PagefileLocation = "C:\pagefile.sys"
            Write-Log "Configuring pagefile on system drive: C:"
        }
        
        # Calculate pagefile size in MB
        $PagefileSizeMB = $PagefileSizeGB * 1024
        
        # Use registry method to configure pagefile
        Write-Log "Configuring pagefile using registry method..."
        
        # Set pagefile configuration in registry
        $PagefileString = "$PagefileLocation $PagefileSizeMB $PagefileSizeMB"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value $PagefileString -Type MultiString
        Write-Log "Set registry PagingFiles: $PagefileString" "INFO"
        
        # Disable automatic pagefile management in registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "AutomaticManagedPagefile" -Value 0 -Type DWord
        Write-Log "Disabled automatic pagefile management via registry" "INFO"
        
        Write-Log "Pagefile configured with ${PagefileSizeGB}GB fixed size" "SUCCESS"
        Write-Log "Pagefile location: $PagefileLocation" "SUCCESS"
        Write-Log "Initial size: ${PagefileSizeMB} MB" "SUCCESS"
        Write-Log "Maximum size: ${PagefileSizeMB} MB" "SUCCESS"
        
        return @{
            Success = $true
            Location = $PagefileLocation
            SizeGB = $PagefileSizeGB
            SizeMB = $PagefileSizeMB
        }
    }
    catch {
        Write-Log "Failed to configure pagefile: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-UserProfilesRedirection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CacheDriveLetter
    )
    
    try {
        Write-Log "Configuring user profiles redirection to ${CacheDriveLetter}: drive..."
        
        # Ensure cache drive exists
        if (-not (Test-Path "${CacheDriveLetter}:\")) {
            Write-Log "Cache drive ${CacheDriveLetter}: not found - cannot redirect user profiles" "ERROR"
            return @{
                Success = $false
                Error = "Cache drive ${CacheDriveLetter}: not accessible"
            }
        }
        
        # Create Users directory structure on cache drive
        $UserProfilesPath = "${CacheDriveLetter}:\Users"
        $DefaultProfilePath = "${CacheDriveLetter}:\Users\Default"
        $PublicProfilePath = "${CacheDriveLetter}:\Users\Public"
        
        Write-Log "Creating user profiles directory structure..."
        New-Item -Path $UserProfilesPath -ItemType Directory -Force | Out-Null
        New-Item -Path $DefaultProfilePath -ItemType Directory -Force | Out-Null
        New-Item -Path $PublicProfilePath -ItemType Directory -Force | Out-Null
        
        # Registry keys for user profiles redirection
        $ProfileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        
        Write-Log "Configuring user profiles registry settings..."
        
        # Redirect profiles directory
        Set-ItemProperty -Path $ProfileListKey -Name "ProfilesDirectory" -Value $UserProfilesPath -Type ExpandString
        Write-Log "Set ProfilesDirectory to: $UserProfilesPath" "INFO"
        
        # Redirect default user profile
        Set-ItemProperty -Path $ProfileListKey -Name "DefaultUserProfile" -Value "Default" -Type String
        Write-Log "Set DefaultUserProfile to: Default" "INFO"
        
        # Redirect public profile
        Set-ItemProperty -Path $ProfileListKey -Name "PublicProfile" -Value "Public" -Type String
        Write-Log "Set PublicProfile to: Public" "INFO"
        
        # Configure shell folders redirection for new users
        $ShellFoldersKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        $UserShellFoldersKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        
        Write-Log "Configuring shell folders redirection..."
        
        # Common Documents
        Set-ItemProperty -Path $ShellFoldersKey -Name "Common Documents" -Value "${CacheDriveLetter}:\Users\Public\Documents" -Type String
        Set-ItemProperty -Path $UserShellFoldersKey -Name "Common Documents" -Value "${CacheDriveLetter}:\Users\Public\Documents" -Type ExpandString
        
        # Common Desktop
        Set-ItemProperty -Path $ShellFoldersKey -Name "Common Desktop" -Value "${CacheDriveLetter}:\Users\Public\Desktop" -Type String
        Set-ItemProperty -Path $UserShellFoldersKey -Name "Common Desktop" -Value "${CacheDriveLetter}:\Users\Public\Desktop" -Type ExpandString
        
        # Default user folders template
        $DefaultFolders = @(
            "Desktop",
            "Documents", 
            "Downloads",
            "Music",
            "Pictures",
            "Videos"
        )
        
        foreach ($Folder in $DefaultFolders) {
            $FolderPath = "${CacheDriveLetter}:\Users\Default\$Folder"
            New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
            Write-Log "Created default folder: $FolderPath" "INFO"
        }
        
        # Set appropriate permissions on Users directory
        Write-Log "Setting permissions on user profiles directory..."
        $Acl = Get-Acl $UserProfilesPath
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($AccessRule)
        Set-Acl -Path $UserProfilesPath -AclObject $Acl
        
        Write-Log "User profiles redirection configured successfully" "SUCCESS"
        Write-Log "New user profiles will be created on: ${CacheDriveLetter}:\Users" "SUCCESS"
        Write-Log "Note: Existing user profiles remain on C: drive until manually moved" "INFO"
        Write-Log "Note: System restart required for changes to take effect" "WARN"
        
        return @{
            Success = $true
            ProfilesPath = $UserProfilesPath
            DefaultPath = $DefaultProfilePath
            PublicPath = $PublicProfilePath
            CacheDrive = $CacheDriveLetter
        }
    }
    catch {
        Write-Log "Failed to configure user profiles redirection: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Reset-RDSGracePeriod {
    <#
    .SYNOPSIS
    Resets the Remote Desktop Services grace period by removing licensing registry keys.
    
    .DESCRIPTION
    This function resets the RDS grace period by removing the licensing-related registry keys
    that track the grace period usage. This effectively resets the 120-day grace period
    for Terminal Services/Remote Desktop Services.
    
    .PARAMETER ConfigFilePath
    Path to the configuration file to read settings from.
    
    .EXAMPLE
    Reset-RDSGracePeriod -ConfigFilePath ".\CitrixConfig.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Starting RDS grace period reset..." "INFO"
        
        # Check if reset is enabled in configuration
        $ResetEnabled = Get-ConfigValue -Key "ResetRDSGracePeriod" -DefaultValue $false -ConfigFile $ConfigFilePath
        if (-not $ResetEnabled) {
            Write-Log "RDS grace period reset is disabled in configuration" "INFO"
            return @{
                Success = $true
                Action = "Skipped"
                Reason = "Disabled in configuration"
            }
        }
        
        # Registry paths for RDS licensing
        $LicensingRegPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod",
            "HKLM:\SOFTWARE\Microsoft\MSLicensing\Store\LICENSE000*",
            "HKLM:\SOFTWARE\Microsoft\MSLicensing\HardwareID",
            "HKLM:\SOFTWARE\Microsoft\MSLicensing\Store"
        )
        
        $RemovedKeys = @()
        $SkippedKeys = @()
        
        foreach ($RegPath in $LicensingRegPaths) {
            try {
                if ($RegPath -like "*LICENSE000*") {
                    # Handle wildcard pattern for LICENSE keys
                    $ParentPath = "HKLM:\SOFTWARE\Microsoft\MSLicensing\Store"
                    if (Test-Path $ParentPath) {
                        $LicenseKeys = Get-ChildItem $ParentPath -Name | Where-Object { $_ -like "LICENSE000*" }
                        foreach ($LicenseKey in $LicenseKeys) {
                            $FullPath = "$ParentPath\$LicenseKey"
                            if (Test-Path $FullPath) {
                                Remove-Item -Path $FullPath -Recurse -Force
                                $RemovedKeys += $FullPath
                                Write-Log "Removed RDS license key: $FullPath" "INFO"
                            }
                        }
                    }
                } else {
                    if (Test-Path $RegPath) {
                        Remove-Item -Path $RegPath -Recurse -Force
                        $RemovedKeys += $RegPath
                        Write-Log "Removed RDS registry key: $RegPath" "INFO"
                    } else {
                        $SkippedKeys += $RegPath
                        Write-Log "Registry key not found (already clean): $RegPath" "INFO"
                    }
                }
            }
            catch {
                Write-Log "Warning: Could not remove registry key $RegPath - $($_.Exception.Message)" "WARN"
                $SkippedKeys += $RegPath
            }
        }
        

        
        # Clear any cached licensing information
        try {
            $CachedLicensePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList"
            if (Test-Path $CachedLicensePath) {
                Remove-ItemProperty -Path $CachedLicensePath -Name "fDisabledAllowList" -ErrorAction SilentlyContinue
                Write-Log "Cleared cached Terminal Services licensing information" "INFO"
            }
        }
        catch {
            Write-Log "Note: No cached licensing information to clear" "INFO"
        }
        
        $Results = @{
            Success = $true
            RemovedKeys = $RemovedKeys
            SkippedKeys = $SkippedKeys
            TotalRemoved = $RemovedKeys.Count
            TotalSkipped = $SkippedKeys.Count
        }
        
        if ($RemovedKeys.Count -gt 0) {
            Write-Log "RDS grace period reset completed successfully" "SUCCESS"
            Write-Log "Removed $($RemovedKeys.Count) licensing registry keys" "SUCCESS"
            Write-Log "Note: System restart may be required for changes to take full effect" "WARN"
        } else {
            Write-Log "RDS grace period appears to already be reset (no keys found)" "SUCCESS"
        }
        
        return $Results
    }
    catch {
        Write-Log "Failed to reset RDS grace period: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}


function Mount-ISOFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath,
        
        [Parameter(Mandatory=$false)]
        [string]$PreferredDriveLetter = $null
    )
    
    try {
        Write-Log "Mounting ISO file: $ISOPath" "INFO"
        
        if (-not (Test-Path $ISOPath)) {
            Write-Log "ISO file not found: $ISOPath" "ERROR"
            return @{
                Success = $false
                DriveLetter = $null
                Error = "ISO file not found"
            }
        }
        
        # Mount the ISO
        $null = Mount-DiskImage -ImagePath $ISOPath -PassThru
        $Volume = Get-DiskImage -ImagePath $ISOPath | Get-Volume
        
        if ($Volume) {
            $DriveLetter = $Volume.DriveLetter
            Write-Log "ISO mounted successfully to drive $DriveLetter`:" "SUCCESS"
            
            return @{
                Success = $true
                DriveLetter = $DriveLetter
                MountPath = "$DriveLetter`:"
                Error = $null
            }
        } else {
            Write-Log "Failed to get volume information for mounted ISO" "ERROR"
            return @{
                Success = $false
                DriveLetter = $null
                Error = "Failed to get volume information"
            }
        }
    }
    catch {
        Write-Log "Failed to mount ISO: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            DriveLetter = $null
            Error = $_.Exception.Message
        }
    }
}

function Dismount-ISOFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath
    )
    
    try {
        Write-Log "Dismounting ISO file: $ISOPath" "INFO"
        
        $DismountResult = Dismount-DiskImage -ImagePath $ISOPath
        
        if ($DismountResult) {
            Write-Log "ISO dismounted successfully: $ISOPath" "SUCCESS"
            return @{
                Success = $true
                Error = $null
            }
        } else {
            Write-Log "Failed to dismount ISO: $ISOPath" "ERROR"
            return @{
                Success = $false
                Error = "Dismount operation failed"
            }
        }
    }
    catch {
        Write-Log "Error dismounting ISO: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Install-FromISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath,
        
        [Parameter(Mandatory=$true)]
        [string]$InstallerName,
        
        [Parameter(Mandatory=$false)]
        [string]$InstallerArgs = "/quiet /norestart",
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 30,
        
        [Parameter(Mandatory=$false)]
        [string]$ProductName = "Unknown Product"
    )
    
    try {
        Write-Log "Starting installation of $ProductName from ISO: $ISOPath" "INFO"
        
        # Mount the ISO
        $MountResult = Mount-ISOFile -ISOPath $ISOPath
        
        if (-not $MountResult.Success) {
            Write-Log "Failed to mount ISO for $ProductName installation" "ERROR"
            return @{
                Success = $false
                Error = "Failed to mount ISO: $($MountResult.Error)"
                ExitCode = -1
            }
        }
        
        try {
            $MountPath = $MountResult.MountPath
            Write-Log "ISO mounted to: $MountPath" "INFO"
            
            # Find the installer
            $InstallerPath = Join-Path $MountPath $InstallerName
            
            if (-not (Test-Path $InstallerPath)) {
                # Try to find installer in common subdirectories
                $CommonPaths = @("", "x64", "x86", "Setup", "Installers", "x64\XenDesktop Setup")
                $FoundInstaller = $false
                
                foreach ($SubPath in $CommonPaths) {
                    $TestPath = if ($SubPath) { Join-Path $MountPath $SubPath | Join-Path -ChildPath $InstallerName } else { $InstallerPath }
                    if (Test-Path $TestPath) {
                        $InstallerPath = $TestPath
                        $FoundInstaller = $true
                        break
                    }
                }
                
                if (-not $FoundInstaller) {
                    Write-Log "Installer not found: $InstallerName in mounted ISO" "ERROR"
                    return @{
                        Success = $false
                        Error = "Installer not found: $InstallerName"
                        ExitCode = -1
                    }
                }
            }
            
            Write-Log "Found installer: $InstallerPath" "SUCCESS"
            
            # Display full command line for verification
            Write-Host ""
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "EXECUTING $($ProductName.ToUpper()) INSTALLATION COMMAND" -ForegroundColor Yellow
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "Executable: " -NoNewline -ForegroundColor White
            Write-Host $InstallerPath -ForegroundColor Green
            Write-Host "Arguments:  " -NoNewline -ForegroundColor White
            Write-Host $InstallerArgs -ForegroundColor Green
            Write-Host "Full Command: " -NoNewline -ForegroundColor White
            Write-Host "`"$InstallerPath`" $InstallerArgs" -ForegroundColor Magenta
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host ""
            
            Write-Log "Installation arguments: $InstallerArgs" "INFO"
            Write-Log "Starting $ProductName installation..." "INFO"
            $StartTime = Get-Date
            
            # Split arguments properly for Start-Process
            $ArgumentArray = if ($InstallerArgs -match '^\s*$') { 
                @() 
            } elseif ($InstallerArgs -contains ' ') {
                # Parse arguments respecting quotes and spaces
                $ArgumentArray = @()
                $InstallerArgs -split '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)' | ForEach-Object {
                    $arg = $_.Trim()
                    if ($arg -ne '') {
                        $ArgumentArray += $arg.Trim('"')
                    }
                }
                $ArgumentArray
            } else {
                @($InstallerArgs)
            }
            
            $ProcessArgs = @{
                FilePath = $InstallerPath
                ArgumentList = $ArgumentArray
                Wait = $true
                PassThru = $true
                NoNewWindow = $true
            }
            
            $Process = Start-Process @ProcessArgs
            
            # Check if process completed within timeout
            $EndTime = Get-Date
            $Duration = $EndTime - $StartTime
            
            Write-Log "$ProductName installation completed in $([math]::Round($Duration.TotalMinutes, 2)) minutes" "INFO"
            Write-Log "Installation exit code: $($Process.ExitCode)" "INFO"
            
            # For Citrix VDA installations, exit code 3 can indicate success in certain scenarios
            # Exit codes: 0 = success, 3 = success but reboot required, 3010 = success but reboot required
            $SuccessExitCodes = @(0, 3, 3010)
            $IsSuccess = $SuccessExitCodes -contains $Process.ExitCode
            
            $InstallResult = @{
                Success = $IsSuccess
                ExitCode = $Process.ExitCode
                Duration = $Duration
                Error = if ($IsSuccess) { $null } else { "Installation failed with exit code: $($Process.ExitCode)" }
            }
            
            if ($InstallResult.Success) {
                if ($Process.ExitCode -eq 3010) {
                    Write-Log "$ProductName installation completed successfully (reboot required)" "SUCCESS"
                } elseif ($Process.ExitCode -eq 3) {
                    Write-Log "$ProductName installation completed successfully (reboot required)" "SUCCESS"
                } else {
                    Write-Log "$ProductName installation completed successfully" "SUCCESS"
                }
            } else {
                Write-Log "$ProductName installation failed with exit code: $($Process.ExitCode)" "ERROR"
            }
            
            return $InstallResult
        }
        finally {
            # Always dismount the ISO
            Write-Log "Dismounting ISO after installation attempt..." "INFO"
            $DismountResult = Dismount-ISOFile -ISOPath $ISOPath
            
            if ($DismountResult.Success) {
                Write-Log "ISO dismounted successfully" "SUCCESS"
            } else {
                Write-Log "Warning: Failed to dismount ISO: $($DismountResult.Error)" "WARN"
            }
        }
    }
    catch {
        Write-Log "Critical error during $ProductName installation: $($_.Exception.Message)" "ERROR"
        
        # Attempt to dismount ISO in case of error
        try {
            Dismount-ISOFile -ISOPath $ISOPath | Out-Null
        } catch {
            # Ignore dismount errors in exception handling
        }
        
        return @{
            Success = $false
            Error = $_.Exception.Message
            ExitCode = -1
        }
    }
}

function Install-VDAFromISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting VDA installation from ISO..." "INFO"
        
        # Get VDA configuration from config file
        $VDAISOPath = Get-ConfigValue -Key "VDAISOPath" -DefaultValue "C:\Temp\VDA.iso" -ConfigFile $ConfigFilePath
        $InstallVDA = [bool](Get-ConfigValue -Key "InstallVDA" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        
        if (-not $InstallVDA) {
            Write-Log "VDA installation skipped - disabled in configuration" "INFO"
            return @{
                Success = $true
                Skipped = $true
                Error = $null
            }
        }
        
        if (-not (Test-Path $VDAISOPath)) {
            Write-Log "VDA ISO not found: $VDAISOPath" "ERROR"
            return @{
                Success = $false
                Error = "VDA ISO file not found: $VDAISOPath"
            }
        }
        
        # Check available disk space (VDA requires minimum 2GB free space)
        $SystemDrive = $env:SystemDrive
        $FreeSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $SystemDrive }
        $FreeSpaceGB = [math]::Round($FreeSpace.FreeSpace / 1GB, 2)
        
        if ($FreeSpaceGB -lt 2) {
            Write-Log "Insufficient disk space for VDA installation. Available: $FreeSpaceGB GB, Required: 2 GB minimum" "ERROR"
            return @{
                Success = $false
                Error = "Insufficient disk space: $FreeSpaceGB GB available, 2 GB required"
                ExitCode = 13
            }
        }
        
        Write-Log "Disk space validation passed: $FreeSpaceGB GB available on $SystemDrive" "SUCCESS"
        
        # Ensure Spooler service is running for VDA installation
        try {
            $SpoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
            if ($SpoolerService) {
                if ($SpoolerService.Status -ne "Running") {
                    Write-Log "Starting Spooler service for VDA installation..." "INFO"
                    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    
                    # Verify service started
                    $SpoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
                    if ($SpoolerService.Status -eq "Running") {
                        Write-Log "Spooler service started successfully" "SUCCESS"
                    } else {
                        Write-Log "Warning: Spooler service failed to start - VDA installation may fail" "WARN"
                    }
                } else {
                    Write-Log "Spooler service is already running" "SUCCESS"
                }
            }
        }
        catch {
            Write-Log "Warning: Could not verify Spooler service status: $($_.Exception.Message)" "WARN"
        }
        
        # Get VDA installation arguments from config file
        $VDAArgs = Get-ConfigValue -Key "VDAInstallArguments" -DefaultValue "/quiet /norestart /components VDA /masterimage /installdir `"C:\Program Files\Citrix\Virtual Desktop Agent`"" -ConfigFile $ConfigFilePath
        
        # Install VDA from ISO
        $InstallResult = Install-FromISO -ISOPath $VDAISOPath -InstallerName "XenDesktopVDASetup.exe" -InstallerArgs $VDAArgs -ProductName "Citrix VDA" -TimeoutMinutes 45
        
        if ($InstallResult.Success) {
            Write-Log "VDA installation completed successfully" "SUCCESS"
            
            # Check if reboot is required
            if ($InstallResult.ExitCode -eq 3010) {
                Write-Log "VDA installation requires system reboot" "WARN"
            }
        } else {
            Write-Log "VDA installation failed: $($InstallResult.Error)" "ERROR"
            
            # Provide specific error information based on exit code
            switch ($InstallResult.ExitCode) {
                0 { Write-Log "Exit Code 0: Installation completed successfully" "INFO" }
                1 { Write-Log "Exit Code 1: General installation error" "ERROR" }
                3 { Write-Log "Exit Code 3: Installation completed successfully (reboot required)" "INFO" }
                6 { Write-Log "Exit Code 6: Invalid command line parameters - check installation arguments" "ERROR" }
                13 { Write-Log "Exit Code 13: Insufficient disk space or invalid installation path" "ERROR" }
                1603 { Write-Log "Exit Code 1603: Fatal error during installation" "ERROR" }
                1618 { Write-Log "Exit Code 1618: Another installation is already in progress" "ERROR" }
                1619 { Write-Log "Exit Code 1619: Installation package could not be opened" "ERROR" }
                1620 { Write-Log "Exit Code 1620: Installation package could not be opened (corrupt)" "ERROR" }
                1633 { Write-Log "Exit Code 1633: This installation package is not supported on this platform" "ERROR" }
                3010 { Write-Log "Exit Code 3010: Installation succeeded but requires reboot" "WARN" }
                default { Write-Log "Exit Code $($InstallResult.ExitCode): Unknown error code" "ERROR" }
            }
        }
        
        return $InstallResult
    }
    catch {
        Write-Log "Critical error in VDA installation: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Install-PVSFromISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting PVS Target installation from ISO..." "INFO"
        
        # Get PVS configuration from config file
        $PVSISOPath = Get-ConfigValue -Key "PVSISOPath" -DefaultValue "C:\Temp\PVS.iso" -ConfigFile $ConfigFilePath
        $InstallPVS = [bool](Get-ConfigValue -Key "InstallPVS" -DefaultValue "false" -ConfigFile $ConfigFilePath)
        
        if (-not $InstallPVS) {
            Write-Log "PVS Target installation skipped - disabled in configuration" "INFO"
            return @{
                Success = $true
                Skipped = $true
                Error = $null
            }
        }
        
        if (-not (Test-Path $PVSISOPath)) {
            Write-Log "PVS ISO not found: $PVSISOPath" "ERROR"
            return @{
                Success = $false
                Error = "PVS ISO file not found: $PVSISOPath"
            }
        }
        
        # Ensure Windows Installer service is running (fixes error code 1152)
        try {
            $InstallerService = Get-Service -Name "msiserver" -ErrorAction SilentlyContinue
            if ($InstallerService) {
                if ($InstallerService.Status -ne "Running") {
                    Write-Log "Starting Windows Installer service to prevent error code 1152..." "INFO"
                    Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                }
                Write-Log "Windows Installer service is running" "SUCCESS"
            }
        }
        catch {
            Write-Log "Warning: Could not verify Windows Installer service status: $($_.Exception.Message)" "WARN"
        }
        
        # Get PVS installation arguments from config file
        $PVSArgs = Get-ConfigValue -Key "PVSInstallArguments" -DefaultValue "/S" -ConfigFile $ConfigFilePath
        
        # Install PVS Target from ISO
        $InstallResult = Install-FromISO -ISOPath $PVSISOPath -InstallerName "Device\PVS_Device_x64.exe" -InstallerArgs $PVSArgs -ProductName "PVS Target Device" -TimeoutMinutes 20
        
        if ($InstallResult.Success) {
            Write-Log "PVS Target installation completed successfully" "SUCCESS"
            
            # Check if reboot is required
            if ($InstallResult.ExitCode -eq 3010) {
                Write-Log "PVS Target installation requires system reboot" "WARN"
            }
        } else {
            Write-Log "PVS Target installation failed: $($InstallResult.Error)" "ERROR"
            
            # Provide specific error information based on exit code
            switch ($InstallResult.ExitCode) {
                0 { Write-Log "Exit Code 0: Installation completed successfully" "INFO" }
                1 { Write-Log "Exit Code 1: General installation error" "ERROR" }
                3 { Write-Log "Exit Code 3: Installation failed due to insufficient privileges" "ERROR" }
                1152 { Write-Log "Exit Code 1152: Windows Installer service cannot be accessed or is not running" "ERROR" }
                1603 { Write-Log "Exit Code 1603: Fatal error during installation" "ERROR" }
                1618 { Write-Log "Exit Code 1618: Another installation is already in progress" "ERROR" }
                1619 { Write-Log "Exit Code 1619: Installation package could not be opened" "ERROR" }
                1620 { Write-Log "Exit Code 1620: Installation package could not be opened (corrupt)" "ERROR" }
                1633 { Write-Log "Exit Code 1633: This installation package is not supported on this platform" "ERROR" }
                3010 { Write-Log "Exit Code 3010: Installation succeeded but requires reboot" "WARN" }
                default { Write-Log "Exit Code $($InstallResult.ExitCode): Unknown error code" "ERROR" }
            }
        }
        
        return $InstallResult
    }
    catch {
        Write-Log "Critical error in PVS Target installation: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-CacheDriveRequirement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Performing comprehensive D: drive validation..." "INFO"
        
        # Check if cache drive is required
        $RequireCacheDrive = [bool](Get-ConfigValue -Key "RequireCacheDrive" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        $UseVirtualCacheDrive = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "false" -ConfigFile $ConfigFilePath)
        
        $result = @{
            Success = $true
            RequiredButMissing = $false
            DriveType = $null
            Action = "None"
            Message = ""
            Error = $null
        }
        
        if (-not $RequireCacheDrive) {
            $result.Action = "Skipped"
            $result.Message = "Cache drive requirement disabled in configuration"
            Write-Log "D: drive validation skipped - cache drive not required" "INFO"
            return $result
        }
        
        # Check current D: drive status
        $DDriveCheck = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "D:" }
        
        if (-not $DDriveCheck) {
            if ($UseVirtualCacheDrive) {
                # Check if virtual cache drive exists
                if (Test-Path "D:\") {
                    $result.DriveType = "Virtual"
                    $result.Action = "VirtualCacheFound"
                    $result.Message = "Virtual cache drive is accessible"
                    Write-Log "Virtual cache drive found and accessible" "SUCCESS"
                } else {
                    $result.Success = $false
                    $result.RequiredButMissing = $true
                    $result.Action = "VirtualCacheFailed"
                    $result.Error = "Virtual cache drive creation failed or not accessible"
                    Write-Log "Virtual cache drive not accessible" "ERROR"
                }
            } else {
                $result.Success = $false
                $result.RequiredButMissing = $true
                $result.Action = "PhysicalCacheRequired"
                $result.Error = "Physical cache drive required but not attached"
                Write-Log "No D: drive detected and cache drive is required" "ERROR"
            }
        }
        elseif ($DDriveCheck.DriveType -eq 5) {
            # CD/DVD ROM detected - needs relocation
            $result.DriveType = "CDROM"
            $result.Action = "RelocationRequired"
            $result.Message = "CD/DVD ROM detected on D: drive - relocation required"
            Write-Log "CD/DVD ROM detected on D: drive - relocation needed" "WARN"
        }
        elseif ($DDriveCheck.DriveType -eq 3) {
            # Fixed disk - perfect for cache
            $result.DriveType = "FixedDisk"
            $result.Action = "Valid"
            $result.Message = "Fixed disk drive detected - suitable for cache operations"
            Write-Log "Valid fixed disk detected on D: drive" "SUCCESS"
        }
        else {
            # Unknown drive type
            $result.Success = $false
            $result.DriveType = "Unknown"
            $result.Action = "InvalidType"
            $result.Error = "D: drive type $($DDriveCheck.DriveType) not suitable for cache operations"
            Write-Log "D: drive has unsuitable type: $($DDriveCheck.DriveType)" "ERROR"
        }
        
        return $result
    }
    catch {
        Write-Log "Critical error in D: drive validation: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            RequiredButMissing = $true
            DriveType = $null
            Action = "ValidationFailed"
            Message = ""
            Error = $_.Exception.Message
        }
    }
}

function Remove-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetPath,
        
        [Parameter(Mandatory=$false)]
        [bool]$ForceDelete = $true
    )
    
    try {
        Write-Log "Starting installation files cleanup in: $TargetPath" "INFO"
        
        $result = @{
            Success = $true
            FilesRemoved = 0
            FoldersRemoved = 0
            Errors = @()
        }
        
        if (-not (Test-Path $TargetPath)) {
            Write-Log "Target path does not exist: $TargetPath" "WARN"
            return $result
        }
        
        # Get all items in the target path
        $AllItems = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        $Files = $AllItems | Where-Object { -not $_.PSIsContainer }
        $Folders = $AllItems | Where-Object { $_.PSIsContainer } | Sort-Object FullName -Descending
        
        Write-Log "Found $($Files.Count) files and $($Folders.Count) folders to remove" "INFO"
        
        # Remove files first
        foreach ($File in $Files) {
            try {
                if ($ForceDelete) {
                    # Force remove read-only and in-use files
                    Set-ItemProperty -Path $File.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
                    Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                } else {
                    Remove-Item -Path $File.FullName -ErrorAction Stop
                }
                $result.FilesRemoved++
            }
            catch {
                if ($ForceDelete) {
                    # Try alternative methods for stubborn files
                    try {
                        # Use CMD DEL command for in-use files
                        $null = cmd /c "del /f /q `"$($File.FullName)`"" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $result.FilesRemoved++
                        } else {
                            $result.Errors += "Failed to force delete file: $($File.FullName) - $($_.Exception.Message)"
                        }
                    }
                    catch {
                        $result.Errors += "Failed to delete file: $($File.FullName) - $($_.Exception.Message)"
                    }
                } else {
                    $result.Errors += "Failed to delete file: $($File.FullName) - $($_.Exception.Message)"
                }
            }
        }
        
        # Remove folders (from deepest to shallowest)
        foreach ($Folder in $Folders) {
            try {
                if ($ForceDelete) {
                    Remove-Item -Path $Folder.FullName -Recurse -Force -ErrorAction Stop
                } else {
                    Remove-Item -Path $Folder.FullName -Recurse -ErrorAction Stop
                }
                $result.FoldersRemoved++
            }
            catch {
                if ($ForceDelete) {
                    # Try alternative method for stubborn folders
                    try {
                        $null = cmd /c "rmdir /s /q `"$($Folder.FullName)`"" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $result.FoldersRemoved++
                        } else {
                            $result.Errors += "Failed to force delete folder: $($Folder.FullName) - $($_.Exception.Message)"
                        }
                    }
                    catch {
                      ```powershell
                        $result.Errors += "Failed to delete folder: $($Folder.FullName) - $($_.Exception.Message)"
                    }
                } else {
                    $result.Errors += "Failed to delete folder: $($Folder.FullName) - $($_.Exception.Message)"
                }
            }
        }
        
        # Do not remove the target directory - preserve it for future use
        try {
            $RemainingItems = Get-ChildItem -Path $TargetPath -Force -ErrorAction SilentlyContinue
            if ($RemainingItems.Count -eq 0) {
                Write-Log "Target directory is now empty and preserved: $TargetPath" "SUCCESS"
            } else {
                Write-Log "Target directory preserved with $($RemainingItems.Count) items remaining" "INFO"
            }
        }
        catch {
            Write-Log "Error checking target directory status: $TargetPath - $($_.Exception.Message)" "WARN"
        }
        
        if ($result.Errors.Count -gt 0) {
            $result.Success = $false
            Write-Log "Installation files cleanup completed with $($result.Errors.Count) errors" "WARN"
        } else {
            Write-Log "Installation files cleanup completed successfully" "SUCCESS"
        }
        
        Write-Log "Cleanup summary: $($result.FilesRemoved) files, $($result.FoldersRemoved) folders removed" "INFO"
        
        return $result
    }
    catch {
        Write-Log "Critical error in installation files cleanup: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            FilesRemoved = 0
            FoldersRemoved = 0
            Errors = @("Critical error: $($_.Exception.Message)")
        }
    }
}

function Set-WindowsOptimizations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting Windows system optimizations..." "INFO"
        
        $result = @{
            Success = $true
            OptimizationsApplied = @()
            OptimizationsSkipped = @()
            Errors = @()
        }
        
        # Citrix Optimizer handles all Windows optimizations - delegating to optimizer templates
        Write-Log "Windows system optimizations delegated to Citrix Optimizer templates" "INFO"
        
        # All Windows optimizations are now handled by Citrix Optimizer
        # This eliminates duplicate optimization efforts and ensures consistency
        $result.OptimizationsApplied += "Delegated to Citrix Optimizer"
        $result.OptimizationsSkipped += "Individual Windows optimizations (handled by Citrix Optimizer)"
        
        # Set overall success based on errors
        if ($result.Errors.Count -gt 0) {
            $result.Success = $false
            Write-Log "Windows optimizations completed with $($result.Errors.Count) errors" "WARN"
        } else {
            Write-Log "All Windows optimizations completed successfully" "SUCCESS"
        }
        
        return $result
    }
    catch {
        Write-Log "Critical error in Windows optimizations: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            OptimizationsApplied = @()
            OptimizationsSkipped = @()
            Errors = @("Critical error: $($_.Exception.Message)")
        }
    }
}

function New-InstallConfig {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Initializing installation configuration..."
        
        $config = @{
            # Basic properties
            StartTime = Get-Date
            Stage1CompletedAt = $null
            Stage2CompletedAt = $null
            OverallSuccess = $false
            RebootRequired = $false
            ValidationMode = $false
            ValidationWarnings = @()
            
            # Installation paths
            VDAISOPath = $null
            PVSISOPath = $null
            WEMInstallerSourcePath = $null
            WEMInstallerPath = $null
            UberAgentInstallerSourcePath = $null
            UberAgentInstallerPath = $null
            TADDMPath = $null
            
            # Installation results
            InstallationResults = @{
                VDA = @{ Success = $false; Skipped = $false }
                PVS = @{ Success = $false; Skipped = $false }
                WEM = @{ Success = $false; Skipped = $false }
                UberAgent = @{ Success = $false; Skipped = $false; OverallSuccess = $false }
                TADDM = @{ Success = $false; Skipped = $false; OverallSuccess = $false }
                CacheDrive = @{ Success = $false }
                CitrixOptimizer = @{ Success = $false }
                CitrixServicesDisabled = @{ Success = $false }
                DomainJoin = @{ Success = $false; Skipped = $false }
            }
            
            # Legacy properties for compatibility
            Results = @{}
            Errors = @()
            Components = @()
        }
        
        Write-Log "Installation configuration initialized with full structure" "SUCCESS"
        return $config
    }
    catch {
        Write-Log "Failed to initialize installation configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Add-CitrixVDA {
    [CmdletBinding()]
    param(
        [string]$VDAISOSourcePath,
        [string]$VDAISOPath,
        [string]$LogDir,
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Installing Citrix VDA..."
        
        # Get configurable installation arguments
        $VDAInstallArguments = Get-ConfigValue -Key "VDAInstallArguments" -DefaultValue "/quiet /norestart /components vda,plugins /enable_hdx_ports /enable_real_time_transport /masterimage" -ConfigFile $ConfigFilePath
        Write-Log "VDA installation arguments: $VDAInstallArguments" "INFO"
        
        # Mount ISO and run installation
        $null = Mount-DiskImage -ImagePath $VDAISOPath -PassThru
        $DriveLetter = ($null | Get-Volume).DriveLetter
        
        $SetupPath = "${DriveLetter}:\x64\XenDesktop Setup\XenDesktopVdaSetup.exe"
        if (Test-Path $SetupPath) {
            # Display full command line for verification
            Write-Host ""
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "EXECUTING VDA INSTALLATION COMMAND" -ForegroundColor Yellow
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "Executable: " -NoNewline -ForegroundColor White
            Write-Host $SetupPath -ForegroundColor Green
            Write-Host "Arguments:  " -NoNewline -ForegroundColor White
            Write-Host $VDAInstallArguments -ForegroundColor Green
            Write-Host "Full Command: " -NoNewline -ForegroundColor White
            Write-Host "`"$SetupPath`" $VDAInstallArguments" -ForegroundColor Magenta
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host ""
            
            Write-Log "Starting VDA installation with arguments: $VDAInstallArguments" "INFO"
            $VDAProcess = Start-Process -FilePath $SetupPath -ArgumentList $VDAInstallArguments -Wait -PassThru
            
            if ($VDAProcess.ExitCode -eq 0) {
                Write-Log "Citrix VDA installation completed successfully" "SUCCESS"
                $InstallSuccess = $true
            } else {
                Write-Log "Citrix VDA installation failed with exit code: $($VDAProcess.ExitCode)" "ERROR"
                $InstallSuccess = $false
            }
        } else {
            Write-Log "VDA setup file not found at: $SetupPath" "ERROR"
            $InstallSuccess = $false
        }
        
        Dismount-DiskImage -ImagePath $VDAISOPath
        return $InstallSuccess
    }
    catch {
        Write-Log "Failed to install Citrix VDA: $($_.Exception.Message)" "ERROR"
        try { Dismount-DiskImage -ImagePath $VDAISOPath -ErrorAction SilentlyContinue } catch { }
        return $false
    }
}

function Add-PVSTargetDevice {
    [CmdletBinding()]
    param(
        [string]$PVSISOSourcePath,
        [string]$PVSISOPath,
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Installing PVS Target Device..."
        
        # Get configurable installation arguments
        $PVSInstallArguments = Get-ConfigValue -Key "PVSInstallArguments" -DefaultValue "/S" -ConfigFile $ConfigFilePath
        Write-Log "PVS installation arguments: $PVSInstallArguments" "INFO"
        
        $null = Mount-DiskImage -ImagePath $PVSISOPath -PassThru
        $DriveLetter = ($null | Get-Volume).DriveLetter
        
        $SetupPath = "${DriveLetter}:\Device\TargetDeviceSetup.exe"
        if (Test-Path $SetupPath) {
            Write-Log "Starting PVS installation with arguments: $PVSInstallArguments" "INFO"
            
            # Split arguments properly for Start-Process
            $ArgumentArray = if ($PVSInstallArguments -match '^\s*$') { 
                @() 
            } elseif ($PVSInstallArguments -contains ' ') {
                # Parse arguments respecting quotes and spaces
                $ArgumentArray = @()
                $PVSInstallArguments -split '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)' | ForEach-Object {
                    $arg = $_.Trim()
                    if ($arg -ne '') {
                        $ArgumentArray += $arg.Trim('"')
                    }
                }
                $ArgumentArray
            } else {
                @($PVSInstallArguments)
            }
            
            $PVSProcess = Start-Process -FilePath $SetupPath -ArgumentList $ArgumentArray -Wait -PassThru
            
            if ($PVSProcess.ExitCode -eq 0) {
                Write-Log "PVS Target Device installation completed successfully" "SUCCESS"
                $InstallSuccess = $true
            } else {
                Write-Log "PVS Target Device installation failed with exit code: $($PVSProcess.ExitCode)" "ERROR"
                $InstallSuccess = $false
            }
        } else {
            Write-Log "PVS setup file not found at: $SetupPath" "ERROR"
            $InstallSuccess = $false
        }
        
        Dismount-DiskImage -ImagePath $PVSISOPath
        return $InstallSuccess
    }
    catch {
        Write-Log "Failed to install PVS Target Device: $($_.Exception.Message)" "ERROR"
        try { Dismount-DiskImage -ImagePath $PVSISOPath -ErrorAction SilentlyContinue } catch { }
        return $false
    }
}

function Add-WEMAgent {
    [CmdletBinding()]
    param(
        [string]$WEMSourcePath,
        [string]$WEMPath,
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Installing WEM Agent - copying from network to local temp..."
        
        $Results = @{
            Success = $false
            Skipped = $false
            RebootRequired = $false
            FileCopied = $false
            Error = $null
        }
        
        # Check if WEM installer source path is provided
        if ([string]::IsNullOrEmpty($WEMSourcePath)) {
            Write-Log "WEM Agent installation skipped - no source path specified" "INFO"
            $Results.Skipped = $true
            $Results.Success = $true
            return $Results
        }
        
        # Ensure C:\Temp directory exists
        $TempDir = "C:\Temp"
        if (-not (Test-Path $TempDir)) {
            Write-Log "Creating temp directory: $TempDir" "INFO"
            New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
        }
        
        # Copy WEM installer from network to local temp
        Write-Log "Copying WEM Agent from network location: $WEMSourcePath" "INFO"
        Write-Log "Destination: $WEMPath" "INFO"
        
        try {
            Copy-Item -Path $WEMSourcePath -Destination $WEMPath -Force -ErrorAction Stop
            Write-Log "WEM Agent file copied successfully to C:\Temp" "SUCCESS"
            $Results.FileCopied = $true
        }
        catch {
            $ErrorMsg = "Failed to copy WEM Agent from network: $($_.Exception.Message)"
            Write-Log $ErrorMsg "ERROR"
            $Results.Error = $ErrorMsg
            return $Results
        }
        
        # Verify local file exists after copy
        if (Test-Path $WEMPath) {
            Write-Log "Installing WEM Agent from: $WEMPath" "INFO"
            
            # Get configurable installation arguments
            $WEMInstallArguments = Get-ConfigValue -Key "WEMInstallArguments" -DefaultValue "/quiet /norestart" -ConfigFile $ConfigFilePath
            
            # Display full command line for verification
            Write-Host ""
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "EXECUTING WEM AGENT INSTALLATION COMMAND" -ForegroundColor Yellow
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host "Executable: " -NoNewline -ForegroundColor White
            Write-Host $WEMPath -ForegroundColor Green
            Write-Host "Arguments:  " -NoNewline -ForegroundColor White
            Write-Host $WEMInstallArguments -ForegroundColor Green
            Write-Host "Full Command: " -NoNewline -ForegroundColor White
            Write-Host "`"$WEMPath`" $WEMInstallArguments" -ForegroundColor Magenta
            Write-Host "======================================================================" -ForegroundColor Cyan
            Write-Host ""
            
            Write-Log "WEM installation arguments: $WEMInstallArguments" "INFO"
            Write-Log "Starting WEM installation with arguments: $WEMInstallArguments" "INFO"
            $WEMProcess = Start-Process -FilePath $WEMPath -ArgumentList $WEMInstallArguments -Wait -PassThru
            
            if ($WEMProcess.ExitCode -eq 0) {
                Write-Log "WEM Agent installation completed successfully" "SUCCESS"
                $Results.Success = $true
                
                # Check if WEM Agent service exists (indicates successful installation)
                $WEMService = Get-Service -Name "WemAgentsvc" -ErrorAction SilentlyContinue
                if ($WEMService) {
                    Write-Log "WEM Agent service detected - installation verified" "SUCCESS"
                    
                    # Configure WEM Agent cache location if specified
                    $ConfigureWEMAgentCache = [bool](Get-ConfigValue -Key "ConfigureWEMAgentCache" -DefaultValue "false" -ConfigFile $ConfigFilePath)
                    if ($ConfigureWEMAgentCache) {
                        $WEMAgentCacheLocation = Get-ConfigValue -Key "WEMAgentCacheLocation" -DefaultValue "D:\WEM\Cache" -ConfigFile $ConfigFilePath
                        
                        # Validate cache location is not empty
                        if ([string]::IsNullOrWhiteSpace($WEMAgentCacheLocation)) {
                            Write-Log "WEM Agent cache location is empty - using default: D:\WEM\Cache" "WARN"
                            $WEMAgentCacheLocation = "D:\WEM\Cache"
                        }
                        
                        Write-Log "Configuring WEM Agent cache location: $WEMAgentCacheLocation" "INFO"
                        
                        $CacheConfigResult = Set-WEMAgentCacheLocation -CacheLocation $WEMAgentCacheLocation
                        if ($CacheConfigResult.Success) {
                            Write-Log "WEM Agent cache location configured successfully" "SUCCESS"
                            $Results.CacheLocationConfigured = $true
                            $Results.CacheLocation = $WEMAgentCacheLocation
                        } else {
                            Write-Log "Failed to configure WEM Agent cache location: $($CacheConfigResult.Error)" "WARN"
                            $Results.CacheLocationConfigured = $false
                        }
                    } else {
                        Write-Log "WEM Agent cache location configuration skipped - disabled in config" "INFO"
                        $Results.CacheLocationConfigured = $false
                    }
                } else {
                    Write-Log "WEM Agent service not found - installation may require reboot" "WARN"
                    $Results.RebootRequired = $true
                }
            } else {
                $ErrorMsg = "WEM Agent installation failed with exit code: $($WEMProcess.ExitCode)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Error = $ErrorMsg
            }
            
            # Clean up local installer file after installation attempt
            try {
                if (Test-Path $WEMPath) {
                    Remove-Item -Path $WEMPath -Force -ErrorAction Stop
                    Write-Log "Cleaned up WEM installer file from temp directory" "INFO"
                }
            }
            catch {
                Write-Log "Failed to clean up WEM installer file: $($_.Exception.Message)" "WARN"
            }
        }
        else {
            $ErrorMsg = "WEM installer not found after copy operation: $WEMPath"
            Write-Log $ErrorMsg "ERROR"
            $Results.Error = $ErrorMsg
        }
        
        return $Results
    }
    catch {
        $ErrorMsg = "Failed to install WEM Agent: $($_.Exception.Message)"
        Write-Log $ErrorMsg "ERROR"
        return @{
            Success = $false
            Skipped = $false
            RebootRequired = $false
            Error = $ErrorMsg
        }
    }
}

function Set-WEMAgentCacheLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$CacheLocation
    )
    
    try {
        # Validate cache location parameter
        if ([string]::IsNullOrWhiteSpace($CacheLocation)) {
            throw "Cache location cannot be empty or null"
        }
        
        Write-Log "Configuring WEM Agent cache location to: $CacheLocation"
        
        # Ensure cache directory exists
        $CacheDirectory = Split-Path $CacheLocation -Parent
        if (-not (Test-Path $CacheDirectory)) {
            Write-Log "Creating WEM cache directory: $CacheDirectory"
            New-Item -Path $CacheDirectory -ItemType Directory -Force | Out-Null
        }
        
        # Correct WEM Agent registry location for cache configuration
        $WEMRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host"
        
        # Stop the Citrix WEM Agent Host Service before making registry changes
        $WEMService = Get-Service -Name "WemAgentsvc" -ErrorAction SilentlyContinue
        $ServiceWasStopped = $false
        if ($WEMService -and $WEMService.Status -eq 'Running') {
            try {
                Write-Log "Stopping Citrix WEM Agent Host Service before registry modification" "INFO"
                Stop-Service -Name "WemAgentsvc" -Force -ErrorAction Stop
                $ServiceWasStopped = $true
                Write-Log "WEM Agent Host Service stopped successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to stop WEM Agent Host Service: $($_.Exception.Message)" "WARN"
            }
        }
        
        $ConfigurationSuccess = $false
        
        try {
            # Ensure the registry path exists
            if (-not (Test-Path $WEMRegistryPath)) {
                Write-Log "Creating WEM registry path: $WEMRegistryPath" "INFO"
                New-Item -Path $WEMRegistryPath -Force | Out-Null
            }
            
            Write-Log "Setting AgentCacheAlternateLocation in: $WEMRegistryPath" "INFO"
            
            # Set AgentCacheAlternateLocation registry value
            Set-ItemProperty -Path $WEMRegistryPath -Name "AgentCacheAlternateLocation" -Value $CacheLocation -Type String
            
            # Verify the value was set
            $SetValue = Get-ItemProperty -Path $WEMRegistryPath -Name "AgentCacheAlternateLocation" -ErrorAction SilentlyContinue
            if ($SetValue -and $SetValue.AgentCacheAlternateLocation -eq $CacheLocation) {
                Write-Log "Successfully configured WEM Agent cache location: $CacheLocation" "SUCCESS"
                $ConfigurationSuccess = $true
            } else {
                Write-Log "Failed to verify cache location setting in registry" "ERROR"
            }
        }
        catch {
            Write-Log "Failed to configure WEM Agent cache location: $($_.Exception.Message)" "ERROR"
        }
        
        # Restart the WEM Agent Host Service if it was stopped
        if ($ServiceWasStopped) {
            try {
                Write-Log "Restarting Citrix WEM Agent Host Service" "INFO"
                Start-Service -Name "WemAgentsvc" -ErrorAction Stop
                Write-Log "WEM Agent Host Service restarted successfully" "SUCCESS"
            }
            catch {
                Write-Log "Failed to restart WEM Agent Host Service: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Create cache location directory with proper permissions
        if (-not (Test-Path $CacheLocation)) {
            Write-Log "Creating WEM cache location: $CacheLocation"
            New-Item -Path $CacheLocation -ItemType Directory -Force | Out-Null
            
            # Set appropriate permissions for WEM Agent service
            try {
                $Acl = Get-Acl $CacheLocation
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $Acl.SetAccessRule($AccessRule)
                $AccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $Acl.SetAccessRule($AccessRule2)
                Set-Acl -Path $CacheLocation -AclObject $Acl
                Write-Log "Set permissions on WEM cache directory" "SUCCESS"
            }
            catch {
                Write-Log "Failed to set permissions on cache directory: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Return results based on configuration success
        if ($ConfigurationSuccess) {
            Write-Log "WEM Agent cache location configured successfully" "SUCCESS"
            Write-Log "Cache location: $CacheLocation" "SUCCESS"
            Write-Log "Registry path: $WEMRegistryPath" "SUCCESS"
        } else {
            Write-Log "Failed to configure WEM Agent cache location in registry" "ERROR"
        }
        
        return @{
            Success = $ConfigurationSuccess
            CacheLocation = $CacheLocation
            RegistryPath = $WEMRegistryPath
            DirectoryCreated = (Test-Path $CacheLocation)
            ServiceRestarted = $ServiceWasStopped
        }
    }
    catch {
        Write-Log "Failed to configure WEM Agent cache location: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            CacheLocation = $CacheLocation
        }
    }
}

function Add-UberAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UberAgentInstallerPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        # Suppress all confirmation prompts for this function
        $OriginalConfirmPreference = $ConfirmPreference
        $ConfirmPreference = 'None'
        
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
        if ([string]::IsNullOrEmpty($UberAgentInstallerPath)) {
            Write-Log "UberAgent installation skipped - no installer path specified" "INFO"
            $Results.Skipped = $true
            $Results.OverallSuccess = $true
            return $Results
        }
        
        # Check installer availability
        if (-not (Test-Path $UberAgentInstallerPath)) {
            $ErrorMsg = "UberAgent installer not found at: $UberAgentInstallerPath"
            Write-Log $ErrorMsg "ERROR"
            $Results.Errors += $ErrorMsg
            return $Results
        }
        
        # Get UberAgent installation arguments from config file
        $UberAgentInstallArgs = Get-ConfigValue -Key "UberAgentInstallArguments" -DefaultValue "/quiet /norestart ALLUSERS=1 REBOOT=ReallySuppress" -ConfigFile $ConfigFilePath
        
        # Install UberAgent with configurable MSI arguments
        $UberAgentArgs = "/i `"$UberAgentInstallerPath`" $UberAgentInstallArgs /l*v `"C:\Temp\UberAgent_Install.log`""
        
        # Display full command line for verification
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Cyan
        Write-Host "EXECUTING UBERAGENT INSTALLATION COMMAND" -ForegroundColor Yellow
        Write-Host "======================================================================" -ForegroundColor Cyan
        Write-Host "Executable: " -NoNewline -ForegroundColor White
        Write-Host "msiexec.exe" -ForegroundColor Green
        Write-Host "Arguments:  " -NoNewline -ForegroundColor White
        Write-Host $UberAgentArgs -ForegroundColor Green
        Write-Host "Full Command: " -NoNewline -ForegroundColor White
        Write-Host "msiexec.exe $UberAgentArgs" -ForegroundColor Magenta
        Write-Host "======================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Log "Installing UberAgent from: $UberAgentInstallerPath"
        Write-Log "UberAgent installation arguments: $UberAgentArgs" "INFO"
        $InstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $UberAgentArgs -Wait -PassThru
        
        if ($InstallProcess.ExitCode -eq 0) {
            Write-Log "UberAgent installation completed successfully" "SUCCESS"
            $Results.InstallationSuccess = $true
            
            # Wait for installation to complete and create directories
            Start-Sleep -Seconds 5
            
            # Post-installation validation and cleanup
            Write-Log "Performing UberAgent post-installation validation and cleanup..." "INFO"
            
            # Stop UberAgent service
            try {
                $UberAgentService = Get-Service -Name "uberAgentSvc" -ErrorAction SilentlyContinue
                if ($UberAgentService) {
                    Write-Log "Found UberAgent service - stopping for template preparation..." "INFO"
                    if ($UberAgentService.Status -eq "Running") {
                        Stop-Service -Name "uberAgentSvc" -Force -ErrorAction Stop
                        Write-Log "UberAgent service stopped successfully" "SUCCESS"
                        $Results.ServiceStopped = $true
                    } else {
                        Write-Log "UberAgent service already stopped" "INFO"
                        $Results.ServiceStopped = $true
                    }
                } else {
                    Write-Log "UberAgent service not found - may not be installed correctly" "WARN"
                }
            }
            catch {
                $ErrorMsg = "Failed to stop UberAgent service: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Validate and clear UberAgent registry key
            try {
                $UberAgentRegPath = "HKLM:\Software\vast limits\uberAgent"
                # Use Get-ItemProperty to properly handle registry paths with spaces
                try {
                    $RegCheck = Get-ItemProperty -Path $UberAgentRegPath -ErrorAction Stop
                    $RegistryExists = $true
                } catch {
                    $RegistryExists = $false
                }
                
                if ($RegistryExists) {
                    Write-Log "UberAgent registry key found - deleting for template preparation..." "INFO"
                    
                    # Delete the entire registry key for template preparation
                    Remove-Item -Path $UberAgentRegPath -Recurse -Force -ErrorAction Stop
                    Write-Log "UberAgent registry key deleted successfully" "SUCCESS"
                    $Results.RegistryCleared = $true
                } else {
                    Write-Log "UberAgent registry key not found - no cleanup needed" "INFO"
                    $Results.RegistryCleared = $true
                }
            }
            catch {
                $ErrorMsg = "Failed to clear UberAgent registry key: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Clean up temporary UberAgent log files
            try {
                $TempLogPattern = Get-ConfigValue -Key "UberAgentTempLogPattern" -DefaultValue "uberagent*.log" -ConfigFile $ConfigFilePath
                $TempLogFiles = Get-ChildItem -Path "C:\Temp" -Name $TempLogPattern -ErrorAction SilentlyContinue
                
                if ($TempLogFiles) {
                    foreach ($LogFile in $TempLogFiles) {
                        $LogFilePath = Join-Path "C:\Temp" $LogFile
                        Remove-Item -Path $LogFilePath -Force -ErrorAction SilentlyContinue
                        Write-Log "Removed temporary UberAgent log: $LogFile" "INFO"
                    }
                    $Results.TempLogsCleared = $true
                    Write-Log "UberAgent temporary logs cleaned up" "SUCCESS"
                } else {
                    Write-Log "No UberAgent temporary logs found to clean up" "INFO"
                    $Results.TempLogsCleared = $true
                }
            }
            catch {
                $ErrorMsg = "Failed to clean up UberAgent temporary logs: $($_.Exception.Message)"
                Write-Log $ErrorMsg "WARN"
                $Results.Errors += $ErrorMsg
            }
            
            # Add post-installation steps summary
            $Results.PostInstallSteps += "UberAgent service stopped for template preparation"
            $Results.PostInstallSteps += "Registry key HKLM:\Software\vast limits\uberAgent validated and cleared"
            $Results.PostInstallSteps += "Temporary installation logs cleaned up"
            
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
                                        $SizeMismatch = $SourceSize -ne $DestSize
                                        $HashMismatch = $SourceHash -ne $DestHash
                                        
                                        if ($SizeMismatch) {
                                            Write-Log "Template $($TemplateFile.Name) size mismatch - Source: $SourceSize bytes, Destination: $DestSize bytes" "ERROR"
                                        }
                                        if ($HashMismatch) {
                                            Write-Log "Template $($TemplateFile.Name) hash mismatch - Source: $SourceHash, Destination: $DestHash" "ERROR"
                                        }
                                        
                                        $ErrorMsg = "Template validation failed: $($TemplateFile.Name) - Size/Hash mismatch (Source: $([Math]::Round($SourceSize/1KB, 1)) KB, Dest: $([Math]::Round($DestSize/1KB, 1)) KB)"
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
                                $SizeMismatch = $SourceSize -ne $DestSize
                                $HashMismatch = $SourceHash -ne $DestHash
                                
                                if ($SizeMismatch) {
                                    Write-Log "Configuration file size mismatch - Source: $SourceSize bytes, Destination: $DestSize bytes" "ERROR"
                                }
                                if ($HashMismatch) {
                                    Write-Log "Configuration file hash mismatch - Source: $SourceHash, Destination: $DestHash" "ERROR"
                                }
                                
                                $ErrorMsg = "Configuration file validation failed - Size/Hash mismatch (Source: $([Math]::Round($SourceSize/1KB, 1)) KB, Dest: $([Math]::Round($DestSize/1KB, 1)) KB)"
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
                        
                        # Simple file comparison - if same skip copy, if different overwrite
                        $ShouldCopy = $true
                        $CopyAction = "NEW"
                        
                        if (Test-Path $LicenseLocalPath) {
                            # Compare files using hash
                            $SourceHash = (Get-FileHash -Path $LicenseSourcePath -Algorithm MD5).Hash
                            $DestHash = (Get-FileHash -Path $LicenseLocalPath -Algorithm MD5).Hash
                            
                            if ($SourceHash -eq $DestHash) {
                                Write-Log "License files are identical - skipping copy" "INFO"
                                $ShouldCopy = $false
                                $CopyAction = "SKIPPED"
                            } else {
                                Write-Log "License files differ - overwriting" "INFO"
                                $CopyAction = "OVERWRITE"
                            }
                        }
                        
                        # Copy file if needed
                        if ($ShouldCopy) {
                            Copy-Item -Path $LicenseSourcePath -Destination $LicenseLocalPath -Force
                        }
                        
                        # Validate license file result
                        if (Test-Path $LicenseLocalPath) {
                            $LicenseFile = Get-Item $LicenseLocalPath
                            $LicenseSize = $LicenseFile.Length
                            Write-Log "[$CopyAction] UberAgent license file processed successfully ($([Math]::Round($LicenseSize/1KB, 1)) KB)" "SUCCESS"
                            $Results.LicenseCopied = $true
                            $Results.FilesProcessed += "License: uberagent.lic [$CopyAction]"
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
            
            # Configure UberAgent service and registry settings
            $UberAgentServiceName = Get-ConfigValue -Key "UberAgentServiceName" -DefaultValue "uberAgentsvc" -ConfigFile $ConfigFilePath
            $UberAgentRegistryPath = Get-ConfigValue -Key "UberAgentRegistryPath" -DefaultValue "HKLM:\Software\vast limits\uberAgent" -ConfigFile $ConfigFilePath
            
            # Stop UberAgent service for configuration changes
            try {
                $Service = Get-Service -Name $UberAgentServiceName -ErrorAction SilentlyContinue
                if ($Service -and $Service.Status -eq 'Running') {
                    Stop-Service -Name $UberAgentServiceName -Force
                    Write-Log "Stopped UberAgent service: $UberAgentServiceName" "SUCCESS"
                    $Results.ServiceStopped = $true
                    $Results.PostInstallSteps += "Service stopped: $UberAgentServiceName"
                }
            }
            catch {
                Write-Log "Failed to stop UberAgent service: $($_.Exception.Message)" "WARN"
            }
            
            # Clear UberAgent registry for fresh configuration
            try {
                # Use Get-ItemProperty to properly handle registry paths with spaces
                try {
                    $RegCheck = Get-ItemProperty -Path $UberAgentRegistryPath -ErrorAction Stop
                    $RegistryExists = $true
                } catch {
                    $RegistryExists = $false
                }
                
                if ($RegistryExists) {
                    Remove-Item -Path $UberAgentRegistryPath -Recurse -Force
                    Write-Log "Cleared UberAgent registry path: $UberAgentRegistryPath" "SUCCESS"
                    $Results.RegistryCleared = $true
                    $Results.PostInstallSteps += "Registry cleared: $UberAgentRegistryPath"
                } else {
                    Write-Log "UberAgent registry path not found (may not be installed): $UberAgentRegistryPath" "INFO"
                }
            }
            catch {
                Write-Log "Failed to clear UberAgent registry: $($_.Exception.Message)" "WARN"
            }
            
            # Configure output directory for cache drive integration
            try {
                $OutputQueueName = Get-ConfigValue -Key "UberAgentOutputQueueName" -DefaultValue "Output Queue" -ConfigFile $ConfigFilePath
                $OutputDirectory = Get-ConfigValue -Key "UberAgentOutputDirectory" -DefaultValue "D:\Logs\uberAgent\$OutputQueueName" -ConfigFile $ConfigFilePath
                
                # Ensure output directory exists on cache drive
                if (-not (Test-Path $OutputDirectory)) {
                    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                    Write-Log "Created UberAgent output directory: $OutputDirectory" "SUCCESS"
                    $Results.OutputDirectoryConfigured = $true
                } else {
                    Write-Log "UberAgent output directory already exists: $OutputDirectory" "INFO"
                    $Results.OutputDirectoryConfigured = $true
                }
                $Results.PostInstallSteps += "Output directory configured on cache drive"
            }
            catch {
                $ErrorMsg = "Failed to configure UberAgent output directory: $($_.Exception.Message)"
                Write-Log $ErrorMsg "WARN"
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
        
        # Restore original confirmation preference
        $ConfirmPreference = $OriginalConfirmPreference
        return $Results
    }
    catch {
        # Restore original confirmation preference on error
        $ConfirmPreference = $OriginalConfirmPreference
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
    param(
        [Parameter(Mandatory=$false)]
        [string]$TADDMPath = "C:\IBM\TADDM\nonadmin_scripts\install.bat",
        
        [Parameter(Mandatory=$false)]
        [switch]$CreateGroupIfMissing
    )
    
    try {
        Write-Log "Configuring IBM TADDM installation..."
        
        $Results = @{
            OverallSuccess = $false
            Skipped = $false
            InstallBatFound = $false
            InstallBatExecuted = $false
            PermissionsConfigured = $false
            Error = $null
        }
        
        # Use the provided TADDMPath or default location
        $LocalInstallBat = if ([string]::IsNullOrEmpty($TADDMPath)) { "C:\IBM\TADDM\nonadmin_scripts\install.bat" } else { $TADDMPath }
        
        if (Test-Path $LocalInstallBat) {
            Write-Log "Found local TADDM install.bat: $LocalInstallBat" "SUCCESS"
            $Results.InstallBatFound = $true
            
            # Execute the install.bat
            Write-Log "Executing TADDM install.bat for non-administrator configuration..."
            try {
                $InstallProcess = Start-Process -FilePath $LocalInstallBat -Wait -PassThru -WorkingDirectory "C:\IBM\TADDM\nonadmin_scripts"
                
                if ($InstallProcess.ExitCode -eq 0) {
                    Write-Log "TADDM install.bat executed successfully" "SUCCESS"
                    $Results.InstallBatExecuted = $true
                    $Results.OverallSuccess = $true
                } else {
                    Write-Log "TADDM install.bat failed with exit code: $($InstallProcess.ExitCode)" "ERROR"
                    $Results.Error = "Install.bat failed with exit code: $($InstallProcess.ExitCode)"
                }
            }
            catch {
                Write-Log "Failed to execute TADDM install.bat: $($_.Exception.Message)" "ERROR"
                $Results.Error = "Failed to execute install.bat: $($_.Exception.Message)"
            }
        }
        else {
            Write-Log "Local TADDM install.bat not found at: $LocalInstallBat" "WARN"
            
            # Fallback to basic permission setup if install.bat not found
            $TADDMInstallPath = "C:\Program Files\IBM\TADDM"
            if (Test-Path $TADDMInstallPath) {
                Write-Log "Configuring basic TADDM permissions as fallback..."
                $Acl = Get-Acl $TADDMInstallPath
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")
                $Acl.SetAccessRule($AccessRule)
                Set-Acl -Path $TADDMInstallPath -AclObject $Acl
                Write-Log "Basic TADDM permissions configured" "SUCCESS"
                $Results.PermissionsConfigured = $true
                $Results.OverallSuccess = $true
            } else {
                Write-Log "TADDM installation not found - skipping configuration" "INFO"
                $Results.Skipped = $true
                $Results.OverallSuccess = $true
            }
        }
        
        return $Results
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
        [PSCredential]$Credential,
        [string]$ConfigFilePath = "$PSScriptRoot\CitrixConfig.txt"
    )
    
    try {
        # Get OU configuration if available
        $OrganizationalUnit = Get-ConfigValue -Key "OrganizationalUnit" -DefaultValue "" -ConfigFile $ConfigFilePath
        
        if (![string]::IsNullOrWhiteSpace($OrganizationalUnit)) {
            Write-Log "Joining domain: $DomainName with OU: $OrganizationalUnit"
            Add-Computer -DomainName $DomainName -OUPath $OrganizationalUnit -Credential $Credential -Force
        } else {
            Write-Log "Joining domain: $DomainName (using default computer container)"
            Add-Computer -DomainName $DomainName -Credential $Credential -Force
        }
        
        Write-Log "Domain join completed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to join domain: $($_.Exception.Message)" "ERROR"
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
                $ScriptOrderArray = @()
                for ($i = 0; $i -lt $ScriptIndex; $i++) {
                    $ScriptOrderArray += $i.ToString()
                }
                Set-ItemProperty -Path $StartupRegPath -Name "PSScriptOrder" -Value $ScriptOrderArray -Type MultiString
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
                $ScriptOrderArray = @()
                for ($i = 0; $i -lt $ScriptIndex; $i++) {
                    $ScriptOrderArray += $i.ToString()
                }
                Set-ItemProperty -Path $ShutdownRegPath -Name "PSScriptOrder" -Value $ScriptOrderArray -Type MultiString
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

function Clear-WindowsEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeLogs = @("Security"),
        
        [Parameter(Mandatory=$false)]
        [switch]$ClearAll
    )
    
    try {
        Write-Log "Starting Windows Event Logs cleanup for VDI template preparation..." "INFO"
        
        $EventLogResults = @{
            Success = $false
            TotalLogsFound = 0
            LogsCleared = 0
            LogsSkipped = 0
            LogsFailed = 0
            ClearedLogs = @()
            SkippedLogs = @()
            FailedLogs = @()
            ExecutionTime = 0
        }
        
        $StartTime = Get-Date
        
        # Get all Windows Event Logs
        Write-Log "Enumerating Windows Event Logs..." "INFO"
        $AllEventLogs = @()
        
        try {
            # Method 1: Try using Get-WinEvent (Windows Vista+)
            $AllEventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }
            Write-Log "Found $($AllEventLogs.Count) event logs with records using Get-WinEvent" "INFO"
        }
        catch {
            Write-Log "Get-WinEvent method failed, trying Get-EventLog..." "WARN"
            
            # Method 2: Fallback to Get-EventLog (older method)
            try {
                $ClassicLogs = Get-EventLog -List | Where-Object { $_.Entries.Count -gt 0 }
                $AllEventLogs = $ClassicLogs | ForEach-Object { 
                    [PSCustomObject]@{
                        LogName = $_.Log
                        RecordCount = $_.Entries.Count
                        LogType = "Classic"
                    }
                }
                Write-Log "Found $($AllEventLogs.Count) classic event logs using Get-EventLog" "INFO"
            }
            catch {
                Write-Log "Both Get-WinEvent and Get-EventLog methods failed" "ERROR"
                throw "Unable to enumerate event logs"
            }
        }
        
        $EventLogResults.TotalLogsFound = $AllEventLogs.Count
        
        if ($AllEventLogs.Count -eq 0) {
            Write-Log "No event logs found or all logs are empty" "INFO"
            $EventLogResults.Success = $true
            return $EventLogResults
        }
        
        # Process each event log
        foreach ($EventLog in $AllEventLogs) {
            $LogName = $EventLog.LogName
            $RecordCount = $EventLog.RecordCount
            
            # Check if log should be excluded
            $ShouldSkip = $false
            if (!$ClearAll) {
                foreach ($ExcludePattern in $ExcludeLogs) {
                    if ($LogName -like "*$ExcludePattern*") {
                        $ShouldSkip = $true
                        Write-Log "Skipping protected log: $LogName" "INFO"
                        $EventLogResults.LogsSkipped++
                        $EventLogResults.SkippedLogs += $LogName
                        break
                    }
                }
            }
            
            if ($ShouldSkip) {
                continue
            }
            
            # Attempt to clear the event log
            try {
                Write-Log "Clearing event log: $LogName ($RecordCount records)" "INFO"
                
                # Method 1: Try wevtutil (most reliable)
                $WevtutilResult = Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl", "`"$LogName`"" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
                
                if ($WevtutilResult.ExitCode -eq 0) {
                    Write-Log "Successfully cleared $LogName using wevtutil" "SUCCESS"
                    $EventLogResults.LogsCleared++
                    $EventLogResults.ClearedLogs += "$LogName ($RecordCount records)"
                                        }
               else {
                   # Method 2: Try PowerShell cmdlets
                   try {
                       if ($EventLog.LogType -eq "Classic") {
                           Clear-EventLog -LogName $LogName -ErrorAction Stop
                       }
                       else {
                           # For newer logs, try alternative approach
                           Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction SilentlyContinue | Out-Null
                           wevtutil cl "`"$LogName`""
                       }
                       
                       Write-Log "Successfully cleared $LogName using PowerShell cmdlets" "SUCCESS"
                       $EventLogResults.LogsCleared++
                       $EventLogResults.ClearedLogs += "$LogName ($RecordCount records)"
                   }
                   catch {
                       throw "PowerShell cmdlet method failed: $($_.Exception.Message)"
                   }
               }
           }
           catch {
               $ErrorMsg = "Failed to clear log '$LogName': $($_.Exception.Message)"
               Write-Log $ErrorMsg "WARN"
               $EventLogResults.LogsFailed++
               $EventLogResults.FailedLogs += $ErrorMsg
           }
       }
       
       $EndTime = Get-Date
       $EventLogResults.ExecutionTime = ($EndTime - $StartTime).TotalSeconds
       
       # Summary logging
       Write-Log "Event log cleanup completed in $($EventLogResults.ExecutionTime.ToString('F2')) seconds" "INFO"
       Write-Log "Total logs processed: $($EventLogResults.TotalLogsFound)" "INFO"
       Write-Log "Logs successfully cleared: $($EventLogResults.LogsCleared)" "SUCCESS"
       Write-Log "Logs skipped (protected): $($EventLogResults.LogsSkipped)" "INFO"
       
       if ($EventLogResults.LogsFailed -gt 0) {
           Write-Log "Logs failed to clear: $($EventLogResults.LogsFailed)" "WARN"
       }
       
       # Consider success if at least some logs were cleared and no critical failures
       if ($EventLogResults.LogsCleared -gt 0 -or ($EventLogResults.TotalLogsFound -eq $EventLogResults.LogsSkipped)) {
           $EventLogResults.Success = $true
           Write-Log "Event log cleanup completed successfully" "SUCCESS"
           Write-Log "Total logs processed: $($EventLogResults.TotalLogsFound)" "SUCCESS"
           Write-Log "Logs successfully cleared: $($EventLogResults.LogsCleared)" "SUCCESS"
           Write-Log "Logs skipped (protected): $($EventLogResults.LogsSkipped)" "INFO"
       }
       else {
           Write-Log "Event log cleanup completed with issues" "WARN"
       }
       
       return $EventLogResults
   }
   catch {
       Write-Log "Critical error in event log cleanup: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           TotalLogsFound = 0
           LogsCleared = 0
           LogsSkipped = 0
           LogsFailed = 1
           ClearedLogs = @()
           SkippedLogs = @()
           FailedLogs = @("Critical error: $($_.Exception.Message)")
           ExecutionTime = 0
       }
   }
}

function Start-SystemDriveDefragmentation {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$DriveLetter = "C",
       
       [Parameter(Mandatory=$false)]
       [switch]$AnalyzeOnly,
       
       [Parameter(Mandatory=$false)]
       [int]$TimeoutMinutes = 45
   )
   
   try {
       Write-Log "Starting optional system drive defragmentation for template optimization..." "INFO"
       Write-Log "Note: This operation may be skipped in virtualized environments due to volume service conflicts" "INFO"
       
       $DefragResults = @{
           Success = $false
           DriveAnalyzed = $DriveLetter
           DefragmentationPerformed = $false
           AnalysisOnly = $AnalyzeOnly.IsPresent
           FragmentationBefore = 0
           FragmentationAfter = 0
           FreeSpaceConsolidated = $false
           ExecutionTime = 0
           Method = ""
           Errors = @()
           Details = @()
       }
       
       $StartTime = Get-Date
       $DriveToProcess = "${DriveLetter}:"
       
       # Validate drive exists
       if (-not (Test-Path $DriveToProcess)) {
           throw "Drive $DriveToProcess does not exist or is not accessible"
       }
       
       Write-Log "Processing drive: $DriveToProcess" "INFO"
       
       # Get initial drive information
       try {
           $DriveInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$DriveToProcess'"
           $TotalSizeGB = [Math]::Round($DriveInfo.Size / 1GB, 2)
           $FreeSpaceGB = [Math]::Round($DriveInfo.FreeSpace / 1GB, 2)
           $UsedSpaceGB = $TotalSizeGB - $FreeSpaceGB
           
           Write-Log "Drive size: $TotalSizeGB GB, Used: $UsedSpaceGB GB, Free: $FreeSpaceGB GB" "INFO"
           $DefragResults.Details += "Initial drive analysis: $TotalSizeGB GB total, $FreeSpaceGB GB free"
       }
       catch {
           Write-Log "Could not retrieve initial drive information: $($_.Exception.Message)" "WARN"
       }
       
       # PRIORITY: Use PowerShell Optimize-Volume with proper waiting for better performance
       Write-Log "Using PowerShell Optimize-Volume with conflict resolution for optimal performance..." "INFO"
       
       try {
           # Comprehensive detection and waiting for existing operations
           Write-Log "Checking for active volume optimization operations..." "INFO"
           
           $MaxWaitMinutes = 15
           $WaitStartTime = Get-Date
           $OperationDetected = $true
           
           while ($OperationDetected -and ((Get-Date) - $WaitStartTime).TotalMinutes -lt $MaxWaitMinutes) {
               $OperationDetected = $false
               
               # Check for defrag processes
               $DefragProcesses = Get-Process -Name "defrag" -ErrorAction SilentlyContinue
               if ($DefragProcesses) {
                   $OperationDetected = $true
                   Write-Log "Found active defrag.exe processes, waiting for completion..." "INFO"
               }
               
               # Check for volume optimization using WMI
               try {
                   $VolumeOptJobs = Get-WmiOrCimInstance -ClassName Win32_Process -Filter "CommandLine LIKE '%Optimize-Volume%' OR CommandLine LIKE '%StorageWMI%'" -ErrorAction SilentlyContinue
                   if ($VolumeOptJobs) {
                       $OperationDetected = $true
                       Write-Log "Found active volume optimization jobs, waiting for completion..." "INFO"
                   }
               } catch { }
               
               # Test volume accessibility directly
               try {
                   $TestResult = Start-Process -FilePath "defrag.exe" -ArgumentList "$DriveToProcess", "/A" -Wait -PassThru -NoNewWindow -ErrorAction Stop
                   if ($TestResult.ExitCode -ne 0) {
                       # If analysis fails, volume might be locked
                       $OperationDetected = $true
                       Write-Log "Volume appears locked by another operation, waiting..." "INFO"
                   }
               } catch { }
               
               if ($OperationDetected) {
                   $ElapsedMinutes = ((Get-Date) - $WaitStartTime).TotalMinutes
                   Write-Log "Waiting for operations to complete... ($($ElapsedMinutes.ToString('F1')) minutes elapsed)" "INFO"
                   Start-Sleep -Seconds 30
               }
           }
           
           if ($OperationDetected) {
               Write-Log "Still detecting operations after $MaxWaitMinutes minutes - proceeding with caution" "WARN"
               # Force terminate any remaining defrag processes
               $RemainingDefrag = Get-Process -Name "defrag" -ErrorAction SilentlyContinue
               if ($RemainingDefrag) {
                   Write-Log "Force terminating remaining defrag processes..." "WARN"
                   $RemainingDefrag | Stop-Process -Force -ErrorAction SilentlyContinue
                   Start-Sleep -Seconds 10
               }
           } else {
               Write-Log "No active volume operations detected - proceeding with defragmentation" "SUCCESS"
           }
           
           if ($AnalyzeOnly) {
               Write-Log "Running fast analysis using Optimize-Volume..." "INFO"
               try {
                   Optimize-Volume -DriveLetter $DriveLetter -Analyze -Verbose
                   $DefragResults.Success = $true
                   $DefragResults.Method = "Optimize-Volume (Analysis Only)"
                   $DefragResults.AnalysisPerformed = $true
                   Write-Log "Drive analysis completed successfully" "SUCCESS"
               }
               catch {
                   Write-Log "Analysis failed: $($_.Exception.Message)" "WARN"
                   $DefragResults.Success = $false
                   $DefragResults.Errors += "Analysis failed: $($_.Exception.Message)"
               }
           }
           else {
               Write-Log "Starting optimized defragmentation using fast PowerShell methods..." "INFO"
               Write-Log "Using ReTrim for SSD optimization and free space consolidation" "INFO"
               
               try {
                   # Method 1: Fast ReTrim operation (fastest for SSDs and modern drives)
                   Write-Log "Attempting fast ReTrim operation..." "INFO"
                   Optimize-Volume -DriveLetter $DriveLetter -ReTrim -Verbose
                   
                   Write-Log "ReTrim completed successfully - excellent for VDI environments" "SUCCESS"
                   $DefragResults.Success = $true
                   $DefragResults.DefragmentationPerformed = $true
                   $DefragResults.Method = "Optimize-Volume (ReTrim - Fast SSD Optimization)"
                   $DefragResults.FreeSpaceConsolidated = $true
               }
               catch {
                   Write-Log "ReTrim failed: $($_.Exception.Message), trying standard defrag..." "WARN"
                   
                   try {
                       # Method 2: Standard defragmentation as fallback
                       Write-Log "Attempting standard defragmentation..." "INFO"
                       Start-Sleep -Seconds 5  # Brief pause between operations
                       Optimize-Volume -DriveLetter $DriveLetter -Defrag -Verbose
                       
                       Write-Log "Standard defragmentation completed successfully" "SUCCESS"
                       $DefragResults.Success = $true
                       $DefragResults.DefragmentationPerformed = $true
                       $DefragResults.Method = "Optimize-Volume (Standard Defrag)"
                       $DefragResults.FreeSpaceConsolidated = $true
                   }
                   catch {
                       throw "Both ReTrim and standard defrag failed: $($_.Exception.Message)"
                   }
               }
           }
       }
       catch {
           Write-Log "PowerShell optimization methods failed: $($_.Exception.Message)" "WARN"
           $DefragResults.Errors += "PowerShell methods failed: $($_.Exception.Message)"
           
           # Fallback to defrag.exe only if PowerShell completely fails
           try {
               Write-Log "Attempting defrag.exe fallback for compatibility..." "INFO"
               
               if ($AnalyzeOnly) {
                   $AnalysisProcess = Start-Process -FilePath "defrag.exe" -ArgumentList "$DriveToProcess", "/A" -Wait -PassThru -NoNewWindow
                   if ($AnalysisProcess.ExitCode -eq 0) {
                       $DefragResults.Success = $true
                       $DefragResults.Method = "defrag.exe (Analysis Fallback)"
                       Write-Log "Fallback analysis completed" "SUCCESS"
                   }
               }
               else {
                   # Use faster /D (basic defrag) instead of slow /X
                   $DefragProcess = Start-Process -FilePath "defrag.exe" -ArgumentList "$DriveToProcess", "/D" -Wait -PassThru -NoNewWindow
                   if ($DefragProcess.ExitCode -eq 0) {
                       $DefragResults.Success = $true
                       $DefragResults.DefragmentationPerformed = $true
                       $DefragResults.Method = "defrag.exe (Basic Defrag Fallback)"
                       Write-Log "Fallback defragmentation completed" "SUCCESS"
                   }
               }
           }
           catch {
               Write-Log "All defragmentation methods failed - continuing without optimization" "WARN"
               $DefragResults.Success = $false
               $DefragResults.Method = "Skipped due to conflicts"
           }
       }
       
       # Get post-defragmentation drive information
       if ($DefragResults.Success -and $DefragResults.DefragmentationPerformed) {
           try {
               Start-Sleep -Seconds 5  # Allow file system to settle
               $PostDefragInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$DriveToProcess'"
               $PostFreeSpaceGB = [Math]::Round($PostDefragInfo.FreeSpace / 1GB, 2)
               
               Write-Log "Post-defragmentation free space: $PostFreeSpaceGB GB" "INFO"
               $DefragResults.Details += "Post-defrag analysis: $PostFreeSpaceGB GB free space"
               
               if ($PostFreeSpaceGB -gt $FreeSpaceGB) {
                   $SpaceReclaimed = $PostFreeSpaceGB - $FreeSpaceGB
                   Write-Log "Space reclaimed through defragmentation: $SpaceReclaimed GB" "SUCCESS"
                   $DefragResults.Details += "Space reclaimed: $SpaceReclaimed GB"
               }
           }
           catch {
               Write-Log "Could not retrieve post-defragmentation drive information: $($_.Exception.Message)" "WARN"
           }
       }
       
       $EndTime = Get-Date
       $DefragResults.ExecutionTime = ($EndTime - $StartTime).TotalMinutes
       
       # Summary logging
       $OperationType = if ($DefragResults.AnalysisOnly) { "Analysis" } else { "Defragmentation" }
       Write-Log "$OperationType completed in $($DefragResults.ExecutionTime.ToString('F2')) minutes" "INFO"
       Write-Log "Method used: $($DefragResults.Method)" "INFO"
       
       if ($DefragResults.Success) {
           if ($DefragResults.DefragmentationPerformed) {
               Write-Log "System drive optimized for VDI template performance" "SUCCESS"
           }
           else {
               Write-Log "Drive analysis completed successfully" "SUCCESS"
           }
       }
       
       return $DefragResults
   }
   catch {
       Write-Log "Critical error in system drive defragmentation: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           DriveAnalyzed = $DriveLetter
           DefragmentationPerformed = $false
           AnalysisOnly = $AnalyzeOnly.IsPresent
           FragmentationBefore = 0
           FragmentationAfter = 0
           FreeSpaceConsolidated = $false
           ExecutionTime = 0
           Method = "Failed"
           Errors = @("Critical error: $($_.Exception.Message)")
           Details = @()
       }
   }
}

function Remove-GhostDevices {
   [CmdletBinding()]
   param()
   
   try {
       Write-Log "Starting ghost device removal for template optimization..." "INFO"
       
       $GhostDeviceResults = @{
           Success = $false
           TotalDevicesFound = 0
           GhostDevicesRemoved = 0
           DevicesFailedToRemove = 0
           GhostDevicesList = @()
           Errors = @()
           ExecutionTime = 0
       }
       
       $StartTime = Get-Date
       
       # Check if DevCon utility is available (optional enhancement)
       $DevConPath = ""
       $DevConLocations = @(
           "${env:ProgramFiles(x86)}\Windows Kits\10\Tools\x64\devcon.exe",
           "${env:ProgramFiles}\Windows Kits\10\Tools\x64\devcon.exe",
           "C:\Windows\System32\devcon.exe",
           ".\devcon.exe"
       )
       
       foreach ($Location in $DevConLocations) {
           if (Test-Path $Location) {
               $DevConPath = $Location
               Write-Log "DevCon utility found at: $DevConPath" "INFO"
               break
           }
       }
       
       if ([string]::IsNullOrEmpty($DevConPath)) {
           Write-Log "DevCon utility not found - using PowerShell WMI method for ghost device removal" "INFO"
       }
       
       # Method 1: Use DevCon if available (more reliable)
       if (![string]::IsNullOrEmpty($DevConPath)) {
           try {
               Write-Log "Using DevCon utility to remove ghost devices..." "INFO"
               
               # Get list of all devices including hidden/ghost devices
               $DevConOutput = & $DevConPath findall "*" 2>&1
               
               if ($LASTEXITCODE -eq 0) {
                   $AllDevices = $DevConOutput | Where-Object { $_ -match "^[A-Z0-9\\]+" }
                   $GhostDeviceResults.TotalDevicesFound = $AllDevices.Count
                   Write-Log "Found $($AllDevices.Count) total devices" "INFO"
                   
                   # Remove ghost devices (devices not currently present)
                   $RemoveOutput = & $DevConPath remove "@*" 2>&1
                   
                   if ($LASTEXITCODE -eq 0) {
                       $RemovedCount = ($RemoveOutput | Select-String "removed" | Measure-Object).Count
                       $GhostDeviceResults.GhostDevicesRemoved = $RemovedCount
                       Write-Log "Successfully removed $RemovedCount ghost devices using DevCon" "SUCCESS"
                       $GhostDeviceResults.Success = $true
                   }
                   else {
                       Write-Log "DevCon remove operation failed with exit code: $LASTEXITCODE" "WARN"
                       $GhostDeviceResults.Errors += "DevCon remove failed: $RemoveOutput"
                   }
               }
               else {
                   Write-Log "DevCon findall operation failed with exit code: $LASTEXITCODE" "WARN"
                   $GhostDeviceResults.Errors += "DevCon findall failed: $DevConOutput"
               }
           }
           catch {
               Write-Log "Error using DevCon utility: $($_.Exception.Message)" "ERROR"
               $GhostDeviceResults.Errors += "DevCon exception: $($_.Exception.Message)"
           }
       }
       
       # Method 2: PowerShell WMI approach (fallback or primary if DevCon unavailable)
       if (!$GhostDeviceResults.Success) {
           Write-Log "Using PowerShell WMI method to identify and remove ghost devices..." "INFO"
           
           try {
               # Set environment variable to show hidden devices
               $env:DEVMGR_SHOW_NONPRESENT_DEVICES = "1"
               
               # Get all PnP devices including non-present (ghost) devices
               $AllPnPDevices = Get-WmiOrCimInstance -ClassName Win32_PnPEntity
               $GhostDeviceResults.TotalDevicesFound = $AllPnPDevices.Count
               
               # Filter for ghost devices (ConfigManagerErrorCode 22 = device disabled/not present)
               $GhostDevices = $AllPnPDevices | Where-Object { 
                   $_.ConfigManagerErrorCode -eq 22 -or 
                   $_.Status -eq "Unknown" -or 
                   ($_.Present -eq $false) 
               }
               
               Write-Log "Found $($GhostDevices.Count) potential ghost devices out of $($AllPnPDevices.Count) total devices" "INFO"
               
               if ($GhostDevices.Count -gt 0) {
                   $RemovalCount = 0
                   $FailureCount = 0
                   
                   foreach ($Device in $GhostDevices) {
                       try {
                           # Skip critical system devices
                           $SkipDevice = $false
                           $CriticalDeviceTypes = @(
                               "System devices",
                               "Computer",
                               "Processors",
                               "ACPI",
                               "System board",
                               "Motherboard resources"
                           )
                           
                           foreach ($CriticalType in $CriticalDeviceTypes) {
                               if ($Device.Name -like "*$CriticalType*" -or $Device.Description -like "*$CriticalType*") {
                                   $SkipDevice = $true
                                   break
                               }
                           }
                           
                           if ($SkipDevice) {
                               Write-Log "Skipping critical device: $($Device.Name)" "INFO"
                               continue
                           }
                           
                           # Attempt to remove the ghost device
                           $DeviceInfo = @{
                               Name = $Device.Name
                               DeviceID = $Device.DeviceID
                               Description = $Device.Description
                               Status = $Device.Status
                           }
                           
                           $GhostDeviceResults.GhostDevicesList += $DeviceInfo
                           
                           # Use pnputil command instead of WMI methods to avoid compatibility issues
                           $DeviceInstanceId = $Device.PNPDeviceID
                           if ($DeviceInstanceId) {
                               & pnputil /remove-device $DeviceInstanceId /uninstall 2>$null
                               $RemovalCount++
                               Write-Log "Removed ghost device via pnputil: $($Device.Name)" "SUCCESS"
                           } else {
                               Write-Log "Skipped device without PNP ID: $($Device.Name)" "INFO"
                           }
                       }
                       catch {
                           $FailureCount++
                           $ErrorMsg = "Failed to remove device '$($Device.Name)': $($_.Exception.Message)"
                           Write-Log $ErrorMsg "WARN"
                           $GhostDeviceResults.Errors += $ErrorMsg
                       }
                   }
                   
                   $GhostDeviceResults.GhostDevicesRemoved = $RemovalCount
                   $GhostDeviceResults.DevicesFailedToRemove = $FailureCount
                   
                   if ($RemovalCount -gt 0) {
                       Write-Log "Successfully removed $RemovalCount ghost devices" "SUCCESS"
                       $GhostDeviceResults.Success = $true
                   }
                   
                   if ($FailureCount -gt 0) {
                       Write-Log "Failed to remove $FailureCount devices" "WARN"
                   }
               }
               else {
                   Write-Log "No ghost devices found to remove" "INFO"
                   $GhostDeviceResults.Success = $true
               }
           }
           catch {
               $ErrorMsg = "Error during PowerShell ghost device removal: $($_.Exception.Message)"
               Write-Log $ErrorMsg "ERROR"
               $GhostDeviceResults.Errors += $ErrorMsg
           }
           finally {
               # Clean up environment variable
               Remove-Item Env:\DEVMGR_SHOW_NONPRESENT_DEVICES -ErrorAction SilentlyContinue
           }
       }
       
       $EndTime = Get-Date
       $GhostDeviceResults.ExecutionTime = ($EndTime - $StartTime).TotalSeconds
       
       # Summary logging
       Write-Log "Ghost device removal completed in $($GhostDeviceResults.ExecutionTime) seconds" "INFO"
       Write-Log "Total devices scanned: $($GhostDeviceResults.TotalDevicesFound)" "INFO"
       Write-Log "Ghost devices removed: $($GhostDeviceResults.GhostDevicesRemoved)" "INFO"
       
       if ($GhostDeviceResults.DevicesFailedToRemove -gt 0) {
           Write-Log "Devices failed to remove: $($GhostDeviceResults.DevicesFailedToRemove)" "WARN"
       }
       
       return $GhostDeviceResults
   }
   catch {
       Write-Log "Critical error in ghost device removal: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           TotalDevicesFound = 0
           GhostDevicesRemoved = 0
           DevicesFailedToRemove = 0
           GhostDevicesList = @()
           Errors = @("Critical error: $($_.Exception.Message)")
           ExecutionTime = 0
       }
   }
}

function Start-DotNetOptimization {
   [CmdletBinding()]
   param()
   
   try {
       Write-Log "Starting .NET Framework optimization for VDI template preparation..." "INFO"
       
       # Create optimization results object
       $OptimizationResult = @{
           Success = $false
           NgenExecuted = $false
           FrameworkVersionsOptimized = @()
           OptimizationErrors = @()
           ExecutionTime = $null
           TotalAssembliesOptimized = 0
       }
       
       $StartTime = Get-Date
       
       # Get .NET Framework installation paths
       $DotNetPaths = @()
       
       # .NET Framework 4.x paths
       $Framework4Path = "${env:WINDIR}\Microsoft.NET\Framework64\v4.0.30319"
       $Framework4x86Path = "${env:WINDIR}\Microsoft.NET\Framework\v4.0.30319"
       
       # .NET Framework 2.0/3.5 paths
       $Framework2Path = "${env:WINDIR}\Microsoft.NET\Framework64\v2.0.50727"
       $Framework2x86Path = "${env:WINDIR}\Microsoft.NET\Framework\v2.0.50727"
       
       # Check which .NET Framework versions are installed
       if (Test-Path $Framework4Path) {
           $DotNetPaths += @{ Path = $Framework4Path; Version = ".NET 4.x (x64)" }
       }
       if (Test-Path $Framework4x86Path) {
           $DotNetPaths += @{ Path = $Framework4x86Path; Version = ".NET 4.x (x86)" }
       }
       if (Test-Path $Framework2Path) {
           $DotNetPaths += @{ Path = $Framework2Path; Version = ".NET 2.0/3.5 (x64)" }
       }
       if (Test-Path $Framework2x86Path) {
           $DotNetPaths += @{ Path = $Framework2x86Path; Version = ".NET 2.0/3.5 (x86)" }
       }
       
       if ($DotNetPaths.Count -eq 0) {
           Write-Log "No .NET Framework installations found" "WARN"
           $OptimizationResult.OptimizationErrors += "No .NET Framework installations detected"
           return $OptimizationResult
       }
       
       Write-Log "Found $($DotNetPaths.Count) .NET Framework installations" "INFO"
       
       # Execute ngen.exe for each .NET Framework version
       foreach ($DotNetInfo in $DotNetPaths) {
           $NgenPath = Join-Path $DotNetInfo.Path "ngen.exe"
           
           if (Test-Path $NgenPath) {
               try {
                   Write-Log "Optimizing $($DotNetInfo.Version) using ngen.exe..." "INFO"
                   
                   # Execute ngen update to optimize all installed assemblies
                   $NgenProcess = Start-Process -FilePath $NgenPath -ArgumentList "update" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\ngen_output.txt" -RedirectStandardError "$env:TEMP\ngen_error.txt"
                   
                   if ($NgenProcess.ExitCode -eq 0) {
                       Write-Log "$($DotNetInfo.Version) optimization completed successfully" "SUCCESS"
                       $OptimizationResult.FrameworkVersionsOptimized += $DotNetInfo.Version
                       $OptimizationResult.NgenExecuted = $true
                       
                       # Try to get assembly count from output
                       if (Test-Path "$env:TEMP\ngen_output.txt") {
                           $NgenOutput = Get-Content "$env:TEMP\ngen_output.txt" -Raw
                           if ($NgenOutput -match "(\d+) assemblies") {
                               $AssemblyCount = [int]$Matches[1]
                               $OptimizationResult.TotalAssembliesOptimized += $AssemblyCount
                               Write-Log "Optimized $AssemblyCount assemblies for $($DotNetInfo.Version)" "INFO"
                           }
                       }
                   }
                   else {
                       $ErrorMessage = "ngen.exe failed for $($DotNetInfo.Version) with exit code: $($NgenProcess.ExitCode)"
                       Write-Log $ErrorMessage "ERROR"
                       $OptimizationResult.OptimizationErrors += $ErrorMessage
                       
                       # Log error details if available
                       if (Test-Path "$env:TEMP\ngen_error.txt") {
                           $NgenError = Get-Content "$env:TEMP\ngen_error.txt" -Raw
                           if (![string]::IsNullOrWhiteSpace($NgenError)) {
                               Write-Log "ngen.exe error details: $NgenError" "ERROR"
                           }
                       }
                   }
               }
               catch {
                   $ErrorMessage = "Failed to execute ngen.exe for $($DotNetInfo.Version): $($_.Exception.Message)"
                   Write-Log $ErrorMessage "ERROR"
                   $OptimizationResult.OptimizationErrors += $ErrorMessage
               }
               finally {
                   # Cleanup temporary files
                   if (Test-Path "$env:TEMP\ngen_output.txt") { Remove-Item "$env:TEMP\ngen_output.txt" -Force -ErrorAction SilentlyContinue }
                   if (Test-Path "$env:TEMP\ngen_error.txt") { Remove-Item "$env:TEMP\ngen_error.txt" -Force -ErrorAction SilentlyContinue }
               }
           }
           else {
               $ErrorMessage = "ngen.exe not found at: $NgenPath"
               Write-Log $ErrorMessage "WARN"
               $OptimizationResult.OptimizationErrors += $ErrorMessage
           }
       }
       
       $EndTime = Get-Date
       $OptimizationResult.ExecutionTime = $EndTime - $StartTime
       
       # Determine overall success
       if ($OptimizationResult.FrameworkVersionsOptimized.Count -gt 0) {
           $OptimizationResult.Success = $true
           Write-Log ".NET Framework optimization completed successfully" "SUCCESS"
           Write-Log "Optimized frameworks: $($OptimizationResult.FrameworkVersionsOptimized -join ', ')" "SUCCESS"
           Write-Log "Total assemblies optimized: $($OptimizationResult.TotalAssembliesOptimized)" "SUCCESS"
           Write-Log "Optimization execution time: $($OptimizationResult.ExecutionTime.TotalMinutes.ToString('F2')) minutes" "INFO"
       }
       else {
           Write-Log ".NET Framework optimization failed for all frameworks" "ERROR"
           $OptimizationResult.Success = $false
       }
       
       return $OptimizationResult
   }
   catch {
       Write-Log "ERROR: .NET Framework optimization failed: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           NgenExecuted = $false
           FrameworkVersionsOptimized = @()
           OptimizationErrors = @("Critical error: $($_.Exception.Message)")
           ExecutionTime = $null
           TotalAssembliesOptimized = 0
       }
   }
}

function Remove-VirtualCacheDrive {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting virtual cache drive removal..." "INFO"
       
       $Results = @{
           Success = $false
           VHDXDismounted = $false
           VHDXRemoved = $false
           DriveRemoved = $false
           Errors = @()
       }
       
       # Read configuration
       $VHDXPath = Get-ConfigValue -Key "VirtualCacheDrivePath" -DefaultValue "C:\Temp\DCACHE.VHDX" -ConfigFile $ConfigFilePath
       $DriveLetter = Get-ConfigValue -Key "VirtualCacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
       
       Write-Log "Virtual cache drive removal configuration:" "INFO"
       Write-Log "VHDX Path: $VHDXPath" "INFO"
       Write-Log "Drive Letter: ${DriveLetter}" "INFO"
       
       # Check if VHDX file exists
       if (-not (Test-Path $VHDXPath)) {
           Write-Log "VHDX file not found: $VHDXPath" "INFO"
           $Results.Success = $true
           return $Results
       }
       
       # Try Hyper-V method first
       try {
           Write-Log "Attempting Hyper-V dismount method..." "INFO"
           $DiskImage = Get-DiskImage -ImagePath $VHDXPath -ErrorAction SilentlyContinue
           
           if ($DiskImage -and $DiskImage.Attached) {
               Dismount-DiskImage -ImagePath $VHDXPath | Out-Null
               Write-Log "VHDX file dismounted successfully using Hyper-V method" "SUCCESS"
               $Results.VHDXDismounted = $true
               $Results.DriveRemoved = $true
           } else {
               Write-Log "VHDX file was not mounted via Hyper-V" "INFO"
               $Results.VHDXDismounted = $true
               $Results.DriveRemoved = $true
           }
       }
       catch {
           Write-Log "Hyper-V dismount failed, trying diskpart method..." "WARN"
           
           # Use diskpart to detach virtual disk
           try {
               $DiskPartScript = @"
select vdisk file="$VHDXPath"
detach vdisk
exit
"@
               
               $TempScript = "$env:TEMP\remove_virtual_cache.txt"
               $DiskPartScript | Out-File -FilePath $TempScript -Encoding ASCII
               
               Write-Log "Executing diskpart script for virtual disk removal..." "INFO"
               $DiskPartProcess = Start-Process -FilePath "diskpart.exe" -ArgumentList "/s `"$TempScript`"" -Wait -PassThru -NoNewWindow
               
               Remove-Item $TempScript -Force -ErrorAction SilentlyContinue
               
               if ($DiskPartProcess.ExitCode -eq 0) {
                   Write-Log "Virtual disk detached successfully using diskpart" "SUCCESS"
                   $Results.VHDXDismounted = $true
                   $Results.DriveRemoved = $true
               } else {
                   Write-Log "Diskpart detach failed with exit code: $($DiskPartProcess.ExitCode)" "WARN"
                   $Results.Errors += "Diskpart detach failed"
               }
           }
           catch {
               $ErrorMsg = "Diskpart dismount failed: $($_.Exception.Message)"
               Write-Log $ErrorMsg "WARN"
               $Results.Errors += $ErrorMsg
           }
       }
       
       # Remove the VHDX file
       try {
           Write-Log "Removing VHDX file..." "INFO"
           Remove-Item $VHDXPath -Force
           Write-Log "VHDX file removed successfully" "SUCCESS"
           $Results.VHDXRemoved = $true
           $Results.Success = $true
       }
       catch {
           $ErrorMsg = "Failed to remove VHDX file: $($_.Exception.Message)"
           Write-Log $ErrorMsg "ERROR"
           $Results.Errors += $ErrorMsg
       }
       
       return $Results
   }
   catch {
       Write-Log "Critical error in virtual cache drive removal: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           VHDXDismounted = $false
           VHDXRemoved = $false
           DriveRemoved = $false
           Errors = @("Critical error: $($_.Exception.Message)")
       }
   }
}

function Remove-PasswordAgeRegistryKey {
   <#
   .SYNOPSIS
       Removes password age registry key if it exists
       
   .DESCRIPTION
       Checks for and removes passwordAge key from the specified registry location
       
   .OUTPUTS
       Returns boolean indicating if key was found and removed
   #>
   
   try {
       $RegistryPath = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
       $KeyName = "passwordAge"
       
       if (Test-Path $RegistryPath) {
           $KeyExists = Get-ItemProperty -Path $RegistryPath -Name $KeyName -ErrorAction SilentlyContinue
           if ($KeyExists) {
               Remove-ItemProperty -Path $RegistryPath -Name $KeyName -Force
               return $true  # Key was found and removed
           }
       }
       
       return $false  # Key was not found
   }
   catch {
       Write-Warning "Failed to remove password age registry key: $($_.Exception.Message)"
       return $false
   }
}

function Set-IBMTADDMSCMPermissions {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$SCMPath,
       
       [Parameter(Mandatory=$false)]
       [string]$ConfigFilePath = "CitrixConfig.txt"
   )
   
   try {
       Write-Log "Starting IBM TADDM Service Control Manager permissions configuration" "INFO"
       
       $Result = @{
           Success = $false
           CurrentSDDLGenerated = $false
           SDDLComparisonCompleted = $false
           SCMPermissionsConfigured = $false
           Differences = @()
           Errors = @()
       }
       
       # Validate SCM path exists
       if (-not (Test-Path $SCMPath)) {
           $ErrorMsg = "IBM TADDM SCM path not found: $SCMPath"
           Write-Log $ErrorMsg "ERROR"
           $Result.Errors += $ErrorMsg
           return $Result
       }
       
       # Define file paths
       $CurrentSDDLBat = Join-Path $SCMPath "currentsddl.bat"
       $CurrentSDDLTxt = Join-Path $SCMPath "currentsddl.txt"
       $DefaultSDDLTxt = Join-Path $SCMPath "defaultsddl.txt"
       $SCMConfigBat = Join-Path $SCMPath "sc_sdset_scmanager.bat"
       
       Write-Log "IBM TADDM SCM configuration paths:" "INFO"
       Write-Log "  SCM Path: $SCMPath" "INFO"
       Write-Log "  Current SDDL Batch: $CurrentSDDLBat" "INFO"
       Write-Log "  Current SDDL Text: $CurrentSDDLTxt" "INFO"
       Write-Log "  Default SDDL Text: $DefaultSDDLTxt" "INFO"
       Write-Log "  SCM Config Batch: $SCMConfigBat" "INFO"
       
       # Step 1: Check if currentsddl.bat exists and run it
       if (Test-Path $CurrentSDDLBat) {
           Write-Log "Running IBM TADDM current SDDL detection: $CurrentSDDLBat" "INFO"
           
           try {
               # Execute currentsddl.bat to generate current SDDL
               $CurrentSDDLProcess = Start-Process -FilePath $CurrentSDDLBat -WorkingDirectory $SCMPath -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\taddm_currentsddl_output.txt" -RedirectStandardError "$env:TEMP\taddm_currentsddl_error.txt"
               
               if ($CurrentSDDLProcess.ExitCode -eq 0) {
                   Write-Log "Current SDDL detection completed successfully" "SUCCESS"
                   $Result.CurrentSDDLGenerated = $true
               } else {
                   $ErrorMsg = "Current SDDL detection failed with exit code: $($CurrentSDDLProcess.ExitCode)"
                   Write-Log $ErrorMsg "ERROR"
                   $Result.Errors += $ErrorMsg
                   
                   # Read error output for details
                   if (Test-Path "$env:TEMP\taddm_currentsddl_error.txt") {
                       $ErrorOutput = Get-Content "$env:TEMP\taddm_currentsddl_error.txt" -Raw
                       if ($ErrorOutput) {
                           Write-Log "SDDL detection error details: $ErrorOutput" "ERROR"
                           $Result.Errors += "SDDL Error: $ErrorOutput"
                       }
                   }
               }
               
               # Clean up output files
               Remove-Item "$env:TEMP\taddm_currentsddl_output.txt" -Force -ErrorAction SilentlyContinue
               Remove-Item "$env:TEMP\taddm_currentsddl_error.txt" -Force -ErrorAction SilentlyContinue
               
           } catch {
               $ErrorMsg = "Exception running current SDDL detection: $($_.Exception.Message)"
               Write-Log $ErrorMsg "ERROR"
               $Result.Errors += $ErrorMsg
           }
       } else {
           $ErrorMsg = "Current SDDL batch file not found: $CurrentSDDLBat"
           Write-Log $ErrorMsg "WARN"
           $Result.Errors += $ErrorMsg
       }
       
       # Step 2: Compare currentsddl.txt with defaultsddl.txt
       if ((Test-Path $CurrentSDDLTxt) -and (Test-Path $DefaultSDDLTxt)) {
           Write-Log "Comparing current SDDL with default SDDL configurations" "INFO"
           
           try {
               $CurrentSDDL = Get-Content $CurrentSDDLTxt -ErrorAction Stop
               $DefaultSDDL = Get-Content $DefaultSDDLTxt -ErrorAction Stop
               
               Write-Log "Current SDDL entries: $($CurrentSDDL.Count)" "INFO"
               Write-Log "Default SDDL entries: $($DefaultSDDL.Count)" "INFO"
               
               # Compare line by line
               $MaxLines = [Math]::Max($CurrentSDDL.Count, $DefaultSDDL.Count)
               $DifferenceCount = 0
               
               for ($i = 0; $i -lt $MaxLines; $i++) {
                   $CurrentLine = if ($i -lt $CurrentSDDL.Count) { $CurrentSDDL[$i] } else { "" }
                   $DefaultLine = if ($i -lt $DefaultSDDL.Count) { $DefaultSDDL[$i] } else { "" }
                   
                   if ($CurrentLine -ne $DefaultLine) {
                       $DifferenceCount++
                       $Difference = @{
                           LineNumber = $i + 1
                           Current = $CurrentLine
                           Default = $DefaultLine
                           ChangeType = if ($CurrentLine -eq "") { "Missing in Current" } elseif ($DefaultLine -eq "") { "Extra in Current" } else { "Different" }
                       }
                       $Result.Differences += $Difference
                       
                       Write-Log "SDDL Difference at line $($i + 1)" "WARN"
                       Write-Log "  Current: '$CurrentLine'" "WARN"
                       Write-Log "  Default: '$DefaultLine'" "WARN"
                       Write-Log "  Type: $($Difference.ChangeType)" "WARN"
                   }
               }
               
               if ($DifferenceCount -eq 0) {
                   Write-Log "No differences found between current and default SDDL configurations" "SUCCESS"
               } else {
                   Write-Log "Found $DifferenceCount differences between current and default SDDL configurations" "WARN"
               }
               
               $Result.SDDLComparisonCompleted = $true
               
           } catch {
               $ErrorMsg = "Failed to compare SDDL files: $($_.Exception.Message)"
               Write-Log $ErrorMsg "ERROR"
               $Result.Errors += $ErrorMsg
           }
       } else {
           $MissingFiles = @()
           if (-not (Test-Path $CurrentSDDLTxt)) { $MissingFiles += "currentsddl.txt" }
           if (-not (Test-Path $DefaultSDDLTxt)) { $MissingFiles += "defaultsddl.txt" }
           
           $ErrorMsg = "Cannot compare SDDL files - missing: $($MissingFiles -join ', ')"
           Write-Log $ErrorMsg "WARN"
           $Result.Errors += $ErrorMsg
       }
       
       # Step 3: Configure Service Control Manager permissions
       if (Test-Path $SCMConfigBat) {
           Write-Log "Configuring IBM TADDM Service Control Manager permissions: $SCMConfigBat" "INFO"
           
           try {
               # Execute sc_sdset_scmanager.bat
               $SCMConfigProcess = Start-Process -FilePath $SCMConfigBat -WorkingDirectory $SCMPath -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\taddm_scmconfig_output.txt" -RedirectStandardError "$env:TEMP\taddm_scmconfig_error.txt"
               
               if ($SCMConfigProcess.ExitCode -eq 0) {
                   Write-Log "IBM TADDM SCM permissions configured successfully" "SUCCESS"
                   $Result.SCMPermissionsConfigured = $true
               } else {
                   $ErrorMsg = "SCM permissions configuration failed with exit code: $($SCMConfigProcess.ExitCode)"
                   Write-Log $ErrorMsg "ERROR"
                   $Result.Errors += $ErrorMsg
                   
                   # Read error output for details
                   if (Test-Path "$env:TEMP\taddm_scmconfig_error.txt") {
                       $ErrorOutput = Get-Content "$env:TEMP\taddm_scmconfig_error.txt" -Raw
                       if ($ErrorOutput) {
                           Write-Log "SCM config error details: $ErrorOutput" "ERROR"
                           $Result.Errors += "SCM Config Error: $ErrorOutput"
                       }
                   }
               }
               
               # Read output for informational logging
               if (Test-Path "$env:TEMP\taddm_scmconfig_output.txt") {
                   $OutputContent = Get-Content "$env:TEMP\taddm_scmconfig_output.txt" -Raw
                   if ($OutputContent) {
                       Write-Log "SCM configuration output: $OutputContent" "INFO"
                   }
               }
               
               # Clean up output files
               Remove-Item "$env:TEMP\taddm_scmconfig_output.txt" -Force -ErrorAction SilentlyContinue
               Remove-Item "$env:TEMP\taddm_scmconfig_error.txt" -Force -ErrorAction SilentlyContinue
               
           } catch {
               $ErrorMsg = "Exception configuring SCM permissions: $($_.Exception.Message)"
               Write-Log $ErrorMsg "ERROR"
               $Result.Errors += $ErrorMsg
           }
       } else {
           $ErrorMsg = "SCM configuration batch file not found: $SCMConfigBat"
           Write-Log $ErrorMsg "ERROR"
           $Result.Errors += $ErrorMsg
       }
       
       # Determine overall success
       if ($Result.CurrentSDDLGenerated -and $Result.SDDLComparisonCompleted -and $Result.SCMPermissionsConfigured) {
           $Result.Success = $true
           Write-Log "IBM TADDM SCM permissions configuration completed successfully" "SUCCESS"
       } elseif ($Result.Errors.Count -eq 0) {
           Write-Log "IBM TADDM SCM permissions configuration completed with warnings" "WARN"
       } else {
           Write-Log "IBM TADDM SCM permissions configuration failed" "ERROR"
       }
       
       # Summary logging
       Write-Log "IBM TADDM SCM Configuration Summary:" "INFO"
       Write-Log "  Current SDDL Generated: $($Result.CurrentSDDLGenerated)" "INFO"
       Write-Log "  SDDL Comparison Completed: $($Result.SDDLComparisonCompleted)" "INFO"
       Write-Log "  Differences Found: $($Result.Differences.Count)" "INFO"
       Write-Log "  SCM Permissions Configured: $($Result.SCMPermissionsConfigured)" "INFO"
       Write-Log "  Errors Encountered: $($Result.Errors.Count)" "INFO"
       
       return $Result
       
   } catch {
       $ErrorMsg = "Critical error in IBM TADDM SCM permissions configuration: $($_.Exception.Message)"
       Write-Log $ErrorMsg "ERROR"
       return @{
           Success = $false
           CurrentSDDLGenerated = $false
           SDDLComparisonCompleted = $false
           SCMPermissionsConfigured = $false
           Differences = @()
           Errors = @($ErrorMsg)
       }
   }
}

function Test-VMwareMemoryBallooningStatus {
   <#
   .SYNOPSIS
       Tests VMware memory ballooning status and configuration
       
   .DESCRIPTION
       Checks if the system is running in a VMware environment and validates
       memory ballooning driver status and configuration
       
   .OUTPUTS
       Returns object with VMware environment detection and compliance status
   #>
   
   try {
       $Result = @{
           VMwareEnvironment = $false
           OverallCompliant = $true
           MemoryBalloonStatus = "Not Applicable"
           Issues = @()
       }
       
       # Check if running in VMware environment
       $VMwareDetected = $false
       
       # Check for VMware hardware/BIOS signatures
       try {
           $SystemInfo = Get-WmiOrCimInstance -ClassName Win32_ComputerSystem
           if ($SystemInfo.Manufacturer -like "*VMware*" -or $SystemInfo.Model -like "*VMware*") {
               $VMwareDetected = $true
           }
       }
       catch {
           # Continue with other detection methods
       }
       
       # Check for VMware services
       if (-not $VMwareDetected) {
           try {
               $VMwareServices = Get-Service -Name "*vmware*" -ErrorAction SilentlyContinue
               if ($VMwareServices) {
                   $VMwareDetected = $true
               }
           }
           catch {
               # Continue with other detection methods
           }
       }
       
       $Result.VMwareEnvironment = $VMwareDetected
       
       if ($VMwareDetected) {
           # Check memory ballooning driver status
           try {
               $BalloonService = Get-Service -Name "vmmemctl" -ErrorAction SilentlyContinue
               if ($BalloonService) {
                   if ($BalloonService.Status -eq "Running") {
                       $Result.MemoryBalloonStatus = "Active"
                       $Result.Issues += "VMware memory ballooning driver is active"
                       $Result.OverallCompliant = $false
                   } else {
                       $Result.MemoryBalloonStatus = "Disabled"
                   }
               } else {
                   $Result.MemoryBalloonStatus = "Not Installed"
               }
           }
           catch {
               $Result.MemoryBalloonStatus = "Unknown"
               $Result.Issues += "Unable to determine memory ballooning status"
           }
       }
       
       return $Result
   }
   catch {
       Write-Warning "Error checking VMware memory ballooning status: $($_.Exception.Message)"
       return @{
           VMwareEnvironment = $false
           OverallCompliant = $true
           MemoryBalloonStatus = "Error"
           Issues = @("Error during VMware detection: $($_.Exception.Message)")
       }
   }
}

function Install-UberAgent {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory=$true)]
       [string]$ConfigFilePath
   )
   
   try {
       Write-Log "Starting UberAgent installation process..." "INFO"
       
       # Get UberAgent configuration from config file
       $InstallUberAgent = [bool](Get-ConfigValue -Key "InstallUberAgent" -DefaultValue "false" -ConfigFile $ConfigFilePath)
       $UberAgentInstallerPath = Get-ConfigValue -Key "UberAgentInstallerPath" -DefaultValue "C:\Temp\UberAgent.msi" -ConfigFile $ConfigFilePath
       
       if (-not $InstallUberAgent) {
           Write-Log "UberAgent installation skipped - disabled in configuration" "INFO"
           return @{
               Success = $true
               Skipped = $true
               Error = $null
           }
       }
       
       if (-not (Test-Path $UberAgentInstallerPath)) {
           Write-Log "UberAgent installer not found: $UberAgentInstallerPath" "ERROR"
           return @{
               Success = $false
               Error = "UberAgent installer file not found: $UberAgentInstallerPath"
           }
       }
       
       # Call the Add-UberAgent function with proper configuration
       $InstallResult = Add-UberAgent -UberAgentInstallerPath $UberAgentInstallerPath -ConfigFilePath $ConfigFilePath
       
       if ($InstallResult.OverallSuccess) {
           Write-Log "UberAgent installation and configuration completed successfully" "SUCCESS"
           return @{
               Success = $true
               Error = $null
               Details = $InstallResult
           }
       } else {
           $ErrorMessage = "UberAgent installation failed"
           if ($InstallResult.Errors -and $InstallResult.Errors.Count -gt 0) {
               $ErrorMessage += ": " + ($InstallResult.Errors -join "; ")
           }
           Write-Log $ErrorMessage "ERROR"
           return @{
               Success = $false
               Error = $ErrorMessage
               Details = $InstallResult
           }
       }
   }
   catch {
       Write-Log "Critical error in UberAgent installation: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
       }
   }
}

# Export all functions explicitly
# Export ALL functions to prevent any missing function errors - Complete list from analysis
Export-ModuleMember -Function @(
   'Read-ConfigFile', 'Get-ConfigValue', 'Write-Log', 'Write-LogHeader', 'Write-LogMember', 'Start-Logging', 'Initialize-LoggingSystem', 'Get-DesktopPath', 'Get-DesktopLogPath',
   'Test-AdminPrivileges', 'Get-OSVersion', 'Get-SystemInformation', 'Test-VDAInstallation', 'Get-CitrixServices', 'Test-FileAccess', 'Set-DNSSuffix',
   'Copy-AllInstallationFiles', 'Remove-InstallationFiles', 'Mount-ISOFile', 'Dismount-ISOFile', 'Install-FromISO',
   'Install-VDAFromISO', 'Install-PVSFromISO', 'Add-WEMAgent', 'Add-UberAgent', 'Set-IBMTADDMPermissions', 'Set-IBMTADDMSCMPermissions',
   'Get-CacheDrive', 'New-CacheDrive', 'Set-PageFile', 'Clear-EventLogs', 'Disable-WindowsUpdates',
   'Set-TimeZone', 'Join-Domain', 'Set-LocalUserPassword',
   'Install-CitrixVDA', 'Install-CitrixPVSTarget', 'Install-CitrixWEMAgent', 'Install-UberAgent',
   'Install-IBMTADDMAgent', 'Start-CitrixOptimizer', 'Install-CitrixOptimizer', 'Optimize-CitrixVDI',
   'Set-RegistryValue', 'Get-RegistryValue', 'Test-RegistryPath', 'New-RegistryPath', 'Remove-RegistryValue',
   'Stop-NetBiosOverTCP', 'Stop-NetworkOffloadParameters', 'Set-SMBSettings', 'Set-CrashDumpToKernelMode',
   'Reset-RDSGracePeriod', 'Set-VDAMultipleMonitorHookKeys', 'Test-VMwareMemoryBallooningStatus',
   'New-VirtualCacheDrive', 'Test-VirtualCacheDrive', 'Remove-VirtualCacheDrive',
   'Add-CitrixVDA', 'Add-Domain', 'Add-PVSTargetDevice', 'Add-StartupShutdownScripts', 'Clear-WindowsEventLogs',
   'Copy-FileWithValidation', 'Copy-OSSpecificStartupShutdownScripts', 'Remove-DomainUserProfiles', 'Remove-GhostDevices',
   'Remove-PasswordAgeRegistryKey', 'Remove-WEMRSAKey', 'New-InstallConfig', 'Save-InstallationConfig',
   'Set-EventLogRedirection', 'Set-EventLogs', 'Set-PagefileConfiguration', 'Set-RegistryOptimizations',
   'Set-StartupShutdownScripts', 'Set-UserProfileRedirection', 'Set-UserProfilesRedirection', 'Set-WEMAgentCacheLocation',
   'Set-WindowsOptimizations', 'Set-WindowsServices', 'Show-LoadedConfiguration', 'Start-DotNetOptimization',
   'Start-DriveConfiguration', 'Start-SystemDriveDefragmentation',
   'Stop-CitrixServices', 'Test-AutomaticMaintenanceStatus', 'Test-CacheDriveRequirement', 'Test-DriveConfiguration',
   'Test-SystemOptimizations', 'Test-WEMRSACleanup', 'Test-InstallationFiles', 'Get-WmiOrCimInstance', 'Test-SafePath',
   'Invoke-WithRetry', 'Test-Configuration', 'Write-ProgressHelper', 'Test-ValidInput'
)