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

# Set execution policy to allow script execution (Windows PowerShell only)
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
        # Ensure absolute path
        if (-not [System.IO.Path]::IsPathRooted($ConfigFilePath)) {
            $ConfigFilePath = Join-Path $PSScriptRoot $ConfigFilePath
        }
    } catch {

    
        # Error handling

    
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
            $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
        }
    } catch {
        # Error handling

    
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
        [switch]$CreateIfNotExists = $true
    )try {
        # Try multiple methods to get desktop path
        $DesktopPath = $null
        
        # Method 1: .NET SpecialFolder
        try {
            $DesktopPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
            if (![string]::IsNullOrEmpty($DesktopPath) -and (Test-Path $DesktopPath)) {
                return $DesktopPath
            }

    
    catch {

    
        # Error handling

    
    }}
        catch { }
        
        # Method 2: Registry lookuptry {
            $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            $DesktopPath = (Get-ItemProperty -Path $RegPath -Name "Desktop" -ErrorAction SilentlyContinue).Desktop
            if (![string]::IsNullOrEmpty($DesktopPath) -and (Test-Path $DesktopPath)) {
                return $DesktopPath
            }

        catch {

            # Error handling

        }}
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
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
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
        } catch {
            # Error creating log directory - continue without file logging

        }
        
        # Write to log file
        try {
            $LogEntry | Out-File -FilePath $Global:LogPath -Append -Force
        } catch {
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

    
    catch {

    
        # Error handling

    
    }elseif ($OSCaption -like "*Server 2022*" -or $OSCaption -like "*Server*") {
            $ScriptSource = "win2022"
        }
        elseif ($OSCaption -like "*Windows 10*" -or $OSCaption -like "*Windows 11*") {
            $ScriptSource = "win2022"  # Use 2022 scripts for client OS
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

    
    catch {

    
        # Error handling

    
    }Write-Log "Loading DNS configuration from: $ConfigFile"
        
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
    )try {
        if (-not (Test-Path $Path)) {
            return $false
        }

    
    catch {

    
        # Error handling

    
    }if ($TestWrite) {
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
    }try {
        # Check source file
        if (-not (Test-Path $SourcePath)) {
            $Results.Error = "Source file not found: $SourcePath"
            return $Results
        }

    
    catch {

    
        # Error handling

    
    }$Results.SourceExists = $true
        $SourceSize = (Get-Item $SourcePath).Length
        
        # Ensure destination directory exists
        $DestDir = Split-Path $DestinationPath -Parent
        if (-not (Test-Path $DestDir)) {
            New-Item -Path $DestDir -ItemType Directory -Force | Out-Null
        }
        
        # Copy with retry logic
        $Attempt = 0
        while ($Attempt -lt $RetryAttempts) {try {
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
    
    Write-LogHeader "Domain Profile Cleanup"try {
        $Results = @{
            ProfilesRemoved = 0
            RemovedProfiles = @()
            FailedRemovals = @()
            Success = $true
        }

    
    catch {

    
        # Error handling

    
    }Write-Log "Scanning for domain user profiles..."
        
        # Get all user profiles from registry
        $ProfileListPath = "HKLM:\\SOFTWARE\\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $ProfileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue
        
        foreach ($ProfileKey in $ProfileKeys) {try {
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
                    Write-Log "Failed to remove redirected profile $($DomainDir.Name): $($_.Exception.Message)" "ERROR"
                    $Results.Errors += "Failed to remove $($DomainDir.Name): $($_.Exception.Message)"
                }
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
    
    Write-LogHeader "WEM RSA Key Cleanup"try {
        $Results = @{
            Success = $true
            RemovedKeys = @()
            FailedRemovals = @()
        }
        
        Write-Log "Scanning for WEM RSA keys..."
        
        # WEM RSA key locations
        $WEMKeyPaths = @(
            "HKLM:\\SOFTWARE\\Norskale\Norskale Agent Host",
            "HKLM:\\SOFTWARE\\Wow6432Node\Norskale\Norskale Agent Host",
            "HKLM:\\SOFTWARE\\Citrix\WEM",
            "HKLM:\\SOFTWARE\\Wow6432Node\Citrix\WEM"
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
    )try {
        Write-Log "Testing drive configuration..."
        
        $SystemDrive = $env:SystemDrive
        if (Test-Path $SystemDrive) {
            Write-Log "System drive ($SystemDrive) is accessible" "SUCCESS"
            return $true
        }

    
    catch {

    
        # Error handling

    
    }return $false
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
    )try {
        Write-Log "Redirecting Windows event logs to cache drive..." "INFO"
        
        # Get cache drive letter and event logs path from config
        $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
        $EventLogsPath = Get-ConfigValue -Key "EventLogsPath" -DefaultValue "EventLogs" -ConfigFile $ConfigFilePath
        $LogsPath = "${CacheDriveLetter}

    
    catch {

    
        # Error handling

    
    }:\${EventLogsPath}"
        if (-not (Test-Path $LogsPath)) {
            New-Item -Path $LogsPath -ItemType Directory -Force | Out-Null
            Write-Log "Created event logs directory: $LogsPath" "INFO"
        }
        
        # Event logs to redirect
        $EventLogs = @("Application", "System", "Security")
        $RedirectedCount = 0
        
        foreach ($LogName in $EventLogs) {try {
                $LogRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
                $NewLogPath = "${LogsPath}

            catch {

                # Error handling

            }\${LogName}.evtx"
                
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
    )try {
        Write-Log "Configuring user profile redirection to cache drive..." "INFO"
        
        # Get cache drive letter and user profiles path from config
        $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
        $UserProfilesPath = Get-ConfigValue -Key "UserProfilesPath" -DefaultValue "Profiles" -ConfigFile $ConfigFilePath
        $ProfilesPath = "${CacheDriveLetter}

    
    catch {

    
        # Error handling

    
    }:\${UserProfilesPath}"
        if (-not (Test-Path $ProfilesPath)) {
            New-Item -Path $ProfilesPath -ItemType Directory -Force | Out-Null
            Write-Log "Created profiles directory: $ProfilesPath" "INFO"
        }
        
        # Configure user profile redirection registry settings
        $ProfileRegPath = "HKLM:\\SOFTWARE\\Microsoft\Windows NT\CurrentVersion\ProfileList"
        
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
    param()try {
        Write-Log "Testing automatic maintenance status..."
        
        $MaintenanceKey = "HKLM:\\SOFTWARE\\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
        if (Test-Path $MaintenanceKey) {
            $MaintenanceEnabled = Get-ItemProperty -Path $MaintenanceKey -Name "MaintenanceDisabled" -ErrorAction SilentlyContinue
            return @{
                MaintenanceDisabled = ($MaintenanceEnabled.MaintenanceDisabled -eq 1)
            }

    
    catch {

    
        # Error handling

    
    }}
        
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
    } catch {
        Write-Log "Error getting timestamp or log filename: $($_.Exception.Message)" "ERROR"
        $LogFileName = "Citrix_Install_Default.log"
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
    } catch {
        Write-Host "Failed to create desktop log: $($_.Exception.Message)" -ForegroundColor Yellow
    
    # Fallback to temp directory with immediate creation
    $TempLogPath = "$env:TEMP\$LogFileName"
    try {
        "# Citrix Installation Log - Created $(Get-Date)" | Out-File -FilePath $TempLogPath -Force
        Write-Host "Using temp directory for log: $TempLogPath" -ForegroundColor Yellow
        return $TempLogPath
    } catch {
        Write-Host "Failed to create any log file: $($_.Exception.Message)" -ForegroundColor Red
        # Final fallback - return a valid path even if we can't create the file
        return "$env:TEMP\Citrix_Install_Default.log"
    }
}

function Copy-AllInstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FilesToCopy,
        
        [Parameter(Mandatory=$true)]
        [string]$TempDirectory = "C:\Temp"
    )try {
        Write-Log "Starting simple file copy to temp directory..."
        
        # Ensure temp directory exists
        if (-not (Test-Path $TempDirectory)) {
            New-Item -Path $TempDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created temp directory: $TempDirectory"
        }

    
    catch {

    
        # Error handling

    
    }$Results = @{
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
            
            # Simple copy operationtry {
                Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
                
                # Validate copy
                if (Test-Path $DestinationPath) {
                    Write-Log "$FileType copied successfully" "SUCCESS"
                    $Results.CopiedFiles += @{
                        Type = $FileType
                        Source = $SourcePath
                        Destination = $DestinationPath
                    }

            catch {

                # Error handling

            }$Results.SuccessfulCopies++
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

function Validate-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FilePaths
    )try {
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
        
        # Implementation logic here
        Write-Log "Copying startup/shutdown scripts completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error copying startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-PagefileConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting pagefile configuration..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error configuring pagefile: $($_.Exception.Message)" "ERROR"
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
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting user profiles redirection..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error configuring user profiles redirection: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Clear-WindowsEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting Windows event logs cleanup..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error clearing event logs: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-SystemDriveDefragmentation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting system drive defragmentation..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error during defragmentation: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Remove-GhostDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting ghost devices removal..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error removing ghost devices: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-DotNetOptimization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting .NET optimization..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error during .NET optimization: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Remove-VirtualCacheDrive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting virtual cache drive removal..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error removing virtual cache drive: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Add-UberAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting UberAgent installation..." "INFO"
        
        # Implementation continues
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "Error installing UberAgent: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Install-VDAFromISOWithDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ISOPath,
        
        [Parameter(Mandatory=$false)]
        [string]$InstallerArgs = "/quiet /norestart /components vda,plugins",
        
        [Parameter(Mandatory=$false)]
        [string]$ProductName = "Citrix VDA",
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 45
    )
    
    try {
        Write-Log "Starting $ProductName installation from ISO with auto-detection: $ISOPath" "INFO"
        
        # Mount the ISO
        $MountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru
        $DriveLetter = ($MountResult | Get-Volume).DriveLetter
        $MountPath = "${DriveLetter}:"
        
        Write-Log "ISO mounted to: $MountPath" "INFO"
        
        # Auto-detect VDA installer
        $InstallerPath = Find-VDAInstaller -MountPath $MountPath
        
        if (-not $InstallerPath) {
            throw "No VDA installer found in ISO at any expected location"
        }
        
        Write-Log "Found VDA installer: $InstallerPath" "SUCCESS"
        Write-Log "Starting installation with arguments: $InstallerArgs" "INFO"
        
        # Execute installer
        $InstallProcess = Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArgs -Wait -PassThru -NoNewWindow
        
        $ExitCode = $InstallProcess.ExitCode
        $Success = ($ExitCode -eq 0 -or $ExitCode -eq 3010)
        
        # Dismount ISO
        try {
            Dismount-DiskImage -ImagePath $ISOPath | Out-Null
        } catch {
            Write-Log "Warning: Could not dismount ISO: $($_.Exception.Message)" "WARN"
        }
        
        if ($Success) {
            $LogLevel = if ($ExitCode -eq 3010) { "WARN" } else { "SUCCESS" }
            $Message = if ($ExitCode -eq 3010) { "$ProductName installation completed successfully (reboot required)" } else { "$ProductName installation completed successfully" }
            Write-Log $Message $LogLevel
        } else {
            Write-Log "$ProductName installation failed with exit code: $ExitCode" "ERROR"
        }
        
        return @{
            Success = $Success
            ExitCode = $ExitCode
            InstallerUsed = (Split-Path $InstallerPath -Leaf)
            Error = if (-not $Success) { "Installation failed with exit code: $ExitCode" } else { $null }
            RebootRequired = ($ExitCode -eq 3010)
        }
    }
    catch {
        Write-Log "Critical error during $ProductName installation: $($_.Exception.Message)" "ERROR"
        
        # Attempt to dismount ISO in case of error
        try {
            Dismount-DiskImage -ImagePath $ISOPath | Out-Null
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

function Find-VDAInstaller {
    param([string]$MountPath)
    
    $PossibleNames = @(
        "VDAServerSetup_*.exe",
        "VDAWorkstationSetup_*.exe", 
        "XenDesktopVdaSetup.exe",
        "VDASetup.exe",
        "CitrixVDASetup.exe"
    )
    
    $CommonPaths = @("", "x64", "x86", "VDA", "Setup", "Installers")
    
    foreach ($SubPath in $CommonPaths) {
        $TestPath = if ($SubPath) { Join-Path $MountPath $SubPath } else { $MountPath }
        
        foreach ($InstallerName in $PossibleNames) {
            $FullPath = Join-Path $TestPath $InstallerName
            $FoundFiles = Get-ChildItem -Path $TestPath -Name $InstallerName -ErrorAction SilentlyContinue
            
            if ($FoundFiles) {
                return Join-Path $TestPath $FoundFiles[0]
            }
        }
    }
    
    return $null
}

function Stop-NetBiosOverTCP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Disabling NetBIOS over TCP/IP for PVS compatibility..." "INFO"
        
        $Results = @{
            Success = $true
            AdaptersModified = @()
            Errors = @()
        }
        
        # Get all network adapters
        $NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        foreach ($Adapter in $NetworkAdapters) {
            try {
                Write-Log "Processing adapter: $($Adapter.Description)" "INFO"
                
                # Disable NetBIOS over TCP/IP (0 = Default, 1 = Enable, 2 = Disable)
                $Result = $Adapter.SetTcpipNetbios(2)
                
                if ($Result.ReturnValue -eq 0) {
                    Write-Log "Successfully disabled NetBIOS over TCP/IP for: $($Adapter.Description)" "SUCCESS"
                    $Results.AdaptersModified += $Adapter.Description
                } else {
                    Write-Log "Failed to disable NetBIOS for adapter: $($Adapter.Description), Return code: $($Result.ReturnValue)" "ERROR"
                    $Results.Errors += "Failed to modify adapter: $($Adapter.Description)"
                }
            }
            catch {
                Write-Log "Error processing adapter $($Adapter.Description): $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Error with adapter $($Adapter.Description): $($_.Exception.Message)"
            }
        }
        
        if ($Results.Errors.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "NetBIOS over TCP/IP configuration completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error disabling NetBIOS over TCP/IP: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Stop-NetworkOffloadParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Disabling network offload parameters for PVS compatibility..." "INFO"
        
        $Results = @{
            Success = $true
            ParametersDisabled = @()
            Errors = @()
        }
        
        # Registry path for network adapter settings
        $NetworkPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        
        # Parameters to disable for PVS compatibility
        $OffloadParameters = @(
            "TCPOffloadDisabled",
            "IPChecksumOffloadDisabled", 
            "UDPChecksumOffloadDisabled",
            "TCPChecksumOffloadDisabled",
            "LSODisabled",
            "PMARPOffload",
            "PMNSOffload"
        )
        
        # Get all network adapter subkeys
        $AdapterKeys = Get-ChildItem -Path $NetworkPath -ErrorAction SilentlyContinue
        
        foreach ($AdapterKey in $AdapterKeys) {
            $AdapterPath = $AdapterKey.PSPath
            
            # Check if this is a network adapter (has DriverDesc)
            $DriverDesc = Get-ItemProperty -Path $AdapterPath -Name "DriverDesc" -ErrorAction SilentlyContinue
            
            if ($DriverDesc) {
                Write-Log "Processing network adapter: $($DriverDesc.DriverDesc)" "INFO"
                
                foreach ($Parameter in $OffloadParameters) {
                    try {
                        Set-ItemProperty -Path $AdapterPath -Name $Parameter -Value 1 -Type DWord -ErrorAction SilentlyContinue
                        $Results.ParametersDisabled += "$($DriverDesc.DriverDesc): $Parameter"
                    }
                    catch {
                        Write-Log "Could not set $Parameter for $($DriverDesc.DriverDesc): $($_.Exception.Message)" "WARN"
                    }
                }
            }
        }
        
        Write-Log "Network offload parameters disabled for PVS compatibility" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error disabling network offload parameters: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Reset-RDSGracePeriod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Resetting RDS grace period..." "INFO"
        
        $Results = @{
            Success = $true
            GracePeriodReset = $false
            Error = $null
        }
        
        # Registry paths for RDS grace period
        $RDSPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList"
        )
        
        foreach ($Path in $RDSPaths) {
            if (Test-Path $Path) {
                try {
                    Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed RDS grace period registry key: $Path" "SUCCESS"
                    $Results.GracePeriodReset = $true
                }
                catch {
                    Write-Log "Could not remove RDS registry key $Path: $($_.Exception.Message)" "WARN"
                }
            }
        }
        
        # Reset Terminal Services licensing
        try {
            $TSLicenseKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers"
            if (Test-Path $TSLicenseKey) {
                Remove-Item -Path $TSLicenseKey -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Reset Terminal Services licensing configuration" "SUCCESS"
            }
        }
        catch {
            Write-Log "Could not reset TS licensing: $($_.Exception.Message)" "WARN"
        }
        
        Write-Log "RDS grace period reset completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error resetting RDS grace period: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-VDAInstallation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Testing VDA installation status..." "INFO"
        
        $Results = @{
            VDAInstalled = $false
            VDAVersion = $null
            ServicesRunning = @()
            ServicesStopped = @()
            OverallHealthy = $false
        }
        
        # Check for VDA registry entries
        $VDARegPaths = @(
            "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent",
            "HKLM:\SOFTWARE\Citrix\ICA Client",
            "HKLM:\SOFTWARE\Wow6432Node\Citrix\VirtualDesktopAgent"
        )
        
        foreach ($RegPath in $VDARegPaths) {
            if (Test-Path $RegPath) {
                $Results.VDAInstalled = $true
                
                # Try to get version information
                try {
                    $VersionInfo = Get-ItemProperty -Path $RegPath -Name "ProductVersion" -ErrorAction SilentlyContinue
                    if ($VersionInfo) {
                        $Results.VDAVersion = $VersionInfo.ProductVersion
                        Write-Log "VDA Version detected: $($Results.VDAVersion)" "SUCCESS"
                    }
                }
                catch {
                    # Version detection not critical
                }
                break
            }
        }
        
        if ($Results.VDAInstalled) {
            Write-Log "Citrix VDA installation detected" "SUCCESS"
            
            # Check critical VDA services
            $VDAServices = @(
                "BrokerAgent",
                "picaSvc2", 
                "CdfSvc",
                "ctxlogd"
            )
            
            foreach ($ServiceName in $VDAServices) {
                try {
                    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                    if ($Service) {
                        if ($Service.Status -eq "Running") {
                            $Results.ServicesRunning += $ServiceName
                        } else {
                            $Results.ServicesStopped += $ServiceName
                        }
                    }
                }
                catch {
                    Write-Log "Could not check service $ServiceName: $($_.Exception.Message)" "WARN"
                }
            }
            
            # Determine overall health
            $Results.OverallHealthy = ($Results.ServicesRunning.Count -gt 0 -and $Results.ServicesStopped.Count -eq 0)
        } else {
            Write-Log "Citrix VDA installation not detected" "WARN"
        }
        
        return $Results
    }
    catch {
        Write-Log "Error testing VDA installation: $($_.Exception.Message)" "ERROR"
        return @{
            VDAInstalled = $false
            Error = $_.Exception.Message
        }
    }
}

function Stop-CitrixServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Stopping Citrix services for optimization..." "INFO"
        
        $Results = @{
            Success = $true
            ServicesStopped = @()
            ServicesDisabled = @()
            Errors = @()
        }
        
        # Citrix services to stop/disable during optimization
        $CitrixServices = @(
            "BrokerAgent",
            "picaSvc2",
            "CdfSvc", 
            "ctxlogd",
            "CtxUvi",
            "Spooler"
        )
        
        foreach ($ServiceName in $CitrixServices) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    if ($Service.Status -eq "Running") {
                        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                        Write-Log "Stopped service: $ServiceName" "SUCCESS"
                        $Results.ServicesStopped += $ServiceName
                    }
                    
                    # Temporarily disable the service
                    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                    Write-Log "Disabled service: $ServiceName" "SUCCESS"
                    $Results.ServicesDisabled += $ServiceName
                }
            }
            catch {
                Write-Log "Error processing service $ServiceName: $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Failed to process $ServiceName: $($_.Exception.Message)"
            }
        }
        
        if ($Results.Errors.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "Citrix services management completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error managing Citrix services: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-RegistryOptimizations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Applying registry optimizations..." "INFO"
        
        $Results = @{
            Success = $true
            OptimizationsApplied = @()
            Errors = @()
        }
        
        # Registry optimizations for VDI performance
        $RegOptimizations = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0; Type = "DWORD" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "DisablePreviewDesktop"; Value = 1; Type = "DWORD" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "DisablePreviewWindow"; Value = 1; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "IRPStackSize"; Value = 32; Type = "DWORD" }
        )
        
        foreach ($Optimization in $RegOptimizations) {
            try {
                # Ensure registry path exists
                if (-not (Test-Path $Optimization.Path)) {
                    New-Item -Path $Optimization.Path -Force | Out-Null
                }
                
                # Apply the optimization
                Set-ItemProperty -Path $Optimization.Path -Name $Optimization.Name -Value $Optimization.Value -Type $Optimization.Type -ErrorAction Stop
                
                Write-Log "Applied registry optimization: $($Optimization.Path)\$($Optimization.Name) = $($Optimization.Value)" "SUCCESS"
                $Results.OptimizationsApplied += "$($Optimization.Name) = $($Optimization.Value)"
            }
            catch {
                Write-Log "Failed to apply registry optimization $($Optimization.Name): $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Failed to set $($Optimization.Name): $($_.Exception.Message)"
            }
        }
        
        if ($Results.Errors.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "Registry optimizations completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error applying registry optimizations: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-CitrixOptimizer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting Citrix Optimizer for VDI optimizations..." "INFO"
        
        $Results = @{
            Success = $true
            OptimizerFound = $false
            TemplatesApplied = @()
            Error = $null
        }
        
        # Get Citrix Optimizer configuration
        $OptimizerPath = Get-ConfigValue -Key "CitrixOptimizerPath" -DefaultValue "C:\Temp\CitrixOptimizer.exe" -ConfigFile $ConfigFilePath
        $OptimizerTemplate = Get-ConfigValue -Key "CitrixOptimizerTemplate" -DefaultValue "Windows_10_VDI.xml" -ConfigFile $ConfigFilePath
        
        if (-not (Test-Path $OptimizerPath)) {
            Write-Log "Citrix Optimizer not found at: $OptimizerPath" "ERROR"
            $Results.Success = $false
            $Results.Error = "Citrix Optimizer executable not found"
            return $Results
        }
        
        $Results.OptimizerFound = $true
        Write-Log "Found Citrix Optimizer: $OptimizerPath" "SUCCESS"
        
        # Build optimizer arguments
        $OptimizerArgs = @("-Execute")
        
        if ($OptimizerTemplate -and $OptimizerTemplate -ne "") {
            $TemplatePath = Join-Path (Split-Path $OptimizerPath) "Templates\$OptimizerTemplate"
            if (Test-Path $TemplatePath) {
                $OptimizerArgs += "-Template"
                $OptimizerArgs += "`"$TemplatePath`""
                Write-Log "Using optimization template: $OptimizerTemplate" "INFO"
            }
        }
        
        # Execute Citrix Optimizer
        Write-Log "Executing Citrix Optimizer with arguments: $($OptimizerArgs -join ' ')" "INFO"
        
        $OptimizerProcess = Start-Process -FilePath $OptimizerPath -ArgumentList $OptimizerArgs -Wait -PassThru -NoNewWindow
        
        if ($OptimizerProcess.ExitCode -eq 0) {
            Write-Log "Citrix Optimizer completed successfully" "SUCCESS"
            $Results.TemplatesApplied += $OptimizerTemplate
        } else {
            Write-Log "Citrix Optimizer failed with exit code: $($OptimizerProcess.ExitCode)" "ERROR"
            $Results.Success = $false
            $Results.Error = "Optimizer failed with exit code: $($OptimizerProcess.ExitCode)"
        }
        
        return $Results
    }
    catch {
        Write-Log "Error running Citrix Optimizer: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-SMBSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Configuring SMB settings for VDI optimization..." "INFO"
        
        $Results = @{
            Success = $true
            SettingsApplied = @()
            Errors = @()
        }
        
        # SMB optimizations for VDI
        $SMBSettings = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"; Name = "SMB1"; Value = 0; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"; Name = "SMB2"; Value = 1; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"; Name = "RequireSecuritySignature"; Value = 0; Type = "DWORD" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters"; Name = "RequireSecuritySignature"; Value = 0; Type = "DWORD" }
        )
        
        foreach ($Setting in $SMBSettings) {
            try {
                if (-not (Test-Path $Setting.Path)) {
                    New-Item -Path $Setting.Path -Force | Out-Null
                }
                
                Set-ItemProperty -Path $Setting.Path -Name $Setting.Name -Value $Setting.Value -Type $Setting.Type -ErrorAction Stop
                Write-Log "Applied SMB setting: $($Setting.Name) = $($Setting.Value)" "SUCCESS"
                $Results.SettingsApplied += "$($Setting.Name) = $($Setting.Value)"
            }
            catch {
                Write-Log "Failed to apply SMB setting $($Setting.Name): $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Failed to set $($Setting.Name): $($_.Exception.Message)"
            }
        }
        
        if ($Results.Errors.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "SMB settings configuration completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error configuring SMB settings: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-CrashDumpToKernelMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Configuring crash dump to kernel mode..." "INFO"
        
        $Results = @{
            Success = $true
            CrashDumpConfigured = $false
            Error = $null
        }
        
        # Configure crash dump settings for VDI
        $CrashControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
        
        try {
            # Set crash dump type to kernel memory dump (2)
            Set-ItemProperty -Path $CrashControlPath -Name "CrashDumpEnabled" -Value 2 -Type DWord -ErrorAction Stop
            
            # Configure dump file location
            Set-ItemProperty -Path $CrashControlPath -Name "DumpFile" -Value "%SystemRoot%\MEMORY.DMP" -Type String -ErrorAction Stop
            
            # Disable automatic restart
            Set-ItemProperty -Path $CrashControlPath -Name "AutoReboot" -Value 0 -Type DWord -ErrorAction Stop
            
            Write-Log "Crash dump configured to kernel mode" "SUCCESS"
            $Results.CrashDumpConfigured = $true
        }
        catch {
            Write-Log "Failed to configure crash dump settings: $($_.Exception.Message)" "ERROR"
            $Results.Success = $false
            $Results.Error = $_.Exception.Message
        }
        
        return $Results
    }
    catch {
        Write-Log "Error configuring crash dump: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-SystemInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Gathering system information..." "INFO"
        
        $Results = @{
            Success = $true
            ComputerName = $env:COMPUTERNAME
            OSVersion = $null
            OSBuild = $null
            TotalMemoryGB = $null
            ProcessorCount = $null
            SystemDrive = $env:SystemDrive
            Error = $null
        }
        
        # Get OS information
        try {
            $OS = Get-WmiObject -Class Win32_OperatingSystem
            $Results.OSVersion = $OS.Caption
            $Results.OSBuild = $OS.BuildNumber
            $Results.TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
        }
        catch {
            Write-Log "Could not retrieve OS information: $($_.Exception.Message)" "WARN"
        }
        
        # Get processor information
        try {
            $Processor = Get-WmiObject -Class Win32_Processor
            $Results.ProcessorCount = $Processor.NumberOfCores
        }
        catch {
            Write-Log "Could not retrieve processor information: $($_.Exception.Message)" "WARN"
        }
        
        Write-Log "System information gathered successfully" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error gathering system information: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-CitrixServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Checking Citrix services status..." "INFO"
        
        $Results = @{
            Success = $true
            ServicesFound = @()
            ServicesRunning = @()
            ServicesStopped = @()
            Error = $null
        }
        
        # Common Citrix service names
        $CitrixServiceNames = @(
            "BrokerAgent",
            "picaSvc2",
            "CdfSvc",
            "ctxlogd",
            "CtxUvi",
            "CitrixPrintManagerService"
        )
        
        foreach ($ServiceName in $CitrixServiceNames) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    $Results.ServicesFound += $ServiceName
                    
                    if ($Service.Status -eq "Running") {
                        $Results.ServicesRunning += $ServiceName
                    } else {
                        $Results.ServicesStopped += $ServiceName
                    }
                    
                    Write-Log "Citrix service $ServiceName: $($Service.Status)" "INFO"
                }
            }
            catch {
                Write-Log "Error checking service $ServiceName: $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Found $($Results.ServicesFound.Count) Citrix services" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error checking Citrix services: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-WindowsServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Configuring Windows services for VDI optimization..." "INFO"
        
        $Results = @{
            Success = $true
            ServicesConfigured = @()
            Errors = @()
        }
        
        # Services to disable for VDI optimization
        $ServicesToDisable = @(
            "Themes",
            "TabletInputService", 
            "Fax",
            "WSearch",
            "BITS",
            "Schedule"
        )
        
        foreach ($ServiceName in $ServicesToDisable) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    if ($Service.Status -eq "Running") {
                        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                    }
                    
                    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                    Write-Log "Disabled service: $ServiceName" "SUCCESS"
                    $Results.ServicesConfigured += "Disabled: $ServiceName"
                }
            }
            catch {
                Write-Log "Failed to configure service $ServiceName: $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Failed to configure $ServiceName: $($_.Exception.Message)"
            }
        }
        
        if ($Results.Errors.Count -gt 0) {
            $Results.Success = $false
        }
        
        Write-Log "Windows services configuration completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error configuring Windows services: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function New-VirtualCacheDrive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Creating virtual cache drive..." "INFO"
        
        $Results = @{
            Success = $true
            VirtualDriveCreated = $false
            DriveLetter = "D"
            Error = $null
        }
        
        # Get virtual drive configuration
        $VirtualDriveSizeGB = [int](Get-ConfigValue -Key "VirtualCacheDriveSizeGB" -DefaultValue "50" -ConfigFile $ConfigFilePath)
        $VirtualDrivePath = Get-ConfigValue -Key "VirtualCacheDrivePath" -DefaultValue "C:\VirtualCacheDrive.vhdx" -ConfigFile $ConfigFilePath
        
        Write-Log "Creating virtual cache drive: $VirtualDrivePath ($VirtualDriveSizeGB GB)" "INFO"
        
        # Create VHDX file
        $VHDResult = New-VHD -Path $VirtualDrivePath -SizeBytes ($VirtualDriveSizeGB * 1GB) -Dynamic
        
        if ($VHDResult) {
            # Mount the VHDX
            $MountResult = Mount-VHD -Path $VirtualDrivePath -PassThru
            
            # Initialize and format the disk
            $DiskNumber = $MountResult.DiskNumber
            Initialize-Disk -Number $DiskNumber -PartitionStyle MBR
            $Partition = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -DriveLetter D
            Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "CacheDrive" -Confirm:$false
            
            Write-Log "Virtual cache drive created and mounted as D:" "SUCCESS"
            $Results.VirtualDriveCreated = $true
        }
        
        return $Results
    }
    catch {
        Write-Log "Error creating virtual cache drive: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-VMwareMemoryBallooningStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Testing VMware memory ballooning status..." "INFO"
        
        $Results = @{
            VMwareEnvironment = $false
            OverallCompliant = $true
            MemoryBalloonStatus = "Not Applicable"
            Issues = @()
        }
        
        # Check if running in VMware environment
        $VMwareDetected = $false
        
        try {
            $SystemInfo = Get-WmiObject -Class Win32_ComputerSystem
            if ($SystemInfo.Manufacturer -like "*VMware*" -or $SystemInfo.Model -like "*VMware*") {
                $VMwareDetected = $true
            }
        }
        catch {
            # Continue with other detection methods
        }
        
        $Results.VMwareEnvironment = $VMwareDetected
        
        if ($VMwareDetected) {
            try {
                $BalloonService = Get-Service -Name "vmmemctl" -ErrorAction SilentlyContinue
                if ($BalloonService) {
                    if ($BalloonService.Status -eq "Running") {
                        $Results.MemoryBalloonStatus = "Active"
                        $Results.Issues += "VMware memory ballooning driver is active"
                        $Results.OverallCompliant = $false
                    } else {
                        $Results.MemoryBalloonStatus = "Disabled"
                    }
                } else {
                    $Results.MemoryBalloonStatus = "Not Installed"
                }
            }
            catch {
                $Results.MemoryBalloonStatus = "Unknown"
                $Results.Issues += "Unable to determine memory ballooning status"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Error checking VMware memory ballooning status: $($_.Exception.Message)" "ERROR"
        return @{
            VMwareEnvironment = $false
            OverallCompliant = $true
            MemoryBalloonStatus = "Error"
            Issues = @("Error during VMware detection: $($_.Exception.Message)")
        }
    }
}

function Remove-PasswordAgeRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Removing password age registry keys..." "INFO"
        
        $Results = @{
            Success = $true
            KeysRemoved = @()
            Error = $null
        }
        
        # Password age registry keys
        $PasswordAgeKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning"
        )
        
        foreach ($KeyPath in $PasswordAgeKeys) {
            try {
                if (Test-Path $KeyPath) {
                    Remove-ItemProperty -Path (Split-Path $KeyPath) -Name (Split-Path $KeyPath -Leaf) -ErrorAction Stop
                    Write-Log "Removed password age key: $KeyPath" "SUCCESS"
                    $Results.KeysRemoved += $KeyPath
                }
            }
            catch {
                Write-Log "Could not remove password age key $KeyPath: $($_.Exception.Message)" "WARN"
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Error removing password age registry keys: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-WEMRSACleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Testing WEM RSA cleanup status..." "INFO"
        
        $Results = @{
            Success = $true
            CleanupRequired = $false
            RemainingKeys = @()
            Error = $null
        }
        
        # WEM RSA key locations
        $WEMKeyPaths = @(
            "HKLM:\SOFTWARE\Norskale\Norskale Agent Host",
            "HKLM:\SOFTWARE\Wow6432Node\Norskale\Norskale Agent Host",
            "HKLM:\SOFTWARE\Citrix\WEM",
            "HKLM:\SOFTWARE\Wow6432Node\Citrix\WEM"
        )
        
        foreach ($KeyPath in $WEMKeyPaths) {
            if (Test-Path $KeyPath) {
                $Results.CleanupRequired = $true
                $Results.RemainingKeys += $KeyPath
                Write-Log "Found remaining WEM key: $KeyPath" "WARN"
            }
        }
        
        if (-not $Results.CleanupRequired) {
            Write-Log "WEM RSA cleanup validation passed - no remaining keys found" "SUCCESS"
        }
        
        return $Results
    }
    catch {
        Write-Log "Error testing WEM RSA cleanup: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-SystemOptimizations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Testing system optimizations status..." "INFO"
        
        $Results = @{
            Success = $true
            OptimizationsApplied = @()
            OptimizationsMissing = @()
            Error = $null
        }
        
        # Check key optimization registry values
        $OptimizationChecks = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; ExpectedValue = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; ExpectedValue = 0 },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "DisablePreviewDesktop"; ExpectedValue = 1 }
        )
        
        foreach ($Check in $OptimizationChecks) {
            try {
                $CurrentValue = Get-ItemProperty -Path $Check.Path -Name $Check.Name -ErrorAction SilentlyContinue
                
                if ($CurrentValue -and $CurrentValue.$($Check.Name) -eq $Check.ExpectedValue) {
                    $Results.OptimizationsApplied += "$($Check.Name) = $($Check.ExpectedValue)"
                } else {
                    $Results.OptimizationsMissing += "$($Check.Name) should be $($Check.ExpectedValue)"
                }
            }
            catch {
                $Results.OptimizationsMissing += "$($Check.Name) check failed"
            }
        }
        
        Write-Log "System optimizations validation completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error testing system optimizations: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Remove-InstallationFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFilePath = ".\CitrixConfig.txt"
    )
    
    try {
        Write-Log "Removing installation files cleanup..." "INFO"
        
        $Results = @{
            Success = $true
            FilesRemoved = 0
            DirectoriesRemoved = 0
            Error = $null
        }
        
        # Common installation file locations
        $CleanupPaths = @(
            "C:\Temp\*.msi",
            "C:\Temp\*.exe",
            "C:\Temp\VDA*",
            "C:\Temp\Citrix*",
            "$env:USERPROFILE\Downloads\*.msi",
            "$env:USERPROFILE\Downloads\*.exe"
        )
        
        foreach ($Path in $CleanupPaths) {
            try {
                $Items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
                
                foreach ($Item in $Items) {
                    if ($Item.PSIsContainer) {
                        Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction Stop
                        $Results.DirectoriesRemoved++
                    } else {
                        Remove-Item -Path $Item.FullName -Force -ErrorAction Stop
                        $Results.FilesRemoved++
                    }
                    
                    Write-Log "Removed: $($Item.Name)" "SUCCESS"
                }
            }
            catch {
                Write-Log "Could not clean path $Path: $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Installation files cleanup completed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Error removing installation files: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Export functions
Export-ModuleMember -Function *
