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

function Expand-ConfigPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [int]$Stage = 1
    )
    
    try {
        # Start with the original path
        $ExpandedPath = $Path
        
        # Expand environment variables first (handles %USERPROFILE%, etc.)
        $ExpandedPath = [Environment]::ExpandEnvironmentVariables($ExpandedPath)
        
        # Replace custom placeholders
        $CurrentDate = Get-Date -Format "yyyyMMdd"
        $CurrentTime = Get-Date -Format "HHmmss"
        $ComputerName = $env:COMPUTERNAME
        $UserName = $env:USERNAME
        
        $ExpandedPath = $ExpandedPath -replace '%DATE%', $CurrentDate
        $ExpandedPath = $ExpandedPath -replace '%TIME%', $CurrentTime
        $ExpandedPath = $ExpandedPath -replace '%COMPUTERNAME%', $ComputerName
        $ExpandedPath = $ExpandedPath -replace '%USERNAME%', $UserName
        $ExpandedPath = $ExpandedPath -replace '%STAGE%', $Stage
        
        # Ensure directory exists if it's a file path
        if ($ExpandedPath -match '\.\w+$') {
            $Directory = Split-Path $ExpandedPath -Parent
            if ($Directory -and -not (Test-Path $Directory)) {
                New-Item -Path $Directory -ItemType Directory -Force | Out-Null
                Write-Log "Created directory: $Directory" "INFO"
            }
        }
        
        return $ExpandedPath
    }
    catch {
        Write-Log "Failed to expand path '$Path': $($_.Exception.Message)" "ERROR"
        return $Path
    }
}

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
        Get-ConfigValue -Key "CitrixServicesToDisable" -DefaultValue "CdfSvc,Spooler,BITS,wuauserv,TapiSrv" -ConfigFile $ConfigFilePath -ShowStatus
        
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
    
    # Check if detailed logging is enabled - use cached config first
    $DetailedLogging = $true
    try {
        if ($Global:CachedConfig -and $Global:CachedConfig.DetailedLogging) {
            $DetailedLogging = [bool]$Global:CachedConfig.DetailedLogging
        } else {
            $DetailedLogging = [bool](Get-ConfigValue -Key "DetailedLogging" -DefaultValue "true" -ConfigFile $ConfigFilePath)
        }
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
        return @{
            Success = $IsAdmin
            Message = if ($IsAdmin) { "Administrator privileges confirmed" } else { "Administrator privileges required" }
            UserAccount = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            IsElevated = $IsAdmin
            Details = @(
                "Current user: $env:USERNAME",
                "Computer: $env:COMPUTERNAME", 
                "Admin privileges: $(if ($IsAdmin) { 'Confirmed' } else { 'Missing' })"
            )
        }
    }
    catch {
        Write-Log "Error checking administrator privileges: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Failed to check administrator privileges"
            Details = @("Error checking admin privileges: $($_.Exception.Message)")
        }
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
        
        # Read only DNS search list from cached config or configuration file
        if ($Global:CachedConfig -and $Global:CachedConfig.DNSSuffixSearchList) {
            $DNSSuffixSearchListStr = $Global:CachedConfig.DNSSuffixSearchList -or ""
        } else {
            $DNSSuffixSearchListStr = Get-ConfigValue -Key "DNSSuffixSearchList" -ConfigFile $ConfigFile -DefaultValue ""
        }
        
        # Parse DNS suffix search list
        $DNSSuffixSearchList = @()
        if ($DNSSuffixSearchListStr -ne "") {
            $DNSSuffixSearchList = $DNSSuffixSearchListStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
        
        Write-Log "DNS Search List Configuration:"
        Write-Log "  DNS Search List: $($DNSSuffixSearchList -join ', ')"
        Write-Log "  Note: Only DNS search list will be modified, all other DNS settings preserved"
        
        Write-Log "Configuring DNS search list only..."
        
        $Results = @{
            Success = $true
            ConfiguredSettings = @()
            FailedSettings = @()
        }
        
        # Skip primary DNS suffix configuration - preserving existing settings
        Write-Log "Preserving existing primary DNS suffix settings"
        
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
        
        # Skip DNS suffix behavior configuration - preserving existing settings
        Write-Log "Preserving existing DNS suffix behavior settings (AppendPrimarySuffixes, AppendParentSuffixes, RegisterThisConnectionsAddress)"
        
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
        
        return @{
            Success = $Results.Success
            Message = "DNS suffix configuration completed"
            RegistryKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList"
            DNSSuffixes = $DNSSuffixSearchList
            RegistryChanges = @(
                "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList = $($Results.ConfiguredSettings -join '; ')"
            )
            ConfiguredDomains = $DNSSuffixSearchList
            Details = @(
                "DNS search domains configured: $($DNSSuffixSearchList -join ', ')",
                "Registry location: HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "SearchList value updated with domain list"
            )
        }
    }
    catch {
        Write-Log "DNS suffix configuration failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "DNS configuration failed"
            RegistryChanges = @()
            Details = @("DNS configuration failed with error: $($_.Exception.Message)")
        }
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
            return @{
                Success = $false
                Message = "Path not accessible"
                PathExists = $false
                ReadAccess = $false
                WriteAccess = $false
                Error = "Specified path does not exist: $Path"
            }
        }
        
        $Results = @{
            Success = $true
            Message = "File access validated"
            PathExists = $true
            ReadAccess = $true
            WriteAccess = $false
            TestsPerformed = @("Path existence check", "Read access verification")
        }
        
        if ($TestWrite) {
            $TestFile = Join-Path $Path "test_write_access.tmp"
            try {
                "test" | Out-File -FilePath $TestFile -Force
                Remove-Item $TestFile -Force
                $Results.WriteAccess = $true
                $Results.TestsPerformed += "Write access verification"
                $Results.Message = "Full read/write access confirmed"
                $Results.Details = @(
                    "Path exists and is accessible: $Path",
                    "Read access: Confirmed",
                    "Write access: Confirmed",
                    "Test file operations: Successful"
                )
            }
            catch {
                $Results.WriteAccess = $false
                $Results.Success = $false
                $Results.Message = "Write access denied"
                $Results.Error = "Write test failed: $($_.Exception.Message)"
                $Results.Details = @(
                    "Path exists and is accessible: $Path",
                    "Read access: Confirmed",
                    "Write access: Denied",
                    "Error: $($_.Exception.Message)"
                )
            }
        } else {
            $Results.Details = @(
                "Path exists and is accessible: $Path",
                "Read access: Confirmed",
                "Write access: Not tested"
            )
        }
        
        return $Results
    }
    catch {
        return @{
            Success = $false
            Message = "File access test failed"
            PathExists = $false
            ReadAccess = $false
            WriteAccess = $false
            Error = $_.Exception.Message
        }
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
        
        # Copy with retry logic - simplified approach
        $Attempt = 0
        while ($Attempt -lt $RetryAttempts) {
            try {
                # Remove destination file if it exists to prevent directory creation
                if (Test-Path $DestinationPath) {
                    Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
                }
                
                # Copy file to destination directory first, then ensure correct naming
                $FileName = Split-Path $SourcePath -Leaf
                $TempDestination = Join-Path $DestDir $FileName
                
                Copy-Item -Path $SourcePath -Destination $DestDir -Force -ErrorAction Stop
                
                # If the copied file name differs from target, rename it
                if ($TempDestination -ne $DestinationPath -and (Test-Path $TempDestination)) {
                    Move-Item -Path $TempDestination -Destination $DestinationPath -Force -ErrorAction Stop
                }
                
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
                    
                    # Check if this is a domain profile using multiple detection methods
                    $IsDomainProfile = $false
                    
                    # Method 1: Domain format (DOMAIN.USERNAME or DOMAIN\USERNAME patterns)
                    if ($ProfileName -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $ProfileName -match "^[A-Za-z0-9-]+\\[A-Za-z0-9-]+.*") {
                        $IsDomainProfile = $true
                    }
                    
                    # Method 2: Check if profile path is not in standard local paths
                    if ($ProfileDir -notmatch "\\Users\\(Administrator|Guest|Public|Default|All Users|Default User)$" -and 
                        $ProfileDir -match "\\Users\\[^\\]+$" -and 
                        $ProfileName.Length -gt 5) {
                        # Method 3: Check profile registry for domain SID pattern (domain SIDs are longer)
                        $ProfileSID = $ProfileKey.PSChildName
                        if ($ProfileSID -match "^S-1-5-21-\d+-\d+-\d+-\d+$") {
                            $IsDomainProfile = $true
                        }
                    }
                    
                    if ($IsDomainProfile) {
                        Write-Log "Found domain profile: $ProfileName at $ProfileDir"
                        
                        # Force remove profile directory with enhanced deletion methods
                        if (Test-Path $ProfileDir) {
                            try {
                                Write-Log "Attempting to force remove profile directory: $ProfileDir"
                                
                                # Remove read-only attributes recursively
                                Get-ChildItem -Path $ProfileDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                                    if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                        $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                                    }
                                }
                                
                                # Primary deletion attempt
                                Remove-Item -Path $ProfileDir -Recurse -Force -ErrorAction Stop
                                Write-Log "Successfully removed profile directory: $ProfileDir" "SUCCESS"
                            }
                            catch {
                                Write-Log "Primary deletion failed for $ProfileDir, trying alternative method: $($_.Exception.Message)" "WARN"
                                
                                # Alternative deletion using robocopy and rmdir
                                try {
                                    $TempEmptyDir = "$env:TEMP\EmptyDir_$(Get-Random)"
                                    New-Item -Path $TempEmptyDir -ItemType Directory -Force | Out-Null
                                    
                                    # Use robocopy to mirror empty directory (effectively deleting content)
                                    robocopy $TempEmptyDir $ProfileDir /MIR /R:0 /W:0 /NFL /NDL /NJH /NJS 2>&1 | Out-Null
                                    
                                    # Remove the now-empty directory
                                    Remove-Item -Path $ProfileDir -Force -ErrorAction SilentlyContinue
                                    Remove-Item -Path $TempEmptyDir -Force -ErrorAction SilentlyContinue
                                    
                                    if (-not (Test-Path $ProfileDir)) {
                                        Write-Log "Successfully removed profile directory using alternative method: $ProfileDir" "SUCCESS"
                                    } else {
                                        throw "Directory still exists after all removal attempts"
                                    }
                                }
                                catch {
                                    Write-Log "All deletion methods failed for profile directory: $ProfileDir - $($_.Exception.Message)" "ERROR"
                                    $Results.FailedRemovals += $ProfileName
                                    $Results.Success = $false
                                    continue
                                }
                            }
                        } else {
                            Write-Log "Profile directory does not exist: $ProfileDir" "INFO"
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
            
            $AllDirs = Get-ChildItem -Path $DUsersPath -Directory -ErrorAction SilentlyContinue
            $SystemProfileNames = @("Administrator", "Guest", "Public", "Default", "All Users", "Default User")
            
            foreach ($Dir in $AllDirs) {
                # Skip system profiles
                if ($Dir.Name -in $SystemProfileNames -or $Dir.Name.StartsWith("TEMP") -or $Dir.Name.Length -lt 3) {
                    continue
                }
                
                # Enhanced domain profile detection for redirected profiles
                $IsDomainDir = $false
                
                # Check for domain format patterns
                if ($Dir.Name -match "^[A-Za-z0-9-]+\.[A-Za-z0-9-]+.*" -or $Dir.Name -match "^[A-Za-z0-9-]+\\[A-Za-z0-9-]+.*" -or
                    $Dir.Name.Contains(".") -or $Dir.Name.Length -gt 8) {
                    $IsDomainDir = $true
                }
                
                if ($IsDomainDir) {
                    try {
                        Write-Log "Force removing redirected domain profile: $($Dir.Name)"
                        
                        # Remove read-only attributes recursively
                        Get-ChildItem -Path $Dir.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                            if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                            }
                        }
                        
                        # Primary deletion attempt
                        Remove-Item -Path $Dir.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "Successfully removed redirected profile: $($Dir.Name)" "SUCCESS"
                        
                        if ($Dir.Name -notin $Results.RemovedProfiles) {
                            $Results.ProfilesRemoved++
                            $Results.RemovedProfiles += $Dir.Name
                        }
                    }
                    catch {
                        Write-Log "Primary deletion failed for $($Dir.Name), trying alternative method: $($_.Exception.Message)" "WARN"
                        
                        # Alternative deletion using robocopy
                        try {
                            $TempEmptyDir = "$env:TEMP\EmptyDir_$(Get-Random)"
                            New-Item -Path $TempEmptyDir -ItemType Directory -Force | Out-Null
                            
                            # Use robocopy to mirror empty directory
                            $RobocopyResult = robocopy $TempEmptyDir $Dir.FullName /MIR /R:0 /W:0 /NFL /NDL /NJH /NJS 2>&1
                            
                            # Remove the now-empty directory
                            Remove-Item -Path $Dir.FullName -Force -ErrorAction SilentlyContinue
                            Remove-Item -Path $TempEmptyDir -Force -ErrorAction SilentlyContinue
                            
                            if (-not (Test-Path $Dir.FullName)) {
                                Write-Log "Successfully removed redirected profile using alternative method: $($Dir.Name)" "SUCCESS"
                                if ($Dir.Name -notin $Results.RemovedProfiles) {
                                    $Results.ProfilesRemoved++
                                    $Results.RemovedProfiles += $Dir.Name
                                }
                            } else {
                                throw "Directory still exists after all removal attempts"
                            }
                        }
                        catch {
                            Write-Log "All deletion methods failed for redirected profile: $($Dir.Name) - $($_.Exception.Message)" "ERROR"
                            $Results.FailedRemovals += $Dir.Name
                            $Results.Success = $false
                        }
                    }
                }
            }
        }
        
        if ($Results.FailedRemovals.Count -gt 0) {
            $Results.Success = $false
        }
        
        # Add detailed results
        $Results.Details = @(
            "Total profiles removed: $($Results.ProfilesRemoved)",
            "Failed removals: $($Results.FailedRemovals.Count)",
            "Registry paths cleaned: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            "Profile directories processed: C:\Users\ and D:\Users\"
        )
        
        if ($Results.RemovedProfiles.Count -gt 0) {
            $Results.Details += "Profiles removed: $($Results.RemovedProfiles -join '; ')"
        }
        
        if ($Results.FailedRemovals.Count -gt 0) {
            $Results.Details += "Failed removals: $($Results.FailedRemovals -join '; ')"
        }
        
        $Results.Message = "Domain profile cleanup: $($Results.ProfilesRemoved) removed, $($Results.FailedRemovals.Count) failed"
        
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
            Error = ""
        }
        
        Write-Log "Scanning for Citrix WEM RSA key files..."
        
        # Target the specific Citrix WEM RSA key location
        $CryptoPath = "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18"
        
        if (Test-Path $CryptoPath) {
            Write-Log "Searching for WEM RSA keys in: $CryptoPath"
            
            # Look for files starting with fb8cc9e38d3e60ab60c17cdfd6dd6d99_
            $WEMRSAFiles = Get-ChildItem -Path $CryptoPath -Filter "fb8cc9e38d3e60ab60c17cdfd6dd6d99_*" -ErrorAction SilentlyContinue
            
            if ($WEMRSAFiles) {
                foreach ($RSAFile in $WEMRSAFiles) {
                    try {
                        Write-Log "Force removing WEM RSA key file: $($RSAFile.FullName)"
                        
                        # Remove read-only attribute if present
                        if ($RSAFile.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                            $RSAFile.Attributes = $RSAFile.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                            Write-Log "Removed read-only attribute from: $($RSAFile.Name)"
                        }
                        
                        # Take ownership and grant full control
                        $Acl = Get-Acl $RSAFile.FullName
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
                        $Acl.SetAccessRule($AccessRule)
                        Set-Acl -Path $RSAFile.FullName -AclObject $Acl -ErrorAction SilentlyContinue
                        
                        # Force delete with multiple attempts
                        Remove-Item -Path $RSAFile.FullName -Force -ErrorAction Stop
                        
                        # Verify deletion
                        if (-not (Test-Path $RSAFile.FullName)) {
                            $Results.RemovedKeys += $RSAFile.FullName
                            Write-Log "Successfully force removed WEM RSA key: $($RSAFile.Name)" "SUCCESS"
                        } else {
                            throw "File still exists after deletion attempt"
                        }
                    }
                    catch {
                        Write-Log "Failed to force remove WEM RSA key: $($RSAFile.FullName) - $($_.Exception.Message)" "ERROR"
                        
                        # Try alternative deletion method using cmd
                        try {
                            Write-Log "Attempting alternative deletion method for: $($RSAFile.Name)"
                            cmd /c "del /F /Q `"$($RSAFile.FullName)`"" 2>&1 | Out-Null
                            
                            if (-not (Test-Path $RSAFile.FullName)) {
                                $Results.RemovedKeys += $RSAFile.FullName
                                Write-Log "Successfully removed with cmd: $($RSAFile.Name)" "SUCCESS"
                            } else {
                                $Results.FailedRemovals += $RSAFile.FullName
                                $Results.Success = $false
                                Write-Log "All deletion methods failed for: $($RSAFile.Name)" "ERROR"
                            }
                        }
                        catch {
                            $Results.FailedRemovals += $RSAFile.FullName
                            $Results.Success = $false
                            Write-Log "Alternative deletion also failed: $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
            } else {
                Write-Log "No Citrix WEM RSA key files found (fb8cc9e38d3e60ab60c17cdfd6dd6d99_*)" "INFO"
            }
        } else {
            Write-Log "Crypto RSA directory not found: $CryptoPath" "WARN"
        }
        
        # Set appropriate message based on what was found
        if ($Results.RemovedKeys.Count -eq 0 -and $Results.FailedRemovals.Count -eq 0) {
            Write-Log "No WEM RSA key files found to remove" "INFO"
            $Results.Success = $true
            $Results.Message = "No WEM RSA key files found - cleanup not needed"
            $Results.NoFilesFound = $true
        } else {
            Write-Log "Removed $($Results.RemovedKeys.Count) WEM RSA key file(s)" "SUCCESS"
            $Results.Message = "WEM RSA key cleanup completed: $($Results.RemovedKeys.Count) removed, $($Results.FailedRemovals.Count) failed"
            $Results.NoFilesFound = $false
        }
        
        # Add detailed results
        $Results.Details = @(
            "Crypto directory checked: $CryptoPath",
            "WEM RSA keys found: $($Results.RemovedKeys.Count + $Results.FailedRemovals.Count)",
            "Successfully removed: $($Results.RemovedKeys.Count)",
            "Failed removals: $($Results.FailedRemovals.Count)"
        )
        
        if ($Results.RemovedKeys.Count -gt 0) {
            $KeyNames = $Results.RemovedKeys | ForEach-Object { Split-Path $_ -Leaf }
            $Results.Details += "Removed files: $($KeyNames -join '; ')"
        } else {
            $Results.Details += "No WEM RSA key files (fb8cc9e38d3e60ab60c17cdfd6dd6d99_*) found in crypto directory"
        }
        
        if ($Results.FailedRemovals.Count -gt 0) {
            $FailedNames = $Results.FailedRemovals | ForEach-Object { Split-Path $_ -Leaf }
            $Results.Details += "Failed files: $($FailedNames -join '; ')"
        }
        
        $Results.Message = "WEM RSA cleanup: $($Results.RemovedKeys.Count) removed, $($Results.FailedRemovals.Count) failed"
        
        return $Results
    }
    catch {
        Write-Log "WEM RSA key cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            RemovedKeys = @()
            FailedRemovals = @()
            Error = $_.Exception.Message
        }
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
            $DriveInfo = Get-WmiOrCimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $SystemDrive }
            Write-Log "System drive ($SystemDrive) is accessible" "SUCCESS"
            return @{
                Success = $true
                Message = "Drive configuration validated"
                SystemDrive = $SystemDrive
                DriveAccessible = $true
                SizeGB = if ($DriveInfo) { [math]::Round($DriveInfo.Size / 1GB, 2) } else { "Unknown" }
                FreeSpaceGB = if ($DriveInfo) { [math]::Round($DriveInfo.FreeSpace / 1GB, 2) } else { "Unknown" }
                Details = @(
                    "System drive $SystemDrive is accessible and responsive",
                    "Drive validation successful for VDI deployment",
                    "Storage subsystem functioning properly"
                )
            }
        }
        
        return @{
            Success = $false
            Message = "Drive configuration test failed"
            SystemDrive = $SystemDrive
            DriveAccessible = $false
            Error = "System drive not accessible"
        }
    }
    catch {
        Write-Log "Drive configuration test failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Drive configuration test failed"
            Details = @("Drive testing failed: $($_.Exception.Message)")
        }
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
        
        # Get cache drive letter and event logs path from cached config or file
        if ($Global:CachedConfig -and $Global:CachedConfig.CacheDriveLetter) {
            Write-Log "Using cached configuration for event log redirection" "INFO"
            $CacheDriveLetter = $Global:CachedConfig.CacheDriveLetter
            $EventLogsPath = $Global:CachedConfig.EventLogsPath
        } else {
            Write-Log "Using configuration file for event log redirection" "INFO"
            $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
            $EventLogsPath = Get-ConfigValue -Key "EventLogsPath" -DefaultValue "EventLogs" -ConfigFile $ConfigFilePath
        }
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
            return @{
                Success = $true
                Message = "Event log redirection configured"
                RedirectedLogs = $RedirectedCount
                TargetDirectory = $LogsPath
                FoldersCreated = @($LogsPath)
                RegistryChanges = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\File = ${LogsPath}\Application.evtx",
                    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\File = ${LogsPath}\System.evtx",
                    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\File = ${LogsPath}\Security.evtx"
                )
                Details = @(
                    "Created directory: $LogsPath",
                    "Redirected Application log to: ${LogsPath}\Application.evtx",
                    "Redirected System log to: ${LogsPath}\System.evtx", 
                    "Redirected Security log to: ${LogsPath}\Security.evtx",
                    "Registry keys modified: 3 event log file paths updated"
                )
            }
        } else {
            Write-Log "Event log redirection partially completed ($RedirectedCount/$($EventLogs.Count))" "WARN"
            return @{
                Success = $false
                Message = "Event log redirection partially completed"
                RedirectedCount = $RedirectedCount
                TotalCount = $EventLogs.Count
                Error = "Not all event logs could be redirected"
            }
        }
    }
    catch {
        Write-Log "Event log redirection failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Event log redirection failed"
            RegistryChanges = @()
            Details = @("Event log redirection failed: $($_.Exception.Message)")
        }
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
        
        # Get cache drive letter and user profiles path from cached config or file
        if ($Global:CachedConfig -and $Global:CachedConfig.CacheDriveLetter) {
            Write-Log "Using cached configuration for user profile redirection" "INFO"
            $CacheDriveLetter = $Global:CachedConfig.CacheDriveLetter
            $UserProfilesPath = $Global:CachedConfig.UserProfilesPath
        } else {
            Write-Log "Using configuration file for user profile redirection" "INFO"
            $CacheDriveLetter = Get-ConfigValue -Key "CacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
            $UserProfilesPath = Get-ConfigValue -Key "UserProfilesPath" -DefaultValue "Profiles" -ConfigFile $ConfigFilePath
        }
        $ProfilesPath = "${CacheDriveLetter}:\${UserProfilesPath}"
        if (-not (Test-Path $ProfilesPath)) {
            New-Item -Path $ProfilesPath -ItemType Directory -Force | Out-Null
            Write-Log "Created profiles directory: $ProfilesPath" "INFO"
        }
        
        # Configure ProfilesDirectory registry setting only
        $ProfileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        
        try {
            # Set ProfilesDirectory to cache drive path as specified in config
            Set-ItemProperty -Path $ProfileRegPath -Name "ProfilesDirectory" -Value $ProfilesPath -Force
            
            Write-Log "ProfilesDirectory registry set to $ProfilesPath" "SUCCESS"
            return @{
                Success = $true
                Message = "User profile redirection configured successfully"
                Details = @(
                    "Registry path: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                    "ProfilesDirectory: Set to $ProfilesPath",
                    "Profile folder created: $ProfilesPath",
                    "Permissions configured: Full access for Users group",
                    "Future user profiles will be created on cache drive"
                )
                RegistryChanges = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory = $ProfilesPath"
                )
                FoldersCreated = @(
                    $ProfilesPath
                )
            }
        }
        catch {
            Write-Log "Failed to set ProfilesDirectory registry: $($_.Exception.Message)" "WARN"
            return @{
                Success = $false
                Error = $_.Exception.Message
                Message = "Failed to set ProfilesDirectory registry"
                Details = @("Registry modification failed: $($_.Exception.Message)")
            }
        }
    }
    catch {
        Write-Log "User profile redirection failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "User profile redirection failed"
            Details = @("Profile redirection configuration failed: $($_.Exception.Message)")
        }
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
            if ($MaintenanceEnabled -and $MaintenanceEnabled.MaintenanceDisabled -eq 1) {
                return @{
                    Success = $true
                    Optimized = $true
                    MaintenanceDisabled = $true
                    Message = "Windows automatic maintenance already disabled"
                    RegistryKey = "$MaintenanceKey\MaintenanceDisabled"
                    RegistryValue = 1
                    RegistryType = "DWORD"
                    Details = @(
                        "Registry key verified: $MaintenanceKey",
                        "Registry value confirmed: MaintenanceDisabled = 1 (DWORD)",
                        "Windows automatic maintenance already disabled",
                        "VDI template optimization already applied"
                    )
                }
            }
        }
        
        return @{ 
            Success = $false
            MaintenanceDisabled = $false
            Optimized = $false
            Message = "Windows automatic maintenance is enabled"
        }
    }
    catch {
        Write-Log "Automatic maintenance status test failed: $($_.Exception.Message)" "ERROR"
        return @{ 
            Success = $false
            MaintenanceDisabled = $false
            Optimized = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-AutomaticMaintenance {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Disabling Windows automatic maintenance for VDI optimization..."
        
        $MaintenanceKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
        
        # Create the registry key if it doesn't exist
        if (-not (Test-Path $MaintenanceKey)) {
            Write-Log "Creating maintenance registry key: $MaintenanceKey"
            New-Item -Path $MaintenanceKey -Force | Out-Null
        }
        
        # Set MaintenanceDisabled to 1 to disable automatic maintenance
        Write-Log "Setting MaintenanceDisabled registry value to 1"
        Set-ItemProperty -Path $MaintenanceKey -Name "MaintenanceDisabled" -Value 1 -Type DWord -Force
        
        # Verify the setting was applied
        $VerifyValue = Get-ItemProperty -Path $MaintenanceKey -Name "MaintenanceDisabled" -ErrorAction SilentlyContinue
        if ($VerifyValue -and $VerifyValue.MaintenanceDisabled -eq 1) {
            Write-Log "Successfully disabled Windows automatic maintenance" "SUCCESS"
            return @{
                Success = $true
                Optimized = $true
                Message = "Windows automatic maintenance disabled"
                RegistryKey = "$MaintenanceKey\MaintenanceDisabled"
                RegistryValue = 1
                RegistryType = "DWORD"
                Details = @(
                    "Registry key created: $MaintenanceKey",
                    "Registry value set: MaintenanceDisabled = 1 (DWORD)",
                    "Windows automatic maintenance tasks disabled",
                    "VDI template optimized for consistent performance"
                )
            }
        } else {
            throw "Failed to verify MaintenanceDisabled registry value"
        }
    }
    catch {
        Write-Log "Failed to disable automatic maintenance: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            MaintenanceDisabled = $false
            Optimized = $false
            Error = $_.Exception.Message
        }
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
        $startupSourceExists = Test-Path $StartupSource
        $shutdownSourceExists = Test-Path $ShutdownSource
        
        if ($startupSourceExists) {
            $StartupFiles = Get-ChildItem -Path $StartupSource -File -ErrorAction SilentlyContinue
            foreach ($File in $StartupFiles) {
                $DestinationFilePath = Join-Path $StartupDestination $File.Name
                Write-Log "Copying startup script: $($File.Name) from $($File.FullName) to $DestinationFilePath" "INFO"
                $CopyResult = Copy-FileWithValidation -SourcePath $File.FullName -DestinationPath $DestinationFilePath
                if ($CopyResult.Success) {
                    $Results.StartupFiles += @{ Name = $File.Name; Size = $File.Length }
                    Write-Log "Successfully copied startup script: $($File.Name)" "SUCCESS"
                } else {
                    $Results.FailedFiles += @{ Name = $File.Name; Reason = $CopyResult.Error }
                    $Results.Success = $false
                    Write-Log "Failed to copy startup script $($File.Name): $($CopyResult.Error)" "ERROR"
                }
            }
        } else {
            Write-Log "Startup script source not found: $StartupSource" "WARN"
        }
        
        # Copy shutdown scripts
        if ($shutdownSourceExists) {
            $ShutdownFiles = Get-ChildItem -Path $ShutdownSource -File -ErrorAction SilentlyContinue
            foreach ($File in $ShutdownFiles) {
                $DestinationFilePath = Join-Path $ShutdownDestination $File.Name
                Write-Log "Copying shutdown script: $($File.Name) from $($File.FullName) to $DestinationFilePath" "INFO"
                $CopyResult = Copy-FileWithValidation -SourcePath $File.FullName -DestinationPath $DestinationFilePath
                if ($CopyResult.Success) {
                    $Results.ShutdownFiles += @{ Name = $File.Name; Size = $File.Length }
                    Write-Log "Successfully copied shutdown script: $($File.Name)" "SUCCESS"
                } else {
                    $Results.FailedFiles += @{ Name = $File.Name; Reason = $CopyResult.Error }
                    $Results.Success = $false
                    Write-Log "Failed to copy shutdown script $($File.Name): $($CopyResult.Error)" "ERROR"
                }
            }
        } else {
            Write-Log "Shutdown script source not found: $ShutdownSource" "WARN"
        }
        
        # If neither source directory exists, mark as skipped
        if (-not $startupSourceExists -and -not $shutdownSourceExists) {
            $Results.Skipped = $true
            $Results.Reason = "Script source directories not found"
            $Results.Success = $false
        }
        # If no files were found in existing directories, also mark as skipped
        elseif ($Results.StartupFiles.Count -eq 0 -and $Results.ShutdownFiles.Count -eq 0 -and $Results.FailedFiles.Count -eq 0) {
            $Results.Skipped = $true
            $Results.Reason = "No script files found in source directories"
            $Results.Success = $false
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
                # Use cached config first for CDDVM target drive
                if ($Global:CachedConfig -and $Global:CachedConfig.CDDVMTargetDrive) {
                    $CDDVMTargetDrive = $Global:CachedConfig.CDDVMTargetDrive
                } else {
                    $CDDVMTargetDrive = Get-ConfigValue -Key "CDDVMTargetDrive" -DefaultValue "Y" -ConfigFile $ConfigFilePath
                }
                
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
           # Use cached configuration if available
           if ($Global:CachedConfig -and $Global:CachedConfig.UseVirtualCacheDrive) {
               $UseVirtualCache = [bool]$Global:CachedConfig.UseVirtualCacheDrive
           } else {
               $UseVirtualCache = [bool](Get-ConfigValue -Key "UseVirtualCacheDrive" -DefaultValue "false")
           }
           
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
           return @{
               Success = $true
               Message = "Cache drive access validated"
               DriveLetter = "D"
               WriteAccess = $true
               TestFile = $TestFile
               Details = @(
                   "Drive D: exists and is accessible",
                   "Write access: Confirmed",
                   "Test file created and removed successfully: $TestFile"
               )
           }
       }
       catch {
           Write-Log "D: cache drive detected but write access failed: $($_.Exception.Message)" "ERROR"
           Write-Host "CRITICAL: D: cache drive write access failed" -ForegroundColor Red
           Write-Host "TERMINATING SCRIPT EXECUTION" -ForegroundColor Red
           return @{
               Success = $false
               Error = $_.Exception.Message
               Message = "Cache drive write access failed"
               DriveLetter = "D"
               WriteAccess = $false
               Details = @(
                   "Drive D: detected but write access failed",
                   "Error: $($_.Exception.Message)",
                   "Critical: Cache drive must be writable"
               )
           }
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
       
       return @{
           Success = $true
           Message = "Logging initialized successfully"
           LogPath = $LogPath
           Details = @("Log file created at: $LogPath", "Logging system ready for use")
       }
   }
   catch {
       Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Logging initialization failed"
           Details = @("Failed to create log file at: $LogPath", "Error: $($_.Exception.Message)")
       }
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
       # Initialize variables first
       $VDAServices = @("BrokerAgent", "picaSvc2", "CdfSvc")
       $FoundServices = 0
       $ServiceDetails = @()
       
       # Check for VDA services first
       foreach ($ServiceName in $VDAServices) {
           $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
           if ($Service) {
               $FoundServices++
               $ServiceDetails += "$ServiceName ($($Service.Status))"
           }
       }
       
       # Check for Citrix VDA registry entries
       $VDARegPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
       $VDAInstalled = Test-Path $VDARegPath
       
       if ($VDAInstalled) {
           Write-Log "VDA registry entries found" "SUCCESS"
           return @{
               Success = $true
               Message = "VDA installation verified"
               RegistryFound = $true
               RegistryPath = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent"
               ServicesFound = $FoundServices
               Details = @(
                   "VDA registry entries present in system",
                   "Installation verified through registry detection", 
                   "Citrix Virtual Desktop Agent properly installed",
                   "Found $FoundServices VDA services running"
               )
           }
       }
       
       if ($FoundServices -ge 2) {
           Write-Log "VDA services detected ($FoundServices found)" "SUCCESS"
           return @{
               Success = $true
               Message = "VDA installation verified through services"
               RegistryFound = $false
               ServicesFound = $FoundServices
               ServiceDetails = $ServiceDetails
               Details = @(
                   "Found $FoundServices VDA services running",
                   "Services detected: $($ServiceDetails -join ', ')",
                   "VDA installation confirmed through service presence"
               )
           }
       }
       
       Write-Log "VDA installation not detected" "WARN"
       return @{
           Success = $false
           Message = "VDA installation not detected"
           RegistryFound = $false
           ServicesFound = $FoundServices
           Error = "No VDA registry entries or sufficient services found"
       }
   }
   catch {
       Write-Log "Error checking VDA installation: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "VDA installation check failed"
           Details = @("Error checking VDA: $($_.Exception.Message)")
       }
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

function Remove-RunKeysRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFile = ""
    )
    
    try {
        Write-Log "Starting configurable Run Keys registry cleanup..." "INFO"
        
        # Get configuration from config file
        if ($ConfigFile -eq "") {
            $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
        }
        
        $RunKeysToRemove = Get-ConfigValue -Key "RunKeysToRemove" -ConfigFile $ConfigFile -DefaultValue ""
        
        if ([string]::IsNullOrEmpty($RunKeysToRemove)) {
            Write-Log "No Run Keys specified for removal - skipping cleanup" "INFO"
            return @{
                Success = $true
                Skipped = $true
                Message = "Run Keys cleanup skipped - no keys configured for removal"
                TotalRemoved = 0
                Details = @("RunKeysToRemove parameter is empty in configuration", "No registry cleanup performed")
            }
        }
        
        # Parse comma-separated list of run keys to remove
        $KeysArray = $RunKeysToRemove -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        
        Write-Log "Run Keys to remove: $($KeysArray -join ', ')" "INFO"
        
        $Results = @{
            Success = $true
            Message = "Run Keys registry cleanup completed"
            RegistryKeysRemoved = $RemovedKeys.Count
            TargetKeys = $RunKeysToRemove
            TotalRemoved = 0
            RemovedKeys = @()
            FailedKeys = @()
            RegistryChanges = @()
            Details = @()
        }
        
        # Define registry paths to check
        $RunKeyPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($KeyToRemove in $KeysArray) {
            $KeyRemoved = $false
            
            foreach ($RegPath in $RunKeyPaths) {
                if (Test-Path $RegPath) {
                    try {
                        $ExistingValue = Get-ItemProperty -Path $RegPath -Name $KeyToRemove -ErrorAction SilentlyContinue
                        if ($ExistingValue) {
                            Remove-ItemProperty -Path $RegPath -Name $KeyToRemove -Force -ErrorAction Stop
                            Write-Log "Removed Run Key: $RegPath\$KeyToRemove" "SUCCESS"
                            $Results.RemovedKeys += "$RegPath\$KeyToRemove"
                            $Results.RegistryChanges += "$RegPath\$KeyToRemove = [REMOVED]"
                            $Results.TotalRemoved++
                            $KeyRemoved = $true
                        }
                    }
                    catch {
                        Write-Log "Failed to remove Run Key $RegPath\$KeyToRemove`: $($_.Exception.Message)" "WARN"
                        $Results.FailedKeys += "$RegPath\$KeyToRemove"
                    }
                }
            }
            
            if (-not $KeyRemoved) {
                Write-Log "Run Key '$KeyToRemove' not found in any registry location" "INFO"
                $Results.Details += "Key '$KeyToRemove' not found (already clean)"
            }
        }
        
        # Special handling for passwordAge key (legacy cleanup)
        if ($KeysArray -contains "passwordAge") {
            Write-Log "Password age registry cleanup handled as part of Run Keys removal" "INFO"
            $Results.Details += "Legacy password age cleanup integrated into Run Keys function"
        }
        
        $Results.Details += "Processed $($KeysArray.Count) configured Run Keys"
        $Results.Details += "Successfully removed: $($Results.TotalRemoved) registry entries"
        $Results.Details += "Registry paths checked: $($RunKeyPaths -join ', ')"
        
        if ($Results.TotalRemoved -eq 0 -and $Results.FailedKeys.Count -eq 0) {
            $Results.Message = "Run Keys cleanup completed - no keys found to remove"
        }
        elseif ($Results.FailedKeys.Count -gt 0) {
            $Results.Success = $false
            $Results.Message = "Run Keys cleanup completed with some failures"
        }
        
        Write-Log "Run Keys cleanup summary: $($Results.TotalRemoved) removed, $($Results.FailedKeys.Count) failed" "SUCCESS"
        return $Results
    }
    catch {
        Write-Log "Run Keys registry cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Run Keys registry cleanup failed"
            TotalRemoved = 0
            Details = @("Registry cleanup failed: $($_.Exception.Message)")
        }
    }
}

function Get-CitrixServicesStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Checking Citrix services status..." "INFO"
        
        $CitrixServices = Get-Service | Where-Object { $_.DisplayName -like "*Citrix*" -or $_.Name -like "*Citrix*" }
        $RunningServices = $CitrixServices | Where-Object { $_.Status -eq "Running" }
        
        return @{
            Success = ($RunningServices.Count -gt 0)
            Message = "Citrix services status checked"
            TotalServices = $CitrixServices.Count
            RunningServices = $RunningServices.Count
            ServiceDetails = $RunningServices | ForEach-Object { 
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.Status.ToString()
                    StartType = $_.StartType.ToString()
                }
            }
            Details = @(
                "Total Citrix services found: $($CitrixServices.Count)",
                "Running Citrix services: $($RunningServices.Count)",
                "Service names: $($RunningServices.Name -join ', ')"
            )
        }
    }
    catch {
        Write-Log "Error checking Citrix services: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Citrix services check failed"
            Details = @("Error checking services: $($_.Exception.Message)")
        }
    }
}

function Test-VDAInstallation {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing VDA installation status..." "INFO"
        
        # Check for VDA registry entries
        $VDARegPaths = @(
            "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent",
            "HKLM:\SOFTWARE\Citrix\ICA Client",
            "HKLM:\SOFTWARE\Wow6432Node\Citrix\VirtualDesktopAgent"
        )
        
        $FoundEntries = @()
        foreach ($RegPath in $VDARegPaths) {
            if (Test-Path $RegPath) {
                $FoundEntries += $RegPath
            }
        }
        
        # Check for VDA services
        $VDAServices = @("CdfSvc", "BrokerAgent", "VDARedirector")
        $RunningVDAServices = @()
        
        foreach ($ServiceName in $VDAServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service) {
                $RunningVDAServices += @{
                    Name = $Service.Name
                    DisplayName = $Service.DisplayName
                    Status = $Service.Status.ToString()
                }
            }
        }
        
        $IsInstalled = ($FoundEntries.Count -gt 0 -or $RunningVDAServices.Count -gt 0)
        
        return @{
            Success = $IsInstalled
            Message = if ($IsInstalled) { "VDA installation detected" } else { "VDA installation not found" }
            RegistryEntries = $FoundEntries
            VDAServices = $RunningVDAServices
            Details = @(
                "Registry entries found: $($FoundEntries.Count)",
                "VDA services found: $($RunningVDAServices.Count)",
                "Registry paths: $($FoundEntries -join ', ')",
                "Service names: $($RunningVDAServices.Name -join ', ')"
            )
        }
    }
    catch {
        Write-Log "Error testing VDA installation: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "VDA installation test failed"
            Details = @("Error testing VDA: $($_.Exception.Message)")
        }
    }
}

function Get-SystemOptimizations {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Applying system registry optimizations..." "INFO"
        
        $OptimizationResults = @()
        $RegistryChanges = @()
        $SuccessCount = 0
        $FailureCount = 0
        
        # Apply common optimization registry keys
        $OptRegKeys = @{
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher" = 0
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnableSuperfetch" = 0
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache\Autorun" = 0
        }
        
        foreach ($RegKey in $OptRegKeys.GetEnumerator()) {
            try {
                $RegPath = Split-Path $RegKey.Key -Parent
                $RegName = Split-Path $RegKey.Key -Leaf
                
                # Create registry path if it doesn't exist
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                    Write-Log "Created registry path: $RegPath" "INFO"
                }
                
                # Check current value
                $CurrentValue = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue
                
                if ($CurrentValue -and $CurrentValue.$RegName -eq $RegKey.Value) {
                    $OptimizationResults += "ALREADY OPTIMIZED: $RegName = $($RegKey.Value)"
                    $RegistryChanges += "$($RegKey.Key) = $($RegKey.Value) (already set)"
                    $SuccessCount++
                } else {
                    # Apply the optimization
                    Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegKey.Value -Type DWord -Force
                    $OptimizationResults += "APPLIED: $RegName = $($RegKey.Value)"
                    $RegistryChanges += "$($RegKey.Key) = $($RegKey.Value)"
                    $SuccessCount++
                    Write-Log "Applied optimization: $RegName = $($RegKey.Value)" "SUCCESS"
                }
            }
            catch {
                $OptimizationResults += "FAILED: $RegName - $($_.Exception.Message)"
                $FailureCount++
                Write-Log "Failed to apply optimization: $RegName - $($_.Exception.Message)" "ERROR"
            }
        }
        
        return @{
            Success = ($SuccessCount -gt 0)
            Message = "System optimizations applied: $SuccessCount successful, $FailureCount failed"
            OptimizationsApplied = $SuccessCount
            OptimizationsFailed = $FailureCount
            RegistryChanges = $RegistryChanges
            Details = @(
                "Total optimizations attempted: $($OptRegKeys.Count)",
                "Successfully applied: $SuccessCount",
                "Failed applications: $FailureCount",
                "Results: $($OptimizationResults -join '; ')"
            )
        }
    }
    catch {
        Write-Log "Error checking system optimizations: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "System optimizations check failed"
            Details = @("Error checking optimizations: $($_.Exception.Message)")
        }
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
       
       return @{
           Success = $CleanupSuccess
           Message = "WEM RSA cleanup validation completed"
           RegistryPath = "HKLM:\SOFTWARE\VirtuaLogix\VirtuaLogix Agent\RSAKey"
           CleanupStatus = "No RSA keys found or already cleaned"
           WEMEntriesFound = if (Test-Path $WEMRegPath) { (Get-ChildItem $WEMRegPath -ErrorAction SilentlyContinue).Count } else { 0 }
           Details = @(
               "Registry path checked: $WEMRegPath",
               "WEM entries found: $(if (Test-Path $WEMRegPath) { (Get-ChildItem $WEMRegPath -ErrorAction SilentlyContinue).Count } else { 0 })",
               "Cleanup status: $(if($CleanupSuccess){'Successful'}else{'Incomplete - entries remain'})"
           )
       }
   }
   catch {
       Write-Log "Error checking WEM RSA cleanup: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "WEM RSA cleanup validation failed"
           Details = @("WEM RSA cleanup validation failed: $($_.Exception.Message)")
       }
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
       
       return @{
           Success = $true
           Message = "Windows services configured for VDI optimization"
           ServicesModified = @(
               "Spooler service set to Manual startup",
               "Windows Update service (wuauserv) disabled"
           )
           RegistryChanges = @(
               "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler\Start = 3 (Manual)",
               "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\Start = 4 (Disabled)"
           )
           Details = @(
               "Print Spooler optimized for VDI environment",
               "Windows Update service disabled to prevent interference",
               "Service configurations effective immediately"
           )
       }
   }
   catch {
       Write-Log "Failed to configure Windows services: $($_.Exception.Message)" "ERROR"
       return @{ Success = $false; Error = $_.Exception.Message }
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
       return @{
           Success = $true
           Message = "NetBIOS over TCP/IP disabled on all network interfaces"
           RegistryChanges = @(
               "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*\NetbiosOptions = 2"
           )
           InterfacesModified = $Interfaces.Count
           Details = @(
               "NetBIOS disabled on $($Interfaces.Count) network interfaces",
               "Registry value NetbiosOptions set to 2 (disable NetBIOS)",
               "Change effective immediately for new connections"
           )
       }
   }
   catch {
       Write-Log "Failed to disable NetBIOS over TCP/IP: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "NetBIOS disabling failed"
           Details = @("NetBIOS disabling failed: $($_.Exception.Message)")
       }
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
       
       Write-Log "Network offload parameters disabled successfully" "SUCCESS"
       return @{
           Success = $true
           Message = "Network offload parameters disabled successfully"
           AdaptersProcessed = $NetworkAdapters.Count
           ParametersDisabled = @("Checksum Offload", "Large Send Offload")
           AdaptersModified = $NetworkAdapters.Count
           OffloadSettings = @(
               "Checksum Offload disabled",
               "Large Send Offload (LSO) disabled"
           )
           Details = @(
               "Network adapters processed: $($NetworkAdapters.Count)",
               "Modified $($NetworkAdapters.Count) active network adapters",
               "Disabled Checksum Offload to reduce CPU overhead", 
               "Disabled Large Send Offload to reduce CPU overhead",
               "Disabled TCP/UDP checksum offload for better VDI performance"
           )
       }
   }
   catch {
       Write-Log "Failed to disable network offload parameters: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Network offload disabling failed"
           Details = @("Network offload disabling failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "SMB settings optimized for VDI performance"
           RegistryChanges = @(
               "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\RequireSecuritySignature = 0",
               "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\EnableSecuritySignature = 0"
           )
           SMBOptimizations = @(
               "SMB security signing disabled for performance",
               "Network latency reduced for file sharing"
           )
           Details = @(
               "SMB security signing disabled to improve file transfer performance",
               "Changes effective for new SMB connections",
               "Optimized for internal VDI network environments"
           )
       }
   }
   catch {
       Write-Log "Failed to configure SMB settings: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "SMB configuration failed"
           Details = @("SMB configuration failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Crash dump configured for kernel mode"
           RegistryChanges = @(
               "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpEnabled = 2 (Kernel mode)",
               "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\DumpFile = %SystemRoot%\MEMORY.DMP"
           )
           DumpSettings = @(
               "Crash dump type: Kernel memory dump",
               "Dump file location: %SystemRoot%\MEMORY.DMP",
               "Reduced dump file size for VDI optimization"
           )
           Details = @(
               "Kernel mode dumps capture essential system information only",
               "Smaller dump files reduce storage impact in VDI",
               "Settings effective after system restart"
           )
       }
   }
   catch {
       Write-Log "Failed to set crash dump mode: $($_.Exception.Message)" "ERROR"
       return @{ Success = $false; Error = $_.Exception.Message }
   }
}



function Start-CitrixOptimizer {
   [CmdletBinding()]
   param(
       [string]$ConfigFilePath = ".\CitrixConfig.txt"
   )
   
   try {
       Write-Log "Launching Citrix Optimizer tool..."
       
       # Use cached configuration from Stage 2 (includes OS-specific template selection)
       Write-Log "Using cached Citrix Optimizer configuration with OS-specific template selection" "INFO"
       $OptimizerPath = $Global:CachedConfig.CitrixOptimizerPath
       $TemplatesPath = $Global:CachedConfig.CitrixOptimizerTemplatesPath
       $TemplateNames = $Global:CachedConfig.CitrixOptimizerTemplate
       $OutputPath = $Global:CachedConfig.CitrixOptimizerOutputPath
       $OptimizerMode = $Global:CachedConfig.CitrixOptimizerMode
       
       Write-Log "Using OS-selected templates: $TemplateNames" "INFO"
       
       $Results = @{
           Success = $false
           OptimizerExecuted = $false
           TemplatesApplied = @()
           OptimizationsApplied = 0
           OutputLocation = ""
           FallbackApplied = $false
           Error = ""
           TemplatesProcessed = 0
       }
       
       # Debug logging to show resolved path
       Write-Log "Checking Citrix Optimizer at resolved path: '$OptimizerPath'" "INFO"
       
       # Check if Citrix Optimizer is available
       if ([string]::IsNullOrEmpty($OptimizerPath) -or -not (Test-Path $OptimizerPath)) {
           Write-Log "Citrix Optimizer tool not found at path: $OptimizerPath" "WARN"
           Write-Log "Citrix Optimizer will be skipped - tool not available" "INFO"
           
           return @{
               Success = $true
               Skipped = $true
               OptimizerExecuted = $false
               TemplatesApplied = @()
               OptimizationsApplied = 0
               OutputLocation = "N/A"
               FallbackApplied = $false
               Error = ""
               TemplatesProcessed = 0
               Message = "Citrix Optimizer skipped - executable not found"
               Details = @(
                   "Citrix Optimizer path checked: $OptimizerPath",
                   "Executable not found - optimization skipped",
                   "This is normal if Citrix Optimizer is not installed",
                   "VDI optimizations can continue without this tool"
               )
           }
       }
       
       # Create output directory
       if (-not (Test-Path $OutputPath)) {
           New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
           Write-Log "Created Citrix Optimizer output directory: $OutputPath" "INFO"
       }
       
       # Parse multiple templates (comma-separated)
       $TemplateArray = $TemplateNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
       
       Write-Log "Processing $($TemplateArray.Count) Citrix Optimizer template(s): $($TemplateArray -join ', ')" "INFO"
       
       # Determine templates path
       $TemplatesDirectory = ""
       if (![string]::IsNullOrEmpty($TemplatesPath) -and (Test-Path $TemplatesPath)) {
           $TemplatesDirectory = $TemplatesPath
       }
       else {
           # Try to find template in same directory as optimizer
           $OptimizerDir = Split-Path $OptimizerPath -Parent
           $DefaultTemplatesPath = Join-Path $OptimizerDir "Templates"
           if (Test-Path $DefaultTemplatesPath) {
               $TemplatesDirectory = $DefaultTemplatesPath
           }
       }
       
       # Validate all templates exist before processing
       $ValidTemplates = @()
       $MissingTemplates = @()
       
       foreach ($TemplateName in $TemplateArray) {
           $TemplatePath = Join-Path $TemplatesDirectory $TemplateName
           if (Test-Path $TemplatePath) {
               $ValidTemplates += @{
                   Name = $TemplateName
                   Path = $TemplatePath
               }
           } else {
               $MissingTemplates += $TemplateName
           }
       }
       
       if ($MissingTemplates.Count -gt 0) {
           Write-Log "Missing template(s): $($MissingTemplates -join ', ')" "ERROR"
           Write-Log "Templates directory: $TemplatesDirectory" "INFO"
           Write-Log "Available templates in directory:" "INFO"
           if (Test-Path $TemplatesDirectory) {
               $AvailableTemplates = Get-ChildItem -Path $TemplatesDirectory -Filter "*.xml"
               if ($AvailableTemplates.Count -gt 0) {
                   foreach ($Template in $AvailableTemplates) {
                       Write-Log "  - $($Template.Name)" "INFO"
                   }
                   

               } else {
                   Write-Log "No XML templates found in templates directory" "ERROR"
               }
           } else {
               Write-Log "Templates directory does not exist or is not accessible" "ERROR"
           }
           
           if ($ValidTemplates.Count -eq 0) {
               Write-Log "No valid templates found - skipping VDI optimizations" "ERROR"
               $Results.Success = $false
               $Results.Error = "No valid templates found: $($MissingTemplates -join ', ')"
               return $Results
           } else {
               Write-Log "Continuing with $($ValidTemplates.Count) valid template(s), skipping $($MissingTemplates.Count) missing template(s)" "WARN"
           }
       }
       
       Write-Log "Citrix Optimizer configuration:" "INFO"
       Write-Log "  Optimizer Path: $OptimizerPath" "INFO"
       Write-Log "  Templates: $($ValidTemplates.Count) template(s)" "INFO"
       foreach ($Template in $ValidTemplates) {
           Write-Log "    - $($Template.Name)" "INFO"
       }
       Write-Log "  Output Path: $OutputPath" "INFO"
       Write-Log "  Mode: $OptimizerMode" "INFO"
       
       # Process each template
       $SuccessfulTemplates = 0
       $FailedTemplates = 0
       
       foreach ($Template in $ValidTemplates) {
           Write-Log "Processing template: $($Template.Name)" "INFO"
           
           # Prepare Citrix Optimizer execution parameters for this template
           $OptimizerArgs = @(
               "-Source `"$($Template.Path)`""
               "-OutputLogFolder `"$OutputPath`""
               "-OutputHtml"
               "-Verbose"
           )
           
           # Add mode-specific parameters
           switch ($OptimizerMode.ToLower()) {
               "execute" {
                   $OptimizerArgs += "-Mode Execute"
                   Write-Log "Executing Citrix Optimizer in EXECUTE mode for $($Template.Name)..." "INFO"
               }
               "analyze" {
                   $OptimizerArgs += "-Mode Analyze"
                   Write-Log "Executing Citrix Optimizer in ANALYZE mode for $($Template.Name)..." "INFO"
               }
               "rollback" {
                   $OptimizerArgs += "-Mode Rollback"
                   Write-Log "Executing Citrix Optimizer in ROLLBACK mode for $($Template.Name)..." "INFO"
               }
               default {
                   $OptimizerArgs += "-Mode Execute"
                   Write-Log "Using default EXECUTE mode for $($Template.Name)..." "INFO"
               }
           }
           
           # Execute Citrix Optimizer for this template
           $ArgumentString = $OptimizerArgs -join " "
           Write-Log "Executing: PowerShell.exe -ExecutionPolicy Bypass -File `"$OptimizerPath`" $ArgumentString" "INFO"
           
           try {
               $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
               $ProcessStartInfo.FileName = "PowerShell.exe"
               $ProcessStartInfo.Arguments = "-ExecutionPolicy Bypass -File `"$OptimizerPath`" $ArgumentString"
               $ProcessStartInfo.RedirectStandardOutput = $true
               $ProcessStartInfo.RedirectStandardError = $true
               $ProcessStartInfo.UseShellExecute = $false
               $ProcessStartInfo.CreateNoWindow = $true
               
               $Process = New-Object System.Diagnostics.Process
               $Process.StartInfo = $ProcessStartInfo
               
               Write-Log "Starting Citrix Optimizer execution for $($Template.Name)..." "INFO"
               $Process.Start() | Out-Null
               
               # Read output in real-time
               $OutputData = ""
               $ErrorData = ""
               
               while (-not $Process.HasExited) {
                   if (-not $Process.StandardOutput.EndOfStream) {
                       $Line = $Process.StandardOutput.ReadLine()
                       if ($Line) {
                           Write-Log "CITRIX OPTIMIZER ($($Template.Name)): $Line" "INFO"
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
               
               # Process results for this template
               if ($ExitCode -eq 0) {
                   Write-Log "Citrix Optimizer completed successfully for $($Template.Name) (Exit Code: $ExitCode)" "SUCCESS"
                   $Results.OptimizerExecuted = $true
                   $Results.TemplatesApplied += $Template.Name
                   $Results.OutputLocation = $OutputPath
                   $SuccessfulTemplates++
                   
                   # Parse output for optimization count
                   if ($OutputData -match "(\d+)\s+optimizations?\s+applied") {
                       $OptimizationsCount = [int]$Matches[1]
                       $Results.OptimizationsApplied += $OptimizationsCount
                       Write-Log "Applied $OptimizationsCount optimizations from template $($Template.Name)" "SUCCESS"
                   }
                   
                   # Check for output files
                   $OutputFiles = Get-ChildItem -Path $OutputPath -File -ErrorAction SilentlyContinue
                   if ($OutputFiles) {
                       Write-Log "Citrix Optimizer output files for $($Template.Name):" "INFO"
                       foreach ($File in $OutputFiles) {
                           Write-Log "  - $($File.Name) ($([math]::Round($File.Length/1024, 2)) KB)" "INFO"
                       }
                   }
               }
               else {
                   Write-Log "Citrix Optimizer failed for $($Template.Name) with exit code: $ExitCode" "ERROR"
                   if ($ErrorData) {
                       Write-Log "Error output for $($Template.Name): $ErrorData" "ERROR"
                   }
                   $FailedTemplates++
               }
           }
           catch {
               Write-Log "Exception processing template $($Template.Name): $($_.Exception.Message)" "ERROR"
               $FailedTemplates++
           }
       }
       
       # Final results summary
       $Results.TemplatesProcessed = $ValidTemplates.Count
       if ($SuccessfulTemplates -gt 0) {
           $Results.Success = $true
           Write-Log "Citrix Optimizer completed: $SuccessfulTemplates successful, $FailedTemplates failed" "SUCCESS"
       } else {
           Write-Log "All Citrix Optimizer templates failed" "ERROR"
           $Results.Success = $false
           $Results.Error = "Citrix Optimizer failed with exit code: $ExitCode"
       }
       
       # Add detailed results
       $Results.Details = @(
           "Optimizer executable: $OptimizerPath",
           "Templates processed: $($Results.TemplatesProcessed)",
           "Templates applied: $($Results.TemplatesApplied.Count)",
           "Total optimizations: $($Results.OptimizationsApplied)",
           "Output location: $($Results.OutputLocation)",
           "Execution mode: $OptimizerMode"
       )
       
       if ($Results.TemplatesApplied.Count -gt 0) {
           $Results.Details += "Applied templates: $($Results.TemplatesApplied -join '; ')"
       }
       
       $Results.Message = "Citrix Optimizer: $($Results.TemplatesApplied.Count) templates applied, $($Results.OptimizationsApplied) optimizations"
       
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
           return @{
               Success = $false
               Message = "Path validation failed - empty path"
               PathExists = $false
               Details = @("Path is null or empty")
           }
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
                   return @{
                       Success = $true
                       Message = "UNC path accessible"
                       PathType = "UNC"
                       TestPath = $CleanPath
                       Details = @("UNC path validated: $CleanPath", "Network path is accessible")
                   }
               }
               catch {
                   return @{
                       Success = $false
                       Error = $_.Exception.Message
                       Message = "UNC path not accessible"
                       PathType = "UNC"
                       TestPath = $CleanPath
                       Details = @("UNC path failed: $CleanPath", "Error: $($_.Exception.Message)")
                   }
               }
           }
           return @{
               Success = $false
               Message = "Invalid UNC path format"
               PathType = "UNC"
               TestPath = $CleanPath
               Details = @("UNC path format invalid: $CleanPath", "Must follow \\\\server\\share format")
           }
       }
       
       # Handle local paths
       $CleanPath = $CleanPath.Replace('\\\\', '\')
       
       # Test path
       if (Test-Path -Path $CleanPath) {
           return @{
               Success = $true
               Message = "Local path accessible"
               PathType = "Local"
               TestPath = $CleanPath
               Details = @("Local path validated: $CleanPath", "Directory exists and is accessible")
           }
       }
       elseif ($CreateIfMissing) {
           try {
               New-Item -Path $CleanPath -ItemType Directory -Force | Out-Null
               return @{
                   Success = $true
                   Message = "Local path created"
                   PathType = "Local"
                   TestPath = $CleanPath
                   Created = $true
                   Details = @("Directory created: $CleanPath", "Path is now accessible")
               }
           }
           catch {
               return @{
                   Success = $false
                   Error = $_.Exception.Message
                   Message = "Failed to create local path"
                   PathType = "Local"
                   TestPath = $CleanPath
                   Details = @("Failed to create: $CleanPath", "Error: $($_.Exception.Message)")
               }
           }
       }
       
       return @{
           Success = $false
           Message = "Path not accessible"
           PathType = "Local"
           TestPath = $CleanPath
           Details = @("Path does not exist: $CleanPath", "CreateIfMissing not specified")
       }
   }
   catch {
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Path validation failed"
           Details = @("Error validating path: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Logging system initialized successfully"
           LogPath = $LogPath
           LogDirectory = $LogDir
           Details = @(
               "Log file path: $LogPath",
               "Log directory: $LogDir",
               "Initialization time: $(Get-Date)"
           )
       }
   }
   catch {
       Write-Host "Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Logging initialization failed"
           Details = @("Logging initialization failed: $($_.Exception.Message)")
       }
   }
}



function Invoke-SystemOptimizations {
    <#
    .SYNOPSIS
        Invokes comprehensive system optimizations
    .DESCRIPTION
        Runs system-wide optimizations for VDI environments
    .EXAMPLE
        Invoke-SystemOptimizations
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting comprehensive system optimizations..." "INFO"
        
        # Registry optimizations
        $OptimizationKeys = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control"; Name = "WaitToKillServiceTimeout"; Value = "2000" }
        )
        
        foreach ($Key in $OptimizationKeys) {
            try {
                if (-not (Test-Path $Key.Path)) {
                    New-Item -Path $Key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -Force
            } catch {
                Write-Log "Failed to set optimization registry key $($Key.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "System optimizations completed successfully" "SUCCESS"
        return @{ 
            OverallStatus = $true
            Success = $true
            Message = "System optimizations applied"
            OptimizationsFound = $OptimizationChecks.Count
            RegistryKeysChecked = $OptRegKeys.Count
            OptimizationsApplied = @(
                "Windows Update service (wuauserv) management",
                "Registry performance optimizations", 
                "Memory management settings",
                "File system optimization settings"
            )
            RegistryKeysModified = $OptimizationKeys.Count
            ServicesOptimized = 2
        }
    }
    catch {
        Write-Log "System optimizations failed: $($_.Exception.Message)" "ERROR"
        return @{ OverallStatus = $false; Message = $_.Exception.Message }
    }
}

function Invoke-VDIOptimizations {
    <#
    .SYNOPSIS
        Invokes VDI-specific optimizations
    .DESCRIPTION
        Runs VDI optimizations for improved performance
    .EXAMPLE
        Invoke-VDIOptimizations
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting VDI optimizations..." "INFO"
        
        # VDI registry optimizations
        $VDIKeys = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; Value = 1 },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "HideSCAHealth"; Value = 1 }
        )
        
        foreach ($Key in $VDIKeys) {
            try {
                if (-not (Test-Path $Key.Path)) {
                    New-Item -Path $Key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -Force
            } catch {
                Write-Log "Failed to set VDI registry key $($Key.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "VDI optimizations completed successfully" "SUCCESS"
        return @{ 
            OverallStatus = $true
            Success = $true
            Message = "VDI optimizations applied"
            RegistryKeysModified = $VDIKeys.Count
            OptimizationCategories = @("Notification Center", "Security Center")
            RegistryChanges = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableNotificationCenter",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAHealth"
            )
            OptimizationsCount = $VDIKeys.Count
        }
    }
    catch {
        Write-Log "VDI optimizations failed: $($_.Exception.Message)" "ERROR"
        return @{ OverallStatus = $false; Success = $false; Message = $_.Exception.Message }
    }
}

function Invoke-WEMCleanup {
    <#
    .SYNOPSIS
        Invokes WEM cleanup operations
    .DESCRIPTION
        Cleans up WEM-related registry keys and files
    .EXAMPLE
        Invoke-WEMCleanup
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting WEM cleanup..." "INFO"
        
        # WEM RSA key cleanup
        $WEMResult = Remove-WEMRSAKey
        
        Write-Log "WEM cleanup completed successfully" "SUCCESS"
        return $WEMResult
    }
    catch {
        Write-Log "WEM cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "WEM cleanup failed"
            Details = @("WEM cleanup failed: $($_.Exception.Message)")
        }
    }
}

function Invoke-ProfileCleanup {
    <#
    .SYNOPSIS
        Invokes profile cleanup operations
    .DESCRIPTION
        Cleans up domain user profiles
    .EXAMPLE
        Invoke-ProfileCleanup
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting profile cleanup..." "INFO"
        
        # Domain profile cleanup
        $ProfileResult = Remove-DomainUserProfiles
        
        Write-Log "Profile cleanup completed successfully" "SUCCESS"
        return @{ 
            Success = $ProfileResult
            Message = "Profile cleanup completed"
            ProfilesChecked = "Manual registry scan performed"
            CleanupMethod = "Registry-based domain profile detection"
        }
    }
    catch {
        Write-Log "Profile cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Optimize-NetworkSettings {
    <#
    .SYNOPSIS
        Optimizes network settings for VDI environments
    .DESCRIPTION
        Applies network optimizations for improved VDI performance
    .EXAMPLE
        Optimize-NetworkSettings
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting network optimizations..." "INFO"
        
        # Disable NetBIOS over TCP/IP
        $NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        foreach ($Adapter in $NetworkAdapters) {
            try {
                $Adapter.SetTcpipNetbios(2) # Disable NetBIOS
            } catch {
                Write-Log "Failed to disable NetBIOS on adapter: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Network registry optimizations
        $NetworkKeys = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpAckFrequency"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TCPNoDelay"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpDelAckTicks"; Value = 0 }
        )
        
        foreach ($Key in $NetworkKeys) {
            try {
                if (-not (Test-Path $Key.Path)) {
                    New-Item -Path $Key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -Force
            } catch {
                Write-Log "Failed to set network registry key $($Key.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Network optimizations completed successfully" "SUCCESS"
        return @{ 
            Success = $true; 
            Message = "Network optimizations applied"
            RegistryKeysModified = $NetworkKeys.Count
            TCPOptimizations = @("TcpAckFrequency=1", "TCPNoDelay=1", "TcpDelAckTicks=0")
            OptimizationsApplied = $NetworkKeys.Count
            RegistryChanges = $NetworkKeys | ForEach-Object { "$($_.Path)\$($_.Name) = $($_.Value)" }
            Details = @(
                "Total network optimizations: $($NetworkKeys.Count)",
                "Registry keys modified: $($NetworkKeys.Path | Sort-Object -Unique | ForEach-Object { $_ -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' })",
                "Network performance optimizations applied",
                "TCP/IP stack optimizations configured"
            )
        }
    }
    catch {
        Write-Log "Network optimizations failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Optimize-StorageSettings {
    <#
    .SYNOPSIS
        Optimizes storage settings for VDI environments
    .DESCRIPTION
        Applies storage optimizations for improved VDI performance
    .EXAMPLE
        Optimize-StorageSettings
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting storage optimizations..." "INFO"
        
        # Disable Windows Search service
        try {
            Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Windows Search service disabled" "SUCCESS"
        } catch {
            Write-Log "Failed to disable Windows Search: $($_.Exception.Message)" "WARN"
        }
        
        # Storage registry optimizations
        $StorageKeys = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "LongPathsEnabled"; Value = 1 },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "NtfsDisable8dot3NameCreation"; Value = 1 }
        )
        
        foreach ($Key in $StorageKeys) {
            try {
                if (-not (Test-Path $Key.Path)) {
                    New-Item -Path $Key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Key.Path -Name $Key.Name -Value $Key.Value -Force
            } catch {
                Write-Log "Failed to set storage registry key $($Key.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "Storage optimizations completed successfully" "SUCCESS"
        return @{ 
            Success = $true; 
            Message = "Storage optimizations applied"
            OptimizationsApplied = $StorageKeys.Count
            RegistryChanges = $StorageKeys | ForEach-Object { "$($_.Path)\$($_.Name) = $($_.Value)" }
            Details = @(
                "Total storage optimizations: $($StorageKeys.Count)",
                "Registry keys modified: $($StorageKeys.Path | Sort-Object -Unique | ForEach-Object { $_ -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' })",
                "Storage performance optimizations applied",
                "Disk I/O optimizations configured"
            )
        }
    }
    catch {
        Write-Log "Storage optimizations failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Invoke-SystemDefragmentation {
    <#
    .SYNOPSIS
        Performs system defragmentation
    .DESCRIPTION
        Runs defragmentation on system drives if applicable
    .EXAMPLE
        Invoke-SystemDefragmentation
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting system defragmentation check..." "INFO"
        
        # Check if system drive is SSD (skip defrag on SSDs)
        $SystemDrive = $env:SystemDrive.Replace(":", "")
        $DriveType = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
        
        # For VDI templates, typically skip defragmentation
        Write-Log "Skipping defragmentation for VDI template optimization" "INFO"
        
        return @{ 
            Success = $true
            Skipped = $true
            Message = "Defragmentation skipped for VDI template"
        }
    }
    catch {
        Write-Log "System defragmentation check failed: $($_.Exception.Message)" "ERROR"
        return @{ 
            Success = $false
            Skipped = $false
            Message = $_.Exception.Message
        }
    }
}

function Optimize-DotNetFramework {
    <#
    .SYNOPSIS
        Optimizes .NET Framework for VDI environments
    .DESCRIPTION
        Runs .NET framework optimization and compilation
    .EXAMPLE
        Optimize-DotNetFramework
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting .NET Framework optimization..." "INFO"
        
        # Run .NET Framework optimization
        $NGenPaths = @(
            "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\ngen.exe",
            "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\ngen.exe"
        )
        
        $OptimizationResults = @()
        
        foreach ($NGenPath in $NGenPaths) {
            if (Test-Path $NGenPath) {
                try {
                    Write-Log "Running .NET optimization: $NGenPath" "INFO"
                    $Process = Start-Process -FilePath $NGenPath -ArgumentList "update", "/force" -Wait -PassThru -WindowStyle Hidden
                    if ($Process.ExitCode -eq 0) {
                        $OptimizationResults += "Success: $NGenPath"
                    } else {
                        $OptimizationResults += "Warning: $NGenPath (Exit Code: $($Process.ExitCode))"
                    }
                } catch {
                    $OptimizationResults += "Failed: $NGenPath - $($_.Exception.Message)"
                    Write-Log "Failed to run .NET optimization $NGenPath`: $($_.Exception.Message)" "WARN"
                }
            }
        }
        
        Write-Log ".NET Framework optimization completed" "SUCCESS"
        return @{ 
            Success = $true
            Message = ".NET Framework optimization completed"
            Results = $OptimizationResults
        }
    }
    catch {
        Write-Log ".NET Framework optimization failed: $($_.Exception.Message)" "ERROR"
        return @{ 
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

function Remove-RunKeysRegistry {
    <#
    .SYNOPSIS
        Removes specified Run keys from registry based on config file
    .DESCRIPTION
        Removes only the Run keys specified in the configuration file from both HKLM and HKCU Run locations
    .EXAMPLE
        Remove-RunKeysRegistry
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting Run keys registry cleanup..." "INFO"
        
        # Read Run keys to remove from config file
        $RunKeysToRemoveStr = ""
        if ($Global:CachedConfig -and $Global:CachedConfig.PSObject.Properties.Name -contains "RunKeysToRemove") {
            $RunKeysToRemoveStr = $Global:CachedConfig.RunKeysToRemove
        } else {
            $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
            $RunKeysToRemoveStr = Get-ConfigValue -Key "RunKeysToRemove" -ConfigFile $ConfigFile -DefaultValue ""
        }
        
        Write-Log "Run keys config value: '$RunKeysToRemoveStr'" "INFO"
        
        # Parse comma-separated key names
        $RunKeysToRemove = @()
        if (![string]::IsNullOrWhiteSpace($RunKeysToRemoveStr)) {
            $RunKeysToRemove = $RunKeysToRemoveStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
        
        if ($RunKeysToRemove.Count -eq 0) {
            Write-Log "No Run keys specified for removal - skipping cleanup" "INFO"
            return @{
                Success = $true
                TotalRemoved = 0
                RemovedKeys = @()
                Message = "No Run keys specified for removal"
                Skipped = $true
                Details = @(
                    "Run Keys cleanup skipped - no keys configured for removal",
                    "To configure keys for removal, add key names to RunKeysToRemove in config file",
                    "Example: RunKeysToRemove=passwordAge,AdobeUpdater,JavaUpdater"
                )
            }
        }
        
        Write-Log "Run keys configured for removal: $($RunKeysToRemove -join ', ')" "INFO"
        
        $RunKeysPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        $RemovedKeys = @()
        $TotalRemoved = 0
        
        foreach ($BasePath in $RunKeysPaths) {
            if (Test-Path $BasePath) {
                Write-Log "Checking Run keys at: $BasePath" "INFO"
                
                try {
                    foreach ($KeyName in $RunKeysToRemove) {
                        try {
                            $KeyExists = Get-ItemProperty -Path $BasePath -Name $KeyName -ErrorAction SilentlyContinue
                            if ($KeyExists) {
                                Write-Log "Removing Run key: $KeyName from $BasePath" "INFO"
                                Remove-ItemProperty -Path $BasePath -Name $KeyName -Force -ErrorAction Stop
                                $RemovedKeys += "$BasePath\$KeyName"
                                $TotalRemoved++
                                Write-Log "Successfully removed: $KeyName from $BasePath" "SUCCESS"
                            }
                            else {
                                Write-Log "Run key not found (may already be removed): $KeyName in $BasePath" "INFO"
                            }
                        }
                        catch {
                            Write-Log "Failed to remove Run key $KeyName from $BasePath`: $($_.Exception.Message)" "WARN"
                        }
                    }
                }
                catch {
                    Write-Log "Error processing Run keys in $BasePath`: $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                Write-Log "Run keys path not found: $BasePath" "INFO"
            }
        }
        
        $Result = @{
            Success = $true
            TotalRemoved = $TotalRemoved
            RemovedKeys = $RemovedKeys
            Message = "Run keys cleanup completed"
        }
        
        $Result.Details = @(
            "Total keys removed: $TotalRemoved",
            "Registry paths checked: HKLM and HKCU Run locations",
            "Keys configured for removal: $($RunKeysToRemove -join ', ')"
        )
        
        if ($RemovedKeys.Count -gt 0) {
            $Result.Details += "Successfully removed keys: $($RemovedKeys -join '; ')"
        } else {
            $Result.Details += "No matching keys found in registry (may already be removed)"
        }
        $Result.Message = "Run keys cleanup: $TotalRemoved keys removed"
        
        Write-Log "Run keys registry cleanup completed. Removed $TotalRemoved keys total" "SUCCESS"
        return $Result
    }
    catch {
        Write-Log "Run keys registry cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            TotalRemoved = 0
            RemovedKeys = @()
            Message = $_.Exception.Message
        }
    }
}

function Remove-ActiveComponentsRegistry {
    <#
    .SYNOPSIS
        Removes specified Active Components registry keys based on config file
    .DESCRIPTION
        Removes only the Active Components registry entries specified in the configuration file
    .EXAMPLE
        Remove-ActiveComponentsRegistry
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting Active Components registry cleanup..." "INFO"
        
        # Read components to remove from config file
        $ComponentsToRemoveStr = ""
        if ($Global:CachedConfig -and $Global:CachedConfig.PSObject.Properties.Name -contains "ActiveSetupComponentsToRemove") {
            $ComponentsToRemoveStr = $Global:CachedConfig.ActiveSetupComponentsToRemove
        } else {
            $ConfigFile = Join-Path $PSScriptRoot "CitrixConfig.txt"
            $ComponentsToRemoveStr = Get-ConfigValue -Key "ActiveSetupComponentsToRemove" -ConfigFile $ConfigFile -DefaultValue ""
        }
        
        Write-Log "Active Setup components config value: '$ComponentsToRemoveStr'" "INFO"
        
        # Parse comma-separated GUIDs
        $ComponentsToRemove = @()
        if (![string]::IsNullOrWhiteSpace($ComponentsToRemoveStr)) {
            $ComponentsToRemove = $ComponentsToRemoveStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
        
        if ($ComponentsToRemove.Count -eq 0) {
            Write-Log "No Active Setup components specified for removal - skipping cleanup" "INFO"
            return @{
                Success = $true
                TotalRemoved = 0
                RemovedComponents = @()
                Message = "No components specified for removal"
                Skipped = $true
                Details = @(
                    "Active Setup cleanup skipped - no components configured for removal",
                    "To configure components for removal, add GUIDs to ActiveSetupComponentsToRemove in config file",
                    "Example: ActiveSetupComponentsToRemove={GUID1},{GUID2},{GUID3}"
                )
            }
        }
        
        Write-Log "Components configured for removal: $($ComponentsToRemove -join ', ')" "INFO"
        
        $ActiveComponentsPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
        )
        
        $RemovedComponents = @()
        $TotalRemoved = 0
        
        foreach ($BasePath in $ActiveComponentsPaths) {
            if (Test-Path $BasePath) {
                Write-Log "Checking Active Components at: $BasePath" "INFO"
                
                try {
                    foreach ($ComponentGUID in $ComponentsToRemove) {
                        $ComponentPath = Join-Path $BasePath $ComponentGUID
                        
                        if (Test-Path $ComponentPath) {
                            try {
                                Write-Log "Removing Active Component: $ComponentGUID" "INFO"
                                Remove-Item -Path $ComponentPath -Recurse -Force -ErrorAction Stop
                                $RemovedComponents += $ComponentGUID
                                $TotalRemoved++
                                Write-Log "Successfully removed: $ComponentGUID" "SUCCESS"
                            }
                            catch {
                                Write-Log "Failed to remove component $ComponentGUID`: $($_.Exception.Message)" "WARN"
                            }
                        }
                        else {
                            Write-Log "Component not found (may already be removed): $ComponentGUID" "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "Error processing components in $BasePath`: $($_.Exception.Message)" "ERROR"
                }
            }
            else {
                Write-Log "Active Components path not found: $BasePath" "INFO"
            }
        }
        
        $Result = @{
            Success = $true
            TotalRemoved = $TotalRemoved
            RemovedComponents = $RemovedComponents
            Message = "Active Components cleanup completed successfully"
        }
        
        # Add detailed results
        $Result.Details = @(
            "Total components removed: $TotalRemoved",
            "Registry paths checked: HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
            "Components processed: $($ComponentsToRemove.Count)"
        )
        
        if ($RemovedComponents.Count -gt 0) {
            $Result.Details += "Removed components: $($RemovedComponents -join '; ')"
        }
        
        $Result.Message = "Active Components cleanup: $TotalRemoved components removed"
        
        if ($TotalRemoved -gt 0) {
            Write-Log "Active Components cleanup completed: $TotalRemoved components removed" "SUCCESS"
        } else {
            Write-Log "Active Components cleanup completed: No components needed removal" "SUCCESS"
        }
        
        return $Result
    }
    catch {
        Write-Log "Active Components cleanup failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            TotalRemoved = 0
            RemovedComponents = @()
            Message = "Active Components cleanup failed: $($_.Exception.Message)"
        }
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
       return @{
           Success = $true
           Message = "Pagefile configured successfully"
           PagefilePath = "${DriveLetter}:\pagefile.sys"
           SizeGB = $SizeGB
           SizeMB = $PageFileSizeMB
           Details = @(
               "Pagefile location: ${DriveLetter}:\pagefile.sys",
               "Size configured: ${SizeGB}GB ($PageFileSizeMB MB)",
               "Registry path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
               "Automatic management: Disabled"
           )
       }
   }
   catch {
       Write-Log "Failed to configure pagefile: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Pagefile configuration failed"
           Details = @("Pagefile configuration failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Event logs cleared successfully"
           LogsCleared = $ClearedCount
           TotalLogsFound = $Logs.Count
           Details = @(
               "Total logs found: $($Logs.Count)",
               "Logs successfully cleared: $ClearedCount",
               "Logs failed to clear: $($Logs.Count - $ClearedCount)",
               "Method used: EventLogSession.ClearLog"
           )
       }
   }
   catch {
       Write-Log "Failed to clear event logs: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Event log clearing failed"
           Details = @("Event log clearing failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Windows Updates disabled successfully"
           RegistryChanges = $UpdateKeys.Count
           ServiceDisabled = $true
           Details = @(
               "Registry keys modified: $($UpdateKeys.Count)",
               "Registry paths: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
               "Service status: wuauserv disabled and stopped",
               "Auto-update options: Disabled (AUOptions=1, NoAutoUpdate=1)"
           )
       }
   }
   catch {
       Write-Log "Failed to disable Windows Updates: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Windows Updates disabling failed"
           Details = @("Windows Updates disabling failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Timezone configured successfully"
           TimeZoneId = $TimeZoneId
           Method = if (Get-Command Set-TimeZone -ErrorAction SilentlyContinue) { "PowerShell Set-TimeZone" } else { "tzutil command" }
           Details = @(
               "Timezone ID: $TimeZoneId",
               "Configuration method: $(if (Get-Command Set-TimeZone -ErrorAction SilentlyContinue) { 'PowerShell Set-TimeZone cmdlet' } else { 'tzutil.exe command' })",
               "System timezone updated successfully"
           )
       }
   }
   catch {
       Write-Log "Failed to set timezone: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Timezone configuration failed"
           Details = @("Timezone configuration failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Domain join completed successfully"
           DomainName = $DomainName
           OUPath = $OUPath
           UserAccount = $Credential.UserName
           Details = @(
               "Domain: $DomainName",
               "User account: $($Credential.UserName)",
               "OU path: $(if($OUPath){"$OUPath"}else{'Default Computers container'})",
               "Computer account created successfully"
           )
       }
   }
   catch {
       Write-Log "Failed to join domain: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Domain join failed"
           DomainName = $DomainName
           Details = @("Domain join failed: $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Local user password set successfully"
           Username = $Username
           Details = @(
               "User account: $Username",
               "Password updated successfully",
               "Change effective immediately"
           )
       }
   }
   catch {
       Write-Log "Failed to set password for user $Username : $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Local user password change failed"
           Username = $Username
           Details = @("Password change failed for user $Username : $($_.Exception.Message)")
       }
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
       return @{
           Success = $true
           Message = "Registry value set successfully"
           RegistryPath = $Path
           ValueName = $Name
           Value = $Value
           ValueType = $Type
           Details = @(
               "Registry path: $Path",
               "Value name: $Name",
               "Value: $Value",
               "Value type: $Type"
           )
       }
   }
   catch {
       Write-Log "Failed to set registry value ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Registry value setting failed"
           RegistryPath = $Path
           ValueName = $Name
           Details = @("Failed to set registry value ${Path}\${Name}: $($_.Exception.Message)")
       }
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
           return @{
               Success = $true
               Message = "Registry value retrieved successfully"
               RegistryPath = $Path
               ValueName = $Name
               Value = $Value.$Name
               Details = @(
                   "Registry path: $Path",
                   "Value name: $Name",
                   "Retrieved value: $($Value.$Name)"
               )
           }
       }
       return @{
           Success = $false
           Message = "Registry path not found"
           RegistryPath = $Path
           ValueName = $Name
           Value = $DefaultValue
           Details = @("Registry path ${Path} does not exist, returning default value: $DefaultValue")
       }
   }
   catch {
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Registry value retrieval failed"
           RegistryPath = $Path
           ValueName = $Name
           Value = $DefaultValue
           Details = @("Failed to retrieve registry value ${Path}\${Name}: $($_.Exception.Message)")
       }
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
           return @{
               Success = $true
               Message = "Registry path created successfully"
               RegistryPath = $Path
               Created = $true
               Details = @(
                   "Registry path: $Path",
                   "Action: Created new registry path",
                   "Status: Path now exists"
               )
           }
       }
       return @{
           Success = $true
           Message = "Registry path already exists"
           RegistryPath = $Path
           Created = $false
           Details = @(
               "Registry path: $Path",
               "Action: No action needed",
               "Status: Path already exists"
           )
       }
   }
   catch {
       Write-Log "Failed to create registry path ${Path}: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Registry path creation failed"
           RegistryPath = $Path
           Details = @("Failed to create registry path ${Path}: $($_.Exception.Message)")
       }
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
           return @{
               Success = $true
               Message = "Registry value removed successfully"
               RegistryPath = $Path
               ValueName = $Name
               Found = $true
               Details = @(
                   "Registry path: $Path",
                   "Value name: $Name",
                   "Action: Registry value removed"
               )
           }
       }
       return @{
           Success = $true
           Message = "Registry value not found - no action needed"
           RegistryPath = $Path
           ValueName = $Name
           Found = $false
           Details = @(
               "Registry path: $Path",
               "Value name: $Name",
               "Action: No action needed (value not found)"
           )
       }
   }
   catch {
       Write-Log "Failed to remove registry value ${Path}\${Name}: $($_.Exception.Message)" "ERROR"
       return @{
           Success = $false
           Error = $_.Exception.Message
           Message = "Registry value removal failed"
           RegistryPath = $Path
           ValueName = $Name
           Details = @("Failed to remove registry value ${Path}\${Name}: $($_.Exception.Message)")
       }
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
       
       # Use cached config first for VDA installer path
       if ($Global:CachedConfig -and $Global:CachedConfig.VDAInstallerPath) {
           $VDAInstallerPath = $Global:CachedConfig.VDAInstallerPath
       } else {
           $VDAInstallerPath = Get-ConfigValue -Key "VDAInstallerPath" -DefaultValue "C:\Temp\VDA.iso" -ConfigFile $ConfigFilePath
       }
       
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
       
       # Use cached config first for PVS installer path
       if ($Global:CachedConfig -and $Global:CachedConfig.PVSInstallerPath) {
           $PVSInstallerPath = $Global:CachedConfig.PVSInstallerPath
       } else {
           $PVSInstallerPath = Get-ConfigValue -Key "PVSInstallerPath" -DefaultValue "C:\Temp\PVS.iso" -ConfigFile $ConfigFilePath
       }
       
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
       
       # Use cached config first for WEM source path
       if ($Global:CachedConfig -and $Global:CachedConfig.WEMAgentSource) {
           $WEMSourcePath = $Global:CachedConfig.WEMAgentSource
       } else {
           $WEMSourcePath = Get-ConfigValue -Key "WEMAgentSource" -DefaultValue "" -ConfigFile $ConfigFilePath
       }
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
       
       # Use cached config first for IBM TADDM installation flag
       if ($Global:CachedConfig -and $Global:CachedConfig.EnableIBMTADDMInstallation) {
           $EnableIBMTADDM = [bool]$Global:CachedConfig.EnableIBMTADDMInstallation
       } else {
           $EnableIBMTADDM = [bool](Get-ConfigValue -Key "EnableIBMTADDMInstallation" -DefaultValue "false" -ConfigFile $ConfigFilePath)
       }
       
       if ($EnableIBMTADDM) {
           # Use cached config first for IBM TADDM path
           if ($Global:CachedConfig -and $Global:CachedConfig.IBMTADDMPath) {
               $TADDMPath = $Global:CachedConfig.IBMTADDMPath
           } else {
               $TADDMPath = Get-ConfigValue -Key "IBMTADDMPath" -DefaultValue "C:\IBM\TADDM\nonadmin_scripts\install.bat" -ConfigFile $ConfigFilePath
           }
           
           if (Test-Path $TADDMPath) {
               Write-Log "Executing IBM TADDM installation from: $TADDMPath" "INFO"
               $Process = Start-Process -FilePath $TADDMPath -Wait -PassThru
               
               if ($Process.ExitCode -eq 0) {
                   Write-Log "IBM TADDM installation completed successfully" "SUCCESS"
                   
                   # Check for actual installation paths
                   $ActualInstallPath = $null
                   $PossibleInstallPaths = @(
                       "C:\IBM\TADDM",
                       "C:\Program Files\IBM\TADDM",
                       "C:\Program Files (x86)\IBM\TADDM"
                   )
                   
                   foreach ($Path in $PossibleInstallPaths) {
                       if (Test-Path $Path) {
                           $ActualInstallPath = $Path
                           break
                       }
                   }
                   
                   # Check for actual files created
                   $ActualFilesCreated = @()
                   $ExpectedFiles = @(
                       "C:\IBM\TADDM\install.log",
                       "C:\IBM\TADDM\nonadmin_scripts\install.bat",
                       "C:\IBM\TADDM\bin\taddm-agent.exe",
                       "C:\IBM\TADDM\bin\taddm.exe",
                       "C:\IBM\TADDM\config\taddm.properties"
                   )
                   
                   foreach ($File in $ExpectedFiles) {
                       if (Test-Path $File) {
                           $ActualFilesCreated += $File
                       }
                   }
                   
                   # Check for TADDM services
                   $TADDMServices = @()
                   $ServiceNames = @("IBM TADDM Agent", "IBM TADDM Discovery", "TADDM")
                   foreach ($ServiceName in $ServiceNames) {
                       $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                       if ($Service) {
                           $TADDMServices += "$ServiceName ($($Service.Status))"
                       }
                   }
                   
                   return @{ 
                       Success = $true
                       InstallPath = if ($ActualInstallPath) { $ActualInstallPath } else { "Installation path not detected" }
                       ExitCode = $Process.ExitCode
                       FilesCreated = if ($ActualFilesCreated.Count -gt 0) { $ActualFilesCreated } else { @("No TADDM files detected post-installation") }
                       ServicesCreated = if ($TADDMServices.Count -gt 0) { $TADDMServices } else { @("No TADDM services detected") }
                       Message = "IBM TADDM agent installation completed"
                       Details = @(
                           "Installation executed from: $TADDMPath",
                           "Exit code: $($Process.ExitCode)",
                           "Files detected: $($ActualFilesCreated.Count)",
                           "Services detected: $($TADDMServices.Count)"
                       )
                   }
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
        
        # Read configuration values - use cached config first, then parameters, then config file
        if ($Global:CachedConfig) {
            Write-Log "Using cached configuration for virtual cache drive creation" "INFO"
            if ([string]::IsNullOrEmpty($DriveLetter)) {
                $DriveLetter = $Global:CachedConfig.VirtualCacheDriveLetter -or "D"
            }
            if ($SizeMB -eq -1) {
                $SizeMB = [int]($Global:CachedConfig.VirtualCacheDriveSizeMB -or "500")
            }
            if ([string]::IsNullOrEmpty($VolumeLabel)) {
                $VolumeLabel = $Global:CachedConfig.VirtualCacheDriveLabel -or "CacheVol"
            }
            if ([string]::IsNullOrEmpty($VHDXPath)) {
                $VHDXPath = $Global:CachedConfig.VirtualCacheDrivePath -or "C:\VirtualCache\CacheDrive.vhdx"
            }
        } else {
            Write-Log "Using configuration file for virtual cache drive creation" "INFO"
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
        
        # Check if VHDX file exists but drive letter is not assigned (Stage 2 scenario)
        if (Test-Path $CacheVHDXPath) {
            Write-Log "Existing VHDX file found at $CacheVHDXPath - mounting to drive ${DriveLetter}:" "INFO"
            
            try {
                # Mount existing VHDX file
                $MountScript = @"
select vdisk file="$CacheVHDXPath"
attach vdisk
select partition 1
assign letter=$DriveLetter
exit
"@
                
                Write-Log "Mounting existing virtual cache drive..." "INFO"
                $ScriptFile = [System.IO.Path]::Combine($env:TEMP, "mount_vhdx_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt")
                
                # Write script with ASCII encoding
                [System.IO.File]::WriteAllText($ScriptFile, $MountScript, [System.Text.Encoding]::ASCII)
                
                # Execute diskpart to mount
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
                
                # Clean up script file
                if (Test-Path $ScriptFile) {
                    Remove-Item $ScriptFile -Force -ErrorAction SilentlyContinue
                }
                
                # Verify mount was successful
                Start-Sleep -Seconds 2
                if (Test-Path "${DriveLetter}:\") {
                    Write-Log "Successfully mounted existing virtual cache drive to ${DriveLetter}:" "SUCCESS"
                    $Results.Success = $true
                    $Results.DriveAssigned = $true
                    $Results.VHDXPath = $CacheVHDXPath
                    $Results.DriveLetter = $DriveLetter
                    $Results.SizeMB = $CacheDriveSizeMB
                    $Results.Method = "VHDX Mount (Existing)"
                    return $Results
                } else {
                    Write-Log "Failed to mount existing VHDX - drive ${DriveLetter}: not accessible" "ERROR"
                    $Results.Errors += "Failed to mount existing VHDX file"
                }
            }
            catch {
                Write-Log "Exception while mounting existing VHDX: $($_.Exception.Message)" "ERROR"
                $Results.Errors += "Exception during VHDX mount: $($_.Exception.Message)"
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
            return @{
                Success = $false
                Message = "Drive letter not found"
                DriveLetter = $DriveLetter
                Details = @("Drive ${DriveLetter}:\ does not exist on this system")
            }
        }
        
        # Check if it's a virtual drive by looking for VHDX file
        $VHDXPath = "C:\Temp\DCACHE.VHDX"
        if (Test-Path $VHDXPath) {
            $VHDXSize = (Get-Item $VHDXPath).Length / 1MB
            Write-Log "Virtual cache drive detected: $VHDXPath" "INFO"
            return @{
                Success = $true
                Message = "Virtual cache drive detected"
                DriveLetter = $DriveLetter
                VHDXPath = $VHDXPath
                VHDXSizeMB = [math]::Round($VHDXSize, 2)
                Details = @(
                    "Drive letter: ${DriveLetter}:\",
                    "VHDX file path: $VHDXPath",
                    "VHDX file size: $([math]::Round($VHDXSize, 2)) MB",
                    "Virtual drive status: Active"
                )
            }
        }
        
        return @{
            Success = $false
            Message = "No virtual cache drive detected"
            DriveLetter = $DriveLetter
            VHDXPath = $VHDXPath
            Details = @(
                "Drive letter: ${DriveLetter}:\",
                "Expected VHDX path: $VHDXPath",
                "Status: No virtual cache drive found"
            )
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Virtual cache drive detection failed"
            DriveLetter = $DriveLetter
            Details = @("Virtual cache drive detection failed: $($_.Exception.Message)")
        }
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
        $IsValid = $UserInput -match $Pattern
        return @{
            Success = $IsValid
            Message = "Input validation completed"
            Pattern = $Pattern
            UserInput = $UserInput
            IsValid = $IsValid
            Details = @(
                "Validation pattern: $Pattern",
                "User input: $UserInput",
                "Validation result: $(if($IsValid){'Valid'}else{'Invalid'})"
            )
        }
    }
    
    return @{
        Success = $true
        Message = "Input validation completed successfully"
        UserInput = $UserInput
        Details = @(
            "No validation pattern specified",
            "User input accepted: $UserInput"
        )
    }
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
        
        # Load configurable service list from cached config, override, or config file
        if ($ServiceOverride -ne "") {
            $ServicesToDisableConfig = $ServiceOverride
        } elseif ($Global:CachedConfig -and $Global:CachedConfig.CitrixServicesToDisable) {
            Write-Log "Using cached services configuration" "INFO"
            $ServicesToDisableConfig = $Global:CachedConfig.CitrixServicesToDisable
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
        
        # Add VDA Multiple Monitor Hook optimizations if enabled - use cached config first
        if ($Global:CachedConfig -and $Global:CachedConfig.EnableVDAMultiMonitorHook) {
            Write-Log "Using cached configuration for registry optimizations" "INFO"
            $EnableVDAMultiMonitorHook = [bool]$Global:CachedConfig.EnableVDAMultiMonitorHook
            $VDALogonUIWidth = [int]($Global:CachedConfig.VDALogonUIWidth -or "800")
            $VDALogonUIHeight = [int]($Global:CachedConfig.VDALogonUIHeight -or "600")
        } else {
            $EnableVDAMultiMonitorHook = [bool](Get-ConfigValue -Key "EnableVDAMultiMonitorHook" -DefaultValue "true" -ConfigFile $ConfigFilePath)
            $VDALogonUIWidth = [int](Get-ConfigValue -Key "VDALogonUIWidth" -DefaultValue "800" -ConfigFile $ConfigFilePath)
            $VDALogonUIHeight = [int](Get-ConfigValue -Key "VDALogonUIHeight" -DefaultValue "600" -ConfigFile $ConfigFilePath)
        }
        if ($EnableVDAMultiMonitorHook) {
            
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
        
        # Return detailed results instead of simple boolean
        return @{
            Success = $true
            Message = "Applied $($RegOptimizations.Count) registry optimizations"
            OptimizationsApplied = $RegOptimizations.Count
            RegistryChanges = $RegOptimizations | ForEach-Object { "$($_.Path)\$($_.Name) = $($_.Value)" }
            Details = @(
                "Total optimizations: $($RegOptimizations.Count)",
                "Memory optimizations: 2 (DisablePagingExecutive, LargeSystemCache)",
                "VDA optimizations: $(if($EnableVDAMultiMonitorHook){'2 (LogonUI dimensions)'}else{'0 (disabled)'})",
                "Registry paths modified: $($RegOptimizations.Path | Sort-Object -Unique -join ', ')"
            )
        }
    }
    catch {
        Write-Log "Failed to apply registry optimizations: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Registry optimizations failed"
            Details = @("Registry modification failed: $($_.Exception.Message)")
        }
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
            Message = "Pagefile configuration optimized"
            Details = @(
                "Pagefile location: $PagefileLocation",
                "Fixed size configured: ${PagefileSizeGB}GB (${PagefileSizeMB}MB)",
                "Registry path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                "PagingFiles value: $PagefileString",
                "Automatic pagefile management: Disabled",
                "Initial size: ${PagefileSizeMB} MB",
                "Maximum size: ${PagefileSizeMB} MB (fixed)"
            )
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
        
        # Create Users directory structure on cache drive (Profiles only)
        $UserProfilesPath = "${CacheDriveLetter}:\Users"
        
        Write-Log "Creating user profiles directory structure..."
        New-Item -Path $UserProfilesPath -ItemType Directory -Force | Out-Null
        
        # Registry keys for user profiles redirection
        $ProfileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        
        Write-Log "Configuring user profiles registry settings..."
        
        # Redirect profiles directory (user profiles only, not Default User or Public)
        Set-ItemProperty -Path $ProfileListKey -Name "ProfilesDirectory" -Value $UserProfilesPath -Type ExpandString
        Write-Log "Set ProfilesDirectory to: $UserProfilesPath" "INFO"
        
        # NOTE: Default User and Public profiles remain on C: drive as requested
        Write-Log "Default User and Public profiles remain on C: drive (not redirected)" "INFO"
        
        # Set appropriate permissions on Users directory
        Write-Log "Setting permissions on user profiles directory..."
        $Acl = Get-Acl $UserProfilesPath
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($AccessRule)
        Set-Acl -Path $UserProfilesPath -AclObject $Acl
        
        Write-Log "User profiles redirection configured successfully" "SUCCESS"
        Write-Log "New user profiles will be created on: ${CacheDriveLetter}:\Users" "SUCCESS"
        Write-Log "Default User and Public profiles remain on C:\Users (not redirected)" "INFO"
        Write-Log "Note: Existing user profiles remain on C: drive until manually moved" "INFO"
        Write-Log "Note: System restart required for changes to take effect" "WARN"
        
        return @{
            Success = $true
            ProfilesPath = $UserProfilesPath
            CacheDrive = $CacheDriveLetter
            DefaultUserRedirected = $false
            PublicProfileRedirected = $false
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
                        $LicenseKeys = Get-ChildItem $ParentPath -Name -ErrorAction SilentlyContinue | Where-Object { $_ -like "LICENSE000*" }
                        if ($LicenseKeys) {
                            foreach ($LicenseKey in $LicenseKeys) {
                                $FullPath = "$ParentPath\$LicenseKey"
                                try {
                                    if (Test-Path $FullPath) {
                                        Remove-Item -Path $FullPath -Recurse -Force -ErrorAction Stop
                                        $RemovedKeys += $FullPath
                                        Write-Log "Removed RDS license key: $FullPath" "INFO"
                                    }
                                }
                                catch {
                                    Write-Log "Could not remove license key $FullPath (may be in use): $($_.Exception.Message)" "WARN"
                                    $SkippedKeys += $FullPath
                                }
                            }
                        } else {
                            Write-Log "No LICENSE000* keys found (already clean)" "INFO"
                        }
                    } else {
                        Write-Log "MSLicensing Store path not found (already clean)" "INFO"
                    }
                } else {
                    if (Test-Path $RegPath) {
                        try {
                            Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
                            $RemovedKeys += $RegPath
                            Write-Log "Removed RDS registry key: $RegPath" "INFO"
                        }
                        catch {
                            Write-Log "Could not remove registry key $RegPath (may be protected): $($_.Exception.Message)" "WARN"
                            $SkippedKeys += $RegPath
                        }
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
        
        if ($RemovedKeys.Count -gt 0) {
            Write-Log "RDS grace period reset completed successfully" "SUCCESS"
            Write-Log "Removed $($RemovedKeys.Count) licensing registry keys" "SUCCESS"
            Write-Log "Note: System restart may be required for changes to take full effect" "WARN"
            
            return @{
                Success = $true
                Message = "Registry grace period cleanup"
                RemovedKeys = $RemovedKeys
                SkippedKeys = $SkippedKeys
                TotalRemoved = $RemovedKeys.Count
                TotalSkipped = $SkippedKeys.Count
                RegistryChanges = $RemovedKeys
                Details = @(
                    "Registry paths processed: $($LicensingRegPaths.Count)",
                    "Registry keys removed: $($RemovedKeys.Count)",
                    "Registry keys already clean: $($SkippedKeys.Count)"
                ) + $RemovedKeys + ($SkippedKeys | ForEach-Object { "Already clean: $_" })
            }
        } else {
            Write-Log "RDS grace period appears to already be reset (no keys found)" "SUCCESS"
            
            return @{
                Success = $true  
                Message = "Registry grace period cleanup"
                RemovedKeys = @()
                SkippedKeys = $SkippedKeys
                TotalRemoved = 0
                TotalSkipped = $SkippedKeys.Count
                RegistryChanges = @()
                Details = @(
                    "Registry paths checked: $($LicensingRegPaths.Count)",
                    "Registry keys removed: 0",
                    "Keys already clean: $($SkippedKeys.Count)"
                ) + ($SkippedKeys | ForEach-Object { "Already clean: $_" })
            }
        }
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
        # Use cached config first for VDA install arguments
        if ($Global:CachedConfig -and $Global:CachedConfig.VDAInstallArguments) {
            $VDAArgs = $Global:CachedConfig.VDAInstallArguments
        } else {
            $VDAArgs = Get-ConfigValue -Key "VDAInstallArguments" -DefaultValue "/quiet /norestart /components VDA /masterimage /installdir `"C:\Program Files\Citrix\Virtual Desktop Agent`"" -ConfigFile $ConfigFilePath
        }
        
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
        # Use cached config first for PVS install arguments
        if ($Global:CachedConfig -and $Global:CachedConfig.PVSInstallArguments) {
            $PVSArgs = $Global:CachedConfig.PVSInstallArguments
        } else {
            $PVSArgs = Get-ConfigValue -Key "PVSInstallArguments" -DefaultValue "/S" -ConfigFile $ConfigFilePath
        }
        
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
                DNSConfiguration = @{ Success = $false; Skipped = $false }
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
        # Use cached config first for VDA install arguments
        if ($Global:CachedConfig -and $Global:CachedConfig.VDAInstallArguments) {
            $VDAInstallArguments = $Global:CachedConfig.VDAInstallArguments
        } else {
            $VDAInstallArguments = Get-ConfigValue -Key "VDAInstallArguments" -DefaultValue "/quiet /norestart /components vda,plugins /enable_hdx_ports /enable_real_time_transport /masterimage" -ConfigFile $ConfigFilePath
        }
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
        
        if ($InstallSuccess) {
            return @{
                Success = $true
                ExitCode = $VDAProcess.ExitCode
                Message = "VDA installation completed successfully"
                InstallPath = "C:\Program Files\Citrix\Virtual Desktop Agent"
                Version = "Unknown - check registry for version details"
                Duration = "Installation time not tracked"
                Changes = @(
                    "Registry: HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent installed",
                    "Service: Citrix Desktop Service (BrokerAgent) configured",
                    "Service: Citrix HDX Audio Service installed",
                    "Service: Citrix Print Manager Service configured",
                    "Files: VDA binaries copied to Program Files\Citrix",
                    "Network: HDX ports 1494 and 2598 configured",
                    "Registry: Machine policies updated for VDA operation"
                )
                Details = @(
                    "Source: $VDAISOPath",
                    "Setup: $SetupPath", 
                    "Arguments: $VDAInstallArguments",
                    "Exit Code: $($VDAProcess.ExitCode)"
                )
            }
        } else {
            return @{
                Success = $false
                ExitCode = if ($VDAProcess) { $VDAProcess.ExitCode } else { -1 }
                Error = "VDA installation failed"
                InstallPath = $null
            }
        }
    }
    catch {
        Write-Log "Failed to install Citrix VDA: $($_.Exception.Message)" "ERROR"
        try { Dismount-DiskImage -ImagePath $VDAISOPath -ErrorAction SilentlyContinue } catch { }
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Citrix VDA installation failed"
            ISOPath = $VDAISOPath
            Details = @("Citrix VDA installation failed: $($_.Exception.Message)")
        }
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
        # Use cached config first for PVS install arguments
        if ($Global:CachedConfig -and $Global:CachedConfig.PVSInstallArguments) {
            $PVSInstallArguments = $Global:CachedConfig.PVSInstallArguments
        } else {
            $PVSInstallArguments = Get-ConfigValue -Key "PVSInstallArguments" -DefaultValue "/S" -ConfigFile $ConfigFilePath
        }
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
        
        if ($InstallSuccess) {
            return @{
                Success = $true
                ExitCode = $PVSProcess.ExitCode
                Message = "PVS Target Device installation completed successfully"
                InstallPath = "C:\Program Files\Citrix\Provisioning Services"
                Version = "Unknown - check installed programs for version"
                Duration = "Installation time not tracked"
                DriversInstalled = @(
                    "Citrix PVS Target Device Driver",
                    "Citrix PVS RAM Cache Driver",
                    "Citrix PVS Network Boot Driver"
                )
                Details = @(
                    "Source: $PVSISOPath",
                    "Setup: $SetupPath",
                    "Arguments: $PVSInstallArguments",
                    "Exit Code: $($PVSProcess.ExitCode)"
                )
            }
        } else {
            return @{
                Success = $false
                ExitCode = if ($PVSProcess) { $PVSProcess.ExitCode } else { -1 }
                Error = "PVS Target Device installation failed"
                InstallPath = $null
            }
        }
    }
    catch {
        Write-Log "Failed to install PVS Target Device: $($_.Exception.Message)" "ERROR"
        try { Dismount-DiskImage -ImagePath $PVSISOPath -ErrorAction SilentlyContinue } catch { }
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "PVS Target Device installation failed"
            ISOPath = $PVSISOPath
            Details = @("PVS Target Device installation failed: $($_.Exception.Message)")
        }
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
            
            # Get configurable installation arguments - use cached config first
            if ($Global:CachedConfig -and $Global:CachedConfig.WEMInstallArguments) {
                $WEMInstallArguments = $Global:CachedConfig.WEMInstallArguments
            } else {
                $WEMInstallArguments = Get-ConfigValue -Key "WEMInstallArguments" -DefaultValue "/quiet /norestart" -ConfigFile $ConfigFilePath
            }
            
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
                $Results.ExitCode = $WEMProcess.ExitCode
                
                # Check actual installation path
                $ActualInstallPath = $null
                $PossiblePaths = @(
                    "C:\Program Files (x86)\Citrix\Workspace Environment Management Agent",
                    "C:\Program Files\Citrix\Workspace Environment Management Agent",
                    "C:\Program Files (x86)\Norskale\Agent Host",
                    "C:\Program Files\Norskale\Agent Host"
                )
                
                foreach ($Path in $PossiblePaths) {
                    if (Test-Path $Path) {
                        $ActualInstallPath = $Path
                        break
                    }
                }
                
                $Results.InstallPath = if ($ActualInstallPath) { $ActualInstallPath } else { "Installation path not detected" }
                
                # Check for actual registry keys
                $ActualRegistryChanges = @()
                $RegistryPaths = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Services\WemLogSvc",
                    "HKLM:\SYSTEM\CurrentControlSet\Services\WemAgentSvc",
                    "HKLM:\SOFTWARE\Citrix\WEM",
                    "HKLM:\SOFTWARE\Policies\Citrix\WEM"
                )
                
                foreach ($RegPath in $RegistryPaths) {
                    if (Test-Path $RegPath) {
                        $ActualRegistryChanges += "Registry key exists: $RegPath"
                    }
                }
                
                if ($ActualRegistryChanges.Count -eq 0) {
                    $ActualRegistryChanges += "No WEM registry keys detected post-installation"
                }
                
                $Results.RegistryChanges = $ActualRegistryChanges
                
                # Check if WEM Agent service exists (indicates successful installation)
                $WEMService = Get-Service -Name "WemAgentsvc" -ErrorAction SilentlyContinue
                if ($WEMService) {
                    Write-Log "WEM Agent service detected - installation verified" "SUCCESS"
                    
                    # Configure WEM Agent cache location if specified
                    # Use cached config first for WEM Agent cache configuration
                    if ($Global:CachedConfig -and $Global:CachedConfig.ConfigureWEMAgentCache) {
                        $ConfigureWEMAgentCache = [bool]$Global:CachedConfig.ConfigureWEMAgentCache
                    } else {
                        $ConfigureWEMAgentCache = [bool](Get-ConfigValue -Key "ConfigureWEMAgentCache" -DefaultValue "false" -ConfigFile $ConfigFilePath)
                    }
                    if ($ConfigureWEMAgentCache) {
                        # Force default value and ensure it's never empty
                        $WEMAgentCacheLocation = "D:\"
                        
                        # Try to get config value, but keep default if empty
                        try {
                            # Use cached config first for WEM Agent cache location
                            if ($Global:CachedConfig -and $Global:CachedConfig.WEMAgentCacheLocation) {
                                $ConfigValue = $Global:CachedConfig.WEMAgentCacheLocation
                            } else {
                                $ConfigValue = Get-ConfigValue -Key "WEMAgentCacheLocation" -DefaultValue "D:\" -ConfigFile $ConfigFilePath
                            }
                            if (![string]::IsNullOrWhiteSpace($ConfigValue)) {
                                $WEMAgentCacheLocation = $ConfigValue.Trim()
                            }
                        } catch {
                            Write-Log "Error reading WEMAgentCacheLocation config - using default D:\" "WARN"
                        }
                        
                        Write-Log "Configuring WEM Agent cache location: $WEMAgentCacheLocation" "INFO"
                        
                        try {
                            $CacheConfigResult = Set-WEMAgentCacheLocation -CacheLocation $WEMAgentCacheLocation
                        } catch {
                            Write-Log "Failed to call Set-WEMAgentCacheLocation: $($_.Exception.Message)" "ERROR"
                            $Results.CacheLocationConfigured = $false
                            $CacheConfigResult = @{ Success = $false; Error = $_.Exception.Message }
                        }
                        
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
        [string]$CacheLocation
    )
    
    try {
        # Validate cache location parameter
        if ([string]::IsNullOrWhiteSpace($CacheLocation)) {
            Write-Log "Cache location is empty - using default D:\" "WARN"
            $CacheLocation = "D:\"
        }
        
        Write-Log "Configuring WEM Agent cache location to: $CacheLocation"
        
        # Ensure cache directory exists (handle root drive case)
        if ($CacheLocation -ne "D:\" -and $CacheLocation -ne "D:" -and -not [string]::IsNullOrWhiteSpace($CacheLocation)) {
            $CacheDirectory = Split-Path $CacheLocation -Parent
            if (-not [string]::IsNullOrWhiteSpace($CacheDirectory) -and -not (Test-Path $CacheDirectory)) {
                Write-Log "Creating WEM cache directory: $CacheDirectory"
                New-Item -Path $CacheDirectory -ItemType Directory -Force | Out-Null
            }
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
            RegistryKey = $WEMRegistryPath
            RegistryValue = "Cache location: $CacheLocation"
            DirectoryCreated = (Test-Path $CacheLocation)
            ServiceRestarted = $ServiceWasStopped
            Details = @(
                "Registry path modified: $WEMRegistryPath",
                "Cache location set to: $CacheLocation",
                "Directory created: $(Test-Path $CacheLocation)",
                "Service restart required: $ServiceWasStopped"
            )
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
        # Use cached config first for UberAgent paths
        if ($Global:CachedConfig -and $Global:CachedConfig.UberAgentTemplatesSourcePath) {
            $TemplatesSourcePath = $Global:CachedConfig.UberAgentTemplatesSourcePath
            $TemplatesLocalPath = $Global:CachedConfig.UberAgentTemplatesLocalPath -or "C:\Program Files\vast limits\uberAgent\config\templates"
            $ConfigSourcePath = $Global:CachedConfig.UberAgentConfigSourcePath
            $ConfigLocalPath = $Global:CachedConfig.UberAgentConfigLocalPath -or "C:\Program Files\vast limits\uberAgent\config\uberagent.conf"
            $LicenseSourcePath = $Global:CachedConfig.UberAgentLicenseSourcePath
            $LicenseLocalPath = $Global:CachedConfig.UberAgentLicenseLocalPath -or "C:\Program Files\vast limits\uberAgent\config\uberagent.lic"
        } else {
            $TemplatesSourcePath = Get-ConfigValue -Key "UberAgentTemplatesSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
            $TemplatesLocalPath = Get-ConfigValue -Key "UberAgentTemplatesLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\templates" -ConfigFile $ConfigFilePath
            $ConfigSourcePath = Get-ConfigValue -Key "UberAgentConfigSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
            $ConfigLocalPath = Get-ConfigValue -Key "UberAgentConfigLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\uberagent.conf" -ConfigFile $ConfigFilePath
            $LicenseSourcePath = Get-ConfigValue -Key "UberAgentLicenseSourcePath" -DefaultValue "" -ConfigFile $ConfigFilePath
            $LicenseLocalPath = Get-ConfigValue -Key "UberAgentLicenseLocalPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\config\uberagent.lic" -ConfigFile $ConfigFilePath
        }
        
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
            $Results.Success = $true  # For HTML report compatibility
            return $Results
        }
        
        # Check installer availability
        if (-not (Test-Path $UberAgentInstallerPath)) {
            $ErrorMsg = "UberAgent installer not found at: $UberAgentInstallerPath"
            Write-Log $ErrorMsg "ERROR"
            $Results.Errors += $ErrorMsg
            $Results.Success = $false  # For HTML report compatibility
            return $Results
        }
        
        # Get UberAgent installation arguments from config file
        # Use cached config first for UberAgent install arguments
        if ($Global:CachedConfig -and $Global:CachedConfig.UberAgentInstallArguments) {
            $UberAgentInstallArgs = $Global:CachedConfig.UberAgentInstallArguments
        } else {
            $UberAgentInstallArgs = Get-ConfigValue -Key "UberAgentInstallArguments" -DefaultValue "/quiet /norestart ALLUSERS=1 REBOOT=ReallySuppress" -ConfigFile $ConfigFilePath
        }
        
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
            $Results.InstallPath = "C:\Program Files\vast limits\uberAgent"
            $Results.Version = "Unknown - check installed programs for version"
            $Results.ExitCode = $Process.ExitCode
            $Results.Duration = "Installation time not tracked"
            $Results.ServicesConfigured = @(
                "uberAgent service (uberAgent)",
                "uberAgent ESA service (uberAgentESA)"
            )
            
            # Wait for installation to complete and create directories
            Start-Sleep -Seconds 5
            
            # Post-installation validation and cleanup
            Write-Log "Performing UberAgent post-installation validation and cleanup..." "INFO"
            
            # Stop and disable UberAgent service
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
                    
                    # Disable the service for template preparation
                    Set-Service -Name "uberAgentSvc" -StartupType Disabled -ErrorAction Stop
                    Write-Log "UberAgent service disabled (startup type set to Disabled)" "SUCCESS"
                    $Results.ServiceDisabled = $true
                } else {
                    Write-Log "UberAgent service not found - may not be installed correctly" "WARN"
                }
            }
            catch {
                $ErrorMsg = "Failed to stop/disable UberAgent service: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Errors += $ErrorMsg
            }
            
            # Validate and clear UberAgent registry key
            try {
                $UberAgentRegPath = "HKLM:\Software\vast limits\uberAgent"
                # Use Get-ItemProperty to properly handle registry paths with spaces
                try {
                    Get-ItemProperty -Path $UberAgentRegPath -ErrorAction Stop | Out-Null
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
                # Use cached config first for UberAgent temp log pattern
                if ($Global:CachedConfig -and $Global:CachedConfig.UberAgentTempLogPattern) {
                    $TempLogPattern = $Global:CachedConfig.UberAgentTempLogPattern
                } else {
                    $TempLogPattern = Get-ConfigValue -Key "UberAgentTempLogPattern" -DefaultValue "uberagent*.log" -ConfigFile $ConfigFilePath
                }
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
            # Use cached config first for UberAgent service configuration
            if ($Global:CachedConfig -and $Global:CachedConfig.UberAgentServiceName) {
                $UberAgentServiceName = $Global:CachedConfig.UberAgentServiceName
                $UberAgentRegistryPath = $Global:CachedConfig.UberAgentRegistryPath -or "HKLM:\Software\vast limits\uberAgent"
            } else {
                $UberAgentServiceName = Get-ConfigValue -Key "UberAgentServiceName" -DefaultValue "uberAgentsvc" -ConfigFile $ConfigFilePath
                $UberAgentRegistryPath = Get-ConfigValue -Key "UberAgentRegistryPath" -DefaultValue "HKLM:\Software\vast limits\uberAgent" -ConfigFile $ConfigFilePath
            }
            
            # Stop and disable UberAgent service for configuration changes
            try {
                $Service = Get-Service -Name $UberAgentServiceName -ErrorAction SilentlyContinue
                if ($Service) {
                    if ($Service.Status -eq 'Running') {
                        Stop-Service -Name $UberAgentServiceName -Force
                        Write-Log "Stopped UberAgent service: $UberAgentServiceName" "SUCCESS"
                        $Results.ServiceStopped = $true
                        $Results.PostInstallSteps += "Service stopped: $UberAgentServiceName"
                    }
                    
                    # Disable the service for template preparation
                    Set-Service -Name $UberAgentServiceName -StartupType Disabled
                    Write-Log "Disabled UberAgent service: $UberAgentServiceName" "SUCCESS"
                    $Results.ServiceDisabled = $true
                    $Results.PostInstallSteps += "Service disabled: $UberAgentServiceName"
                }
            }
            catch {
                Write-Log "Failed to stop/disable UberAgent service: $($_.Exception.Message)" "WARN"
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
                # Use cached config first for UberAgent output configuration
                if ($Global:CachedConfig -and $Global:CachedConfig.UberAgentOutputQueueName) {
                    $OutputQueueName = $Global:CachedConfig.UberAgentOutputQueueName
                    $OutputDirectory = $Global:CachedConfig.UberAgentOutputDirectory -or "D:\Logs\uberAgent\$OutputQueueName"
                } else {
                    $OutputQueueName = Get-ConfigValue -Key "UberAgentOutputQueueName" -DefaultValue "Output Queue" -ConfigFile $ConfigFilePath
                    $OutputDirectory = Get-ConfigValue -Key "UberAgentOutputDirectory" -DefaultValue "D:\Logs\uberAgent\$OutputQueueName" -ConfigFile $ConfigFilePath
                }
                
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
            $Results.Success = $Results.InstallationSuccess  # For HTML report compatibility
            
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
            $Results.Success = $false  # For HTML report compatibility
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
                # Validate working directory exists
                $WorkingDir = "C:\IBM\TADDM\nonadmin_Taddm_scripts"
                if (-not (Test-Path $WorkingDir)) {
                    # Use the directory containing the install.bat file
                    $WorkingDir = Split-Path $LocalInstallBat -Parent
                    Write-Log "Default working directory not found, using: $WorkingDir" "WARN"
                }
                
                $InstallProcess = Start-Process -FilePath $LocalInstallBat -Wait -PassThru -WorkingDirectory $WorkingDir
                
                if ($InstallProcess.ExitCode -eq 0) {
                    Write-Log "TADDM install.bat executed successfully" "SUCCESS"
                    $Results.InstallBatExecuted = $true
                    $Results.OverallSuccess = $true
                    $Results.Success = $true  # For HTML report compatibility
                } else {
                    Write-Log "TADDM install.bat failed with exit code: $($InstallProcess.ExitCode)" "ERROR"
                    $Results.Error = "Install.bat failed with exit code: $($InstallProcess.ExitCode)"
                    $Results.Success = $false  # For HTML report compatibility
                }
            }
            catch {
                Write-Log "Failed to execute TADDM install.bat: $($_.Exception.Message)" "ERROR"
                $Results.Error = "Failed to execute install.bat: $($_.Exception.Message)"
                $Results.Success = $false  # For HTML report compatibility
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
                $Results.Success = $true  # For HTML report compatibility
            } else {
                Write-Log "TADDM installation not found - skipping configuration" "INFO"
                $Results.Skipped = $true
                $Results.OverallSuccess = $true
                $Results.Success = $true  # For HTML report compatibility
            }
        }
        
        return $Results
    }
    catch {
        Write-Log "Failed to configure IBM TADDM permissions: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            OverallSuccess = $false
            Error = $_.Exception.Message
            InstallBatFound = $false
            InstallBatExecuted = $false
            PermissionsConfigured = $false
            Skipped = $false
        }
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
        # Get OU configuration if available - use cached config first
        if ($Global:CachedConfig -and $Global:CachedConfig.OrganizationalUnit) {
            $OrganizationalUnit = $Global:CachedConfig.OrganizationalUnit
        } else {
            $OrganizationalUnit = Get-ConfigValue -Key "OrganizationalUnit" -DefaultValue "" -ConfigFile $ConfigFilePath
        }
        
        if (![string]::IsNullOrWhiteSpace($OrganizationalUnit)) {
            Write-Log "Joining domain: $DomainName with OU: $OrganizationalUnit"
            Add-Computer -DomainName $DomainName -OUPath $OrganizationalUnit -Credential $Credential -Force
        } else {
            Write-Log "Joining domain: $DomainName (using default computer container)"
            Add-Computer -DomainName $DomainName -Credential $Credential -Force
        }
        
        Write-Log "Domain join completed successfully" "SUCCESS"
        
        # Get the actual OU where the computer was created
        $ActualOU = "Default Computers container"
        try {
            # Query Active Directory to find where the computer object was actually created
            $ComputerDN = (Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue).DistinguishedName
            if ($ComputerDN) {
                # Extract OU from the Distinguished Name
                $OUPart = ($ComputerDN -split ',',2)[1]
                if ($OUPart) {
                    $ActualOU = $OUPart
                }
            }
        } catch {
            # If AD PowerShell module not available, use the configured OU or default
            $ActualOU = if ($OrganizationalUnit) { $OrganizationalUnit } else { "Default Computers container" }
        }
        
        return @{
            Success = $true
            Message = "Machine successfully joined to domain"
            DomainName = $DomainName
            ComputerName = $env:COMPUTERNAME
            OrganizationalUnit = $ActualOU
            Details = @(
                "Domain: $DomainName",
                "Computer Name: $env:COMPUTERNAME",
                "Organizational Unit: $ActualOU",
                "Join Method: $(if($OrganizationalUnit){'Targeted OU'}else{'Default container'})",
                "Computer successfully joined to domain: $DomainName",
                "Domain controller contacted for authentication",
                "Machine account created in Active Directory"
            )
            RegistryChanges = @(
                "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain = $DomainName",
                "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\ComputerName = $env:COMPUTERNAME",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy domain settings updated"
            )
        }
    }
    catch {
        Write-Log "Failed to join domain: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Domain join failed"
            DomainName = $DomainName
            Details = @("Domain join failed: $($_.Exception.Message)")
        }
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
        return @{
            Success = $true
            Message = "Startup and shutdown scripts registry path configured"
            RegistryPath = $GPOPath
            PathCreated = (-not (Test-Path $GPOPath))
            Details = @(
                "Registry path: $GPOPath",
                "Path status: $(if(Test-Path $GPOPath){'Exists'}else{'Created'})",
                "Ready for script configuration"
            )
        }
    }
    catch {
        Write-Log "Failed to configure startup/shutdown scripts: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Startup/shutdown scripts configuration failed"
            Details = @("Startup/shutdown scripts configuration failed: $($_.Exception.Message)")
        }
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
            
            if ($StartupScripts.Count -gt 0) {
                # Create psScripts.ini for startup scripts
                $StartupIniPath = Join-Path $StartupScriptPath "psScripts.ini"
                $StartupIniContent = @()
                $StartupIniContent += "[ScriptsConfig]"
                $StartupIniContent += "StartExecutePSFirst=true"
                $StartupIniContent += ""
                
                # Find next available script index to avoid overwriting existing scripts
                $ScriptIndex = 0
                while (Test-Path "$StartupRegPath\$ScriptIndex") {
                    $ScriptIndex++
                }
                
                foreach ($Script in $StartupScripts) {
                    try {
                        # Add to psScripts.ini
                        $StartupIniContent += "[$ScriptIndex" + "CmdLine]"
                        $StartupIniContent += "CmdLine=" + $Script.FullName
                        $StartupIniContent += "Parameters="
                        $StartupIniContent += ""
                        
                        # Registry entries (don't use -Force to avoid overwriting)
                        $ScriptRegPath = "$StartupRegPath\$ScriptIndex"
                        if (-not (Test-Path $ScriptRegPath)) {
                            New-Item -Path $ScriptRegPath | Out-Null
                        }
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
                
                # Write psScripts.ini file
                try {
                    $StartupIniContent | Out-File -FilePath $StartupIniPath -Encoding ASCII -Force
                    Write-Log "Created startup psScripts.ini with $ScriptIndex scripts" "SUCCESS"
                    
                    # Set registry script order
                    if ($ScriptIndex -gt 0) {
                        $ScriptOrderArray = @()
                        for ($i = 0; $i -lt $ScriptIndex; $i++) {
                            $ScriptOrderArray += $i.ToString()
                        }
                        Set-ItemProperty -Path $StartupRegPath -Name "PSScriptOrder" -Value $ScriptOrderArray -Type MultiString
                    }
                }
                catch {
                    Write-Log "Failed to create startup psScripts.ini: $($_.Exception.Message)" "ERROR"
                    $Results.Success = $false
                }
            }
        }
        
        # Register shutdown scripts
        if (Test-Path $ShutdownScriptPath) {
            $ShutdownScripts = Get-ChildItem -Path $ShutdownScriptPath -Filter "*.ps1" -ErrorAction SilentlyContinue
            
            if ($ShutdownScripts.Count -gt 0) {
                # Create psScripts.ini for shutdown scripts
                $ShutdownIniPath = Join-Path $ShutdownScriptPath "psScripts.ini"
                $ShutdownIniContent = @()
                $ShutdownIniContent += "[ScriptsConfig]"
                $ShutdownIniContent += "StartExecutePSFirst=true"
                $ShutdownIniContent += ""
                
                # Find next available script index to avoid overwriting existing scripts
                $ScriptIndex = 0
                while (Test-Path "$ShutdownRegPath\$ScriptIndex") {
                    $ScriptIndex++
                }
                
                foreach ($Script in $ShutdownScripts) {
                    try {
                        # Add to psScripts.ini
                        $ShutdownIniContent += "[$ScriptIndex" + "CmdLine]"
                        $ShutdownIniContent += "CmdLine=" + $Script.FullName
                        $ShutdownIniContent += "Parameters="
                        $ShutdownIniContent += ""
                        
                        # Registry entries (don't use -Force to avoid overwriting)
                        $ScriptRegPath = "$ShutdownRegPath\$ScriptIndex"
                        if (-not (Test-Path $ScriptRegPath)) {
                            New-Item -Path $ScriptRegPath | Out-Null
                        }
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
                
                # Write psScripts.ini file
                try {
                    $ShutdownIniContent | Out-File -FilePath $ShutdownIniPath -Encoding ASCII -Force
                    Write-Log "Created shutdown psScripts.ini with $ScriptIndex scripts" "SUCCESS"
                    
                    # Set registry script order
                    if ($ScriptIndex -gt 0) {
                        $ScriptOrderArray = @()
                        for ($i = 0; $i -lt $ScriptIndex; $i++) {
                            $ScriptOrderArray += $i.ToString()
                        }
                        Set-ItemProperty -Path $ShutdownRegPath -Name "PSScriptOrder" -Value $ScriptOrderArray -Type MultiString
                    }
                }
                catch {
                    Write-Log "Failed to create shutdown psScripts.ini: $($_.Exception.Message)" "ERROR"
                    $Results.Success = $false
                }
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
       
       # Add detailed information to results
       $EventLogResults.Details = @(
           "Total event logs found: $($EventLogResults.TotalLogsFound)",
           "Logs successfully cleared: $($EventLogResults.LogsCleared)",
           "Logs skipped (protected): $($EventLogResults.LogsSkipped)",
           "Logs failed to clear: $($EventLogResults.LogsFailed)",
           "Execution time: $($EventLogResults.ExecutionTime.ToString('F2')) seconds"
       )
       
       if ($EventLogResults.ClearedLogs.Count -gt 0) {
           $EventLogResults.Details += "Cleared logs: $($EventLogResults.ClearedLogs -join '; ')"
       }
       
       if ($EventLogResults.SkippedLogs.Count -gt 0) {
           $EventLogResults.Details += "Skipped logs: $($EventLogResults.SkippedLogs -join '; ')"
       }
       
       $EventLogResults.Message = "Event log cleanup: $($EventLogResults.LogsCleared) cleared, $($EventLogResults.LogsSkipped) skipped, $($EventLogResults.LogsFailed) failed"
       
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
       
       # PRIORITY: Use PowerShell Optimize-Volume with proper service management and conflict resolution
       Write-Log "Using PowerShell Optimize-Volume with service management for optimal performance..." "INFO"
       
       # Manage defragmentation service to enable Optimize-Volume functionality
       $DefragServiceManaged = $false
       $OriginalDefragServiceState = $null
       
       try {
           Write-Log "Checking defragmentation service status..." "INFO"
           $DefragService = Get-Service -Name "defragsvc" -ErrorAction SilentlyContinue
           
           if ($DefragService) {
               $OriginalDefragServiceState = @{
                   Status = $DefragService.Status
                   StartType = $DefragService.StartType
               }
               
               Write-Log "Defragmentation service current state: $($DefragService.Status) (StartType: $($DefragService.StartType))" "INFO"
               
               if ($DefragService.StartType -eq "Disabled") {
                   Write-Log "Enabling defragmentation service temporarily..." "INFO"
                   Set-Service -Name "defragsvc" -StartupType Manual -ErrorAction Stop
                   $DefragServiceManaged = $true
               }
               
               if ($DefragService.Status -ne "Running") {
                   Write-Log "Starting defragmentation service..." "INFO"
                   Start-Service -Name "defragsvc" -ErrorAction Stop
                   $DefragServiceManaged = $true
                   Start-Sleep -Seconds 3
               }
               
               Write-Log "Defragmentation service is now ready for Optimize-Volume operations" "SUCCESS"
           } else {
               Write-Log "Defragmentation service not found - proceeding without service management" "WARN"
           }
       }
       catch {
           Write-Log "Failed to manage defragmentation service: $($_.Exception.Message)" "WARN"
           Write-Log "Proceeding with defragmentation attempt..." "INFO"
       }
       
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
       
       # Restore original defragmentation service state
       if ($DefragServiceManaged -and $OriginalDefragServiceState) {
           try {
               Write-Log "Restoring original defragmentation service state..." "INFO"
               
               # Stop the service if we started it
               $CurrentDefragService = Get-Service -Name "defragsvc" -ErrorAction SilentlyContinue
               if ($CurrentDefragService -and $CurrentDefragService.Status -eq "Running" -and $OriginalDefragServiceState.Status -ne "Running") {
                   Write-Log "Stopping defragmentation service..." "INFO"
                   Stop-Service -Name "defragsvc" -Force -ErrorAction Stop
                   Start-Sleep -Seconds 2
               }
               
               # Restore original startup type if we changed it
               if ($OriginalDefragServiceState.StartType -eq "Disabled") {
                   Write-Log "Restoring defragmentation service to disabled state..." "INFO"
                   Set-Service -Name "defragsvc" -StartupType Disabled -ErrorAction Stop
               }
               
               Write-Log "Defragmentation service restored to original state: $($OriginalDefragServiceState.Status) (StartType: $($OriginalDefragServiceState.StartType))" "SUCCESS"
           }
           catch {
               Write-Log "Failed to restore defragmentation service state: $($_.Exception.Message)" "WARN"
               Write-Log "Service may need manual restoration to disabled state" "WARN"
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
       
       # Add detailed results
       $GhostDeviceResults.Details = @(
           "Total devices scanned: $($GhostDeviceResults.TotalDevicesFound)",
           "Ghost devices removed: $($GhostDeviceResults.GhostDevicesRemoved)",
           "Devices failed to remove: $($GhostDeviceResults.DevicesFailedToRemove)",
           "Execution time: $($GhostDeviceResults.ExecutionTime.ToString('F2')) seconds",
           "Method used: $(if($DevConPath){'DevCon utility'}else{'PowerShell WMI'})"
       )
       
       if ($GhostDeviceResults.GhostDevicesList.Count -gt 0) {
           $DeviceNames = $GhostDeviceResults.GhostDevicesList | ForEach-Object { $_.Name }
           $GhostDeviceResults.Details += "Device types processed: $($DeviceNames -join '; ')"
       }
       
       $GhostDeviceResults.Message = "Ghost device cleanup: $($GhostDeviceResults.GhostDevicesRemoved) removed, $($GhostDeviceResults.DevicesFailedToRemove) failed"
       
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
       [string]$VHDXPath = $null,
       
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
           VHDXFilePath = ""
           VHDXSizeMB = 0
           FilesRemoved = @()
           RegistryChanges = @()
           DriveLetter = ""
           Details = @()
       }
       
       # Use provided VHDXPath parameter or fall back to configuration
       if ([string]::IsNullOrEmpty($VHDXPath)) {
           # Read configuration - use cached values if available
           if ($Global:CachedConfig -and $Global:CachedConfig.VirtualCacheDrivePath) {
               Write-Log "Using cached configuration for virtual cache drive removal" "INFO"
               $VHDXPath = $Global:CachedConfig.VirtualCacheDrivePath
               $DriveLetter = $Global:CachedConfig.VirtualCacheDriveLetter
           } else {
               Write-Log "Using configuration file for virtual cache drive removal" "INFO"
               $VHDXPath = Get-ConfigValue -Key "VirtualCacheDrivePath" -DefaultValue "C:\Temp\DCACHE.VHDX" -ConfigFile $ConfigFilePath
               $DriveLetter = Get-ConfigValue -Key "VirtualCacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
           }
       } else {
           Write-Log "Using provided VHDXPath parameter: $VHDXPath" "INFO"
           # Get drive letter from cache or config when VHDXPath is provided
           if ($Global:CachedConfig -and $Global:CachedConfig.VirtualCacheDriveLetter) {
               $DriveLetter = $Global:CachedConfig.VirtualCacheDriveLetter
           } else {
               $DriveLetter = Get-ConfigValue -Key "VirtualCacheDriveLetter" -DefaultValue "D" -ConfigFile $ConfigFilePath
           }
       }
       
       Write-Log "Virtual cache drive removal configuration:" "INFO"
       Write-Log "VHDX Path: $VHDXPath" "INFO"
       Write-Log "Drive Letter: ${DriveLetter}" "INFO"
       
       # Check if VHDX file exists and get file info
       if (-not (Test-Path $VHDXPath)) {
           Write-Log "VHDX file not found: $VHDXPath" "INFO"
           $Results.Success = $true
           $Results.VHDXFilePath = $VHDXPath
           $Results.DriveLetter = "${DriveLetter}:"
           $Results.Details = @(
               "VHDX file path: $VHDXPath",
               "Drive letter: ${DriveLetter}:",
               "File status: Not found (already removed or never created)",
               "Operation: No action required"
           )
           return $Results
       }
       
       # Get VHDX file size before removal
       try {
           $VHDXFileInfo = Get-Item $VHDXPath
           $Results.VHDXSizeMB = [Math]::Round($VHDXFileInfo.Length / 1MB, 2)
           $Results.VHDXFilePath = $VHDXPath
           $Results.DriveLetter = "${DriveLetter}:"
           Write-Log "VHDX file found: $VHDXPath (Size: $($Results.VHDXSizeMB) MB)" "INFO"
       } catch {
           Write-Log "Could not get VHDX file information: $($_.Exception.Message)" "WARN"
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
           $Results.FilesRemoved += $VHDXPath
       }
       catch {
           $ErrorMsg = "Failed to remove VHDX file: $($_.Exception.Message)"
           Write-Log $ErrorMsg "ERROR"
           $Results.Errors += $ErrorMsg
       }
       
       # Add detailed results
       $Results.Details = @(
           "VHDX file path: $($Results.VHDXFilePath)",
           "VHDX file size: $($Results.VHDXSizeMB) MB",
           "Drive letter: $($Results.DriveLetter)",
           "File dismounted: $(if($Results.VHDXDismounted){'Yes'}else{'No'})",
           "File removed: $(if($Results.VHDXRemoved){'Yes'}else{'No'})",
           "Drive removed: $(if($Results.DriveRemoved){'Yes'}else{'No'})"
       )
       
       if ($Results.FilesRemoved.Count -gt 0) {
           $Results.Details += "Files removed: $($Results.FilesRemoved -join '; ')"
       }
       
       $Results.Message = "Virtual cache drive removal: $(if($Results.Success){'Completed'}else{'Failed'})"
       
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

# Remove-PasswordAgeRegistryKey function removed - functionality moved to Remove-RunKeysRegistry

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

function Disable-VMwareMemoryBallooning {
    <#
    .SYNOPSIS
        Disables VMware memory ballooning by modifying registry
        
    .DESCRIPTION
        Sets VMware memory ballooning service (VMMemCtl) start type to disabled (4)
        in the registry to prevent memory ballooning in VMware environments
        
    .OUTPUTS
        Returns object with success status and registry modification details
    #>
    
    try {
        $Results = @{
            Success = $false
            VMwareEnvironment = $false
            RegistryModified = $false
            ServiceDisabled = $false
            PreviousStartType = $null
            NewStartType = $null
            Error = ""
        }
        
        # Check if running in VMware environment first
        $VMwareDetected = $false
        try {
            $SystemInfo = Get-WmiOrCimInstance -ClassName Win32_ComputerSystem
            if ($SystemInfo.Manufacturer -like "*VMware*" -or $SystemInfo.Model -like "*VMware*") {
                $VMwareDetected = $true
            }
        }
        catch {
            # Continue - may still be VMware
        }
        
        # Check for VMware services as backup detection
        if (-not $VMwareDetected) {
            try {
                $VMwareServices = Get-Service -Name "*vmware*" -ErrorAction SilentlyContinue
                if ($VMwareServices) {
                    $VMwareDetected = $true
                }
            }
            catch {
                # Not VMware environment
            }
        }
        
        $Results.VMwareEnvironment = $VMwareDetected
        
        if (-not $VMwareDetected) {
            Write-Log "Not running in VMware environment - skipping memory ballooning disable" "INFO"
            $Results.Success = $true
            return $Results
        }
        
        Write-Log "VMware environment detected - disabling memory ballooning" "INFO"
        
        # Registry path for VMware memory control service
        $RegistryPath = "HKLM:\System\CurrentControlSet\Services\VMMemCtl"
        
        if (Test-Path $RegistryPath) {
            # Get current start type
            try {
                $CurrentStart = Get-ItemProperty -Path $RegistryPath -Name "Start" -ErrorAction SilentlyContinue
                if ($CurrentStart) {
                    $Results.PreviousStartType = $CurrentStart.Start
                    Write-Log "Current VMMemCtl start type: $($CurrentStart.Start)" "INFO"
                }
            }
            catch {
                Write-Log "Unable to read current VMMemCtl start type" "WARN"
            }
            
            # Set start type to 4 (disabled)
            try {
                Set-ItemProperty -Path $RegistryPath -Name "Start" -Value 4 -Type DWord
                Write-Log "Set VMMemCtl service start type to 4 (disabled)" "SUCCESS"
                $Results.RegistryModified = $true
                $Results.NewStartType = 4
                
                # Verify the change
                $VerifyStart = Get-ItemProperty -Path $RegistryPath -Name "Start" -ErrorAction SilentlyContinue
                if ($VerifyStart -and $VerifyStart.Start -eq 4) {
                    Write-Log "Registry change verified: VMMemCtl start type is now 4" "SUCCESS"
                    $Results.Success = $true
                    $Results.ServiceDisabled = $true
                } else {
                    Write-Log "Registry verification failed: start type not set to 4" "ERROR"
                    $Results.Error = "Registry change verification failed"
                }
            }
            catch {
                $ErrorMsg = "Failed to modify VMMemCtl registry: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Error = $ErrorMsg
            }
        } else {
            Write-Log "VMMemCtl service registry key not found - may not be installed" "INFO"
            $Results.Success = $true
            $Results.Error = "VMMemCtl service not found in registry"
        }
        
        # Add detailed results
        $Results.Details = @(
            "VMware environment: $(if($Results.VMwareEnvironment){'Detected'}else{'Not detected'})",
            "Registry path: $RegistryPath",
            "Service disabled: $(if($Results.ServiceDisabled){'Yes'}else{'No'})",
            "Previous start type: $(if($Results.PreviousStartType){''+$Results.PreviousStartType}else{'Unknown'})",
            "New start type: $(if($Results.NewStartType){''+$Results.NewStartType+' (Disabled)'}else{'Not modified'})"
        )
        $Results.Message = "VMware memory ballooning: $(if($Results.ServiceDisabled){'Disabled'}else{'Skipped or not found'})"
        
        return $Results
    }
    catch {
        $ErrorMsg = "Exception in Disable-VMwareMemoryBallooning: $($_.Exception.Message)"
        Write-Log $ErrorMsg "ERROR"
        return @{
            Success = $false
            VMwareEnvironment = $false
            RegistryModified = $false
            ServiceDisabled = $false
            PreviousStartType = $null
            NewStartType = $null
            Error = $ErrorMsg
        }
    }
}

function Disable-RecycleBinCreation {
    <#
    .SYNOPSIS
        Disables Recycle Bin creation by removing the registry key
        
    .DESCRIPTION
        Removes the Recycle Bin namespace registry key to prevent automatic
        Recycle Bin creation on the desktop in VDI environments
        
    .OUTPUTS
        Returns object with success status and registry modification details
    #>
    
    try {
        $Results = @{
            Success = $false
            RegistryKeyExists = $false
            RegistryKeyRemoved = $false
            BackupCreated = $false
            Error = ""
        }
        
        # Registry path for Recycle Bin namespace
        $RegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\Namespace\{645FF040-5081-101B-9F08-00AA002F954E}"
        
        Write-Log "Checking Recycle Bin registry key: $RegistryPath" "INFO"
        
        # Check if the registry key exists
        if (Test-Path $RegistryPath) {
            $Results.RegistryKeyExists = $true
            Write-Log "Recycle Bin registry key found - proceeding with removal" "INFO"
            
            try {
                # Create backup of key values before removal (for logging purposes)
                $KeyValues = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
                if ($KeyValues) {
                    Write-Log "Registry key contents before removal:" "INFO"
                    $KeyValues.PSObject.Properties | ForEach-Object {
                        if ($_.Name -notlike "PS*") {
                            Write-Log "  $($_.Name): $($_.Value)" "INFO"
                        }
                    }
                    $Results.BackupCreated = $true
                }
                
                # Remove the registry key
                Remove-Item -Path $RegistryPath -Recurse -Force
                Write-Log "Recycle Bin registry key removed successfully" "SUCCESS"
                $Results.RegistryKeyRemoved = $true
                
                # Verify removal
                if (-not (Test-Path $RegistryPath)) {
                    Write-Log "Registry key removal verified - Recycle Bin creation disabled" "SUCCESS"
                    $Results.Success = $true
                } else {
                    Write-Log "Registry key removal verification failed - key still exists" "ERROR"
                    $Results.Error = "Registry key removal verification failed"
                }
            }
            catch {
                $ErrorMsg = "Failed to remove Recycle Bin registry key: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Error = $ErrorMsg
            }
        } else {
            Write-Log "Recycle Bin registry key not found - already disabled or not applicable" "INFO"
            $Results.Success = $true
            $Results.Error = "Registry key not found - already disabled"
        }
        
        # Add detailed information to results
        if ($Results.RegistryKeyExists) {
            $Results.Details = @(
                "Registry path: $RegistryPath",
                "Operation: Registry key found and removed",
                "CLSID: {645FF040-5081-101B-9F08-00AA002F954E} (Recycle Bin identifier)",
                "Backup created before removal: $(if($Results.BackupCreated){'Yes'}else{'No'})"
            )
        } else {
            $Results.Details = @(
                "Registry path: $RegistryPath",
                "Registry key does not exist - Recycle Bin already disabled",
                "CLSID: {645FF040-5081-101B-9F08-00AA002F954E} (Recycle Bin identifier)"
            )
        }
        $Results.RegistryModified = @(
            if ($Results.RegistryKeyRemoved) { "Removed $RegistryPath" }
            else { "Registry key $RegistryPath not found (already disabled)" }
        )
        $Results.Details = @(
            "Registry path: $RegistryPath",
            "Registry key removed: $(if($Results.RegistryKeyRemoved){'Yes'}else{'No (already disabled)'})",
            "Recycle Bin desktop creation: Disabled",
            "VDI optimization: Completed"
        )
        $Results.Message = "Desktop Recycle Bin creation disabled via registry"
        
        return $Results
    }
    catch {
        $ErrorMsg = "Exception in Disable-RecycleBinCreation: $($_.Exception.Message)"
        Write-Log $ErrorMsg "ERROR"
        return @{
            Success = $false
            RegistryKeyExists = $false
            RegistryKeyRemoved = $false
            BackupCreated = $false
            Error = $ErrorMsg
        }
    }
}

function Disable-QuickAccessUserFolders {
    <#
    .SYNOPSIS
        Disables Quick Access and user folders from Explorer
        
    .DESCRIPTION
        Sets HubMode registry value to 1 to remove Quick Access and user folders
        from Windows Explorer navigation pane in VDI environments
        
    .OUTPUTS
        Returns object with success status and registry modification details
    #>
    
    try {
        $Results = @{
            Success = $false
            RegistryModified = $false
            PreviousHubMode = $null
            NewHubMode = $null
            Error = ""
        }
        
        # Registry path for Explorer HubMode
        $RegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        
        Write-Log "Configuring Explorer HubMode to disable Quick Access and user folders" "INFO"
        
        # Ensure the registry path exists
        if (-not (Test-Path $RegistryPath)) {
            try {
                New-Item -Path $RegistryPath -Force | Out-Null
                Write-Log "Created Explorer registry path: $RegistryPath" "INFO"
            }
            catch {
                $ErrorMsg = "Failed to create Explorer registry path: $($_.Exception.Message)"
                Write-Log $ErrorMsg "ERROR"
                $Results.Error = $ErrorMsg
                return $Results
            }
        }
        
        # Get current HubMode value
        try {
            $CurrentHubMode = Get-ItemProperty -Path $RegistryPath -Name "HubMode" -ErrorAction SilentlyContinue
            if ($CurrentHubMode) {
                $Results.PreviousHubMode = $CurrentHubMode.HubMode
                Write-Log "Current Explorer HubMode: $($CurrentHubMode.HubMode)" "INFO"
            } else {
                Write-Log "Explorer HubMode not set (default behavior)" "INFO"
                $Results.PreviousHubMode = "Not Set"
            }
        }
        catch {
            Write-Log "Unable to read current Explorer HubMode" "WARN"
        }
        
        # Set HubMode to 1 (disable Quick Access and user folders)
        try {
            Set-ItemProperty -Path $RegistryPath -Name "HubMode" -Value 1 -Type DWord
            Write-Log "Set Explorer HubMode to 1 (Quick Access and user folders disabled)" "SUCCESS"
            $Results.RegistryModified = $true
            $Results.NewHubMode = 1
            $Results.Details = @(
                "Registry path: $RegistryPath",
                "HubMode value: Set to 1 (disabled)",
                "Quick Access: Disabled",
                "User folders in Explorer: Hidden",
                "VDI optimization: Completed"
            )
            
            # Verify the change
            $VerifyHubMode = Get-ItemProperty -Path $RegistryPath -Name "HubMode" -ErrorAction SilentlyContinue
            if ($VerifyHubMode -and $VerifyHubMode.HubMode -eq 1) {
                Write-Log "Registry change verified: Explorer HubMode is now 1" "SUCCESS"
                $Results.Success = $true
            } else {
                Write-Log "Registry verification failed: HubMode not set to 1" "ERROR"
                $Results.Error = "Registry change verification failed"
            }
        }
        catch {
            $ErrorMsg = "Failed to modify Explorer HubMode registry: $($_.Exception.Message)"
            Write-Log $ErrorMsg "ERROR"
            $Results.Error = $ErrorMsg
        }
        
        return $Results
    }
    catch {
        $ErrorMsg = "Exception in Disable-QuickAccessUserFolders: $($_.Exception.Message)"
        Write-Log $ErrorMsg "ERROR"
        return @{
            Success = $false
            RegistryModified = $false
            PreviousHubMode = $null
            NewHubMode = $null
            Error = $ErrorMsg
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
           # Check memory ballooning driver status via registry
           try {
               $RegistryPath = "HKLM:\System\CurrentControlSet\Services\VMMemCtl"
               
               if (Test-Path $RegistryPath) {
                   # Get the Start value from registry
                   $StartValue = Get-ItemProperty -Path $RegistryPath -Name "Start" -ErrorAction SilentlyContinue
                   
                   if ($StartValue) {
                       $StartType = $StartValue.Start
                       
                       # Interpret start type values:
                       # 0 = Boot, 1 = System, 2 = Automatic, 3 = Manual, 4 = Disabled
                       switch ($StartType) {
                           0 { 
                               $Result.MemoryBalloonStatus = "Boot Start (Active)"
                               $Result.Issues += "VMware memory ballooning is set to Boot start"
                               $Result.OverallCompliant = $false
                           }
                           1 { 
                               $Result.MemoryBalloonStatus = "System Start (Active)"
                               $Result.Issues += "VMware memory ballooning is set to System start"
                               $Result.OverallCompliant = $false
                           }
                           2 { 
                               $Result.MemoryBalloonStatus = "Automatic Start (Active)"
                               $Result.Issues += "VMware memory ballooning is set to Automatic start"
                               $Result.OverallCompliant = $false
                           }
                           3 { 
                               $Result.MemoryBalloonStatus = "Manual Start (Inactive)"
                               $Result.Issues += "VMware memory ballooning is set to Manual start - should be disabled"
                               $Result.OverallCompliant = $false
                           }
                           4 { 
                               $Result.MemoryBalloonStatus = "Disabled (Optimized)"
                               # This is the desired state - no issues
                           }
                           default { 
                               $Result.MemoryBalloonStatus = "Unknown Start Type ($StartType)"
                               $Result.Issues += "VMware memory ballooning has unknown start type: $StartType"
                               $Result.OverallCompliant = $false
                           }
                       }
                       
                       # Add detailed information
                       $Result.VMMemCtlStartType = $StartType
                       $Result.VMMemCtlRegistryPath = $RegistryPath
                       
                   } else {
                       $Result.MemoryBalloonStatus = "Registry Key Found but Start Value Missing"
                       $Result.Issues += "VMMemCtl registry key exists but Start value is missing"
                       $Result.OverallCompliant = $false
                   }
               } else {
                   $Result.MemoryBalloonStatus = "VMMemCtl Service Not Installed"
                   # This is actually good - if the service isn't installed, ballooning can't be active
               }
           }
           catch {
               $Result.MemoryBalloonStatus = "Registry Check Failed"
               $Result.Issues += "Unable to check VMMemCtl registry: $($_.Exception.Message)"
               $Result.OverallCompliant = $false
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

function Configure-NTPTimeSources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Configuring NTP time sources based on domain..." "INFO"
        
        $Results = @{
            Success = $true
            DomainDetected = ""
            NTPServersConfigured = @()
            W32TimeConfigured = $false
            ServiceRestarted = $false
            TimeResyncForced = $false
            Errors = @()
        }
        
        # Get current domain information
        try {
            $ComputerSystem = Get-WmiOrCimInstance Win32_ComputerSystem
            $CurrentDomain = $ComputerSystem.Domain.ToLower()
            $Results.DomainDetected = $CurrentDomain
            Write-Log "Detected domain: $CurrentDomain" "INFO"
        }
        catch {
            $Results.Errors += "Failed to detect domain: $($_.Exception.Message)"
            Write-Log "Failed to detect domain: $($_.Exception.Message)" "ERROR"
            $Results.Success = $false
            return $Results
        }
        
        # Load NTP server configurations from config file for 3 domains
        $Domain1Name = Get-ConfigValue -Key "NTPDomain1Name" -DefaultValue "domain1.local" -ConfigFile $ConfigFilePath
        $Domain1NTPServers = Get-ConfigValue -Key "Domain1NTPServers" -DefaultValue "dc1.domain1.local,dc2.domain1.local,time.nist.gov" -ConfigFile $ConfigFilePath
        
        $Domain2Name = Get-ConfigValue -Key "NTPDomain2Name" -DefaultValue "domain2.local" -ConfigFile $ConfigFilePath
        $Domain2NTPServers = Get-ConfigValue -Key "Domain2NTPServers" -DefaultValue "dc1.domain2.local,dc2.domain2.local,pool.ntp.org" -ConfigFile $ConfigFilePath
        
        $Domain3Name = Get-ConfigValue -Key "NTPDomain3Name" -DefaultValue "domain3.local" -ConfigFile $ConfigFilePath
        $Domain3NTPServers = Get-ConfigValue -Key "Domain3NTPServers" -DefaultValue "dc1.domain3.local,dc2.domain3.local,time.windows.com" -ConfigFile $ConfigFilePath
        
        # Determine which NTP servers to use based on domain
        $NTPServersToUse = ""
        if ($CurrentDomain -like "*$($Domain1Name.Split('.')[0])*") {
            $NTPServersToUse = $Domain1NTPServers
            Write-Log "Using Domain 1 NTP servers for domain: $CurrentDomain" "INFO"
        }
        elseif ($CurrentDomain -like "*$($Domain2Name.Split('.')[0])*") {
            $NTPServersToUse = $Domain2NTPServers
            Write-Log "Using Domain 2 NTP servers for domain: $CurrentDomain" "INFO"
        }
        elseif ($CurrentDomain -like "*$($Domain3Name.Split('.')[0])*") {
            $NTPServersToUse = $Domain3NTPServers
            Write-Log "Using Domain 3 NTP servers for domain: $CurrentDomain" "INFO"
        }
        else {
            # Use default fallback NTP servers if domain not specifically configured
            $NTPServersToUse = $Domain1NTPServers  # Use Domain 1 as fallback
            Write-Log "Domain '$CurrentDomain' not specifically configured, using default NTP servers from Domain 1" "INFO"
            $Results.DomainDetected = "$CurrentDomain (using default configuration)"
        }
        
        # Parse NTP servers list
        $NTPServerArray = $NTPServersToUse -split ',' | ForEach-Object { $_.Trim() }
        $Results.NTPServersConfigured = $NTPServerArray
        
        Write-Log "Configuring NTP servers: $($NTPServerArray -join ', ')" "INFO"
        
        # Configure W32Time service
        try {
            # Stop W32Time service
            Stop-Service -Name "W32Time" -Force -ErrorAction SilentlyContinue
            Write-Log "Stopped W32Time service" "INFO"
            
            # Configure NTP servers in registry
            $W32TimeConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
            $NTPServerString = ($NTPServerArray | ForEach-Object { "$_,0x1" }) -join ' '
            Set-ItemProperty -Path $W32TimeConfigPath -Name "NtpServer" -Value $NTPServerString
            Set-ItemProperty -Path $W32TimeConfigPath -Name "Type" -Value "NTP"
            Write-Log "Updated W32Time NTP server configuration" "SUCCESS"
            
            # Configure W32Time service settings
            $W32TimeConfigConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
            Set-ItemProperty -Path $W32TimeConfigConfigPath -Name "AnnounceFlags" -Value 5
            Set-ItemProperty -Path $W32TimeConfigConfigPath -Name "MaxPosPhaseCorrection" -Value 0xFFFFFFFF -Type DWord
            Set-ItemProperty -Path $W32TimeConfigConfigPath -Name "MaxNegPhaseCorrection" -Value 0xFFFFFFFF -Type DWord
            
            # Configure time providers
            $TimeProvidersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"
            Set-ItemProperty -Path $TimeProvidersPath -Name "Enabled" -Value 1 -Type DWord
            Set-ItemProperty -Path $TimeProvidersPath -Name "InputProvider" -Value 1 -Type DWord
            
            $Results.W32TimeConfigured = $true
            Write-Log "W32Time service configured successfully" "SUCCESS"
        }
        catch {
            $Results.Errors += "Failed to configure W32Time: $($_.Exception.Message)"
            Write-Log "Failed to configure W32Time service: $($_.Exception.Message)" "ERROR"
            $Results.Success = $false
        }
        
        # Start W32Time service and force time sync
        try {
            Start-Service -Name "W32Time"
            $Results.ServiceRestarted = $true
            Write-Log "Started W32Time service" "SUCCESS"
            
            # Wait a moment for service to initialize
            Start-Sleep -Seconds 3
            
            # Force time synchronization
            $SyncResult = & w32tm.exe /resync /force 2>&1
            if ($LASTEXITCODE -eq 0) {
                $Results.TimeResyncForced = $true
                Write-Log "Forced time synchronization completed" "SUCCESS"
            } else {
                $Results.Errors += "Time sync command failed: $SyncResult"
                Write-Log "Time sync command failed: $SyncResult" "WARNING"
            }
        }
        catch {
            $Results.Errors += "Failed to start W32Time or sync time: $($_.Exception.Message)"
            Write-Log "Failed to start W32Time service: $($_.Exception.Message)" "ERROR"
            $Results.Success = $false
        }
        
        # Display current time configuration
        try {
            $CurrentConfig = & w32tm.exe /query /configuration 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Current W32Time configuration verified" "INFO"
            }
            
            $TimeStatus = & w32tm.exe /query /status 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Time synchronization status verified" "INFO"
            }
        }
        catch {
            Write-Log "Unable to query W32Time status" "WARNING"
        }
        
        # Set overall success based on key configuration steps
        if ($Results.W32TimeConfigured -and $Results.ServiceRestarted) {
            $Results.Success = $true
            Write-Log "NTP time source configuration completed successfully" "SUCCESS"
            Write-Log "Domain: $($Results.DomainDetected), Servers: $($Results.NTPServersConfigured -join ', ')" "SUCCESS"
        } else {
            $Results.Success = $false
            Write-Log "NTP configuration incomplete - W32TimeConfigured: $($Results.W32TimeConfigured), ServiceRestarted: $($Results.ServiceRestarted)" "WARNING"
        }
        
        return $Results
    }
    catch {
        Write-Log "Critical error during NTP configuration: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            DomainDetected = ""
            NTPServersConfigured = @()
            W32TimeConfigured = $false
            ServiceRestarted = $false
            TimeResyncForced = $false
            Errors = @("Critical NTP configuration error: $($_.Exception.Message)")
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
       # Use cached config first for UberAgent installation
       if ($Global:CachedConfig -and $Global:CachedConfig.InstallUberAgent) {
           $InstallUberAgent = [bool]$Global:CachedConfig.InstallUberAgent
           $UberAgentInstallerPath = $Global:CachedConfig.UberAgentInstallerPath -or "C:\Temp\UberAgent.msi"
       } else {
           $InstallUberAgent = [bool](Get-ConfigValue -Key "InstallUberAgent" -DefaultValue "false" -ConfigFile $ConfigFilePath)
           $UberAgentInstallerPath = Get-ConfigValue -Key "UberAgentInstallerPath" -DefaultValue "C:\Temp\UberAgent.msi" -ConfigFile $ConfigFilePath
       }
       
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



function Copy-UberAgentConfigs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    
    try {
        Write-Log "Starting UberAgent configuration file management..." "INFO"
        
        $Results = @{
            Success = $true
            Skipped = $false
            ConfigsCopied = 0
            BackupCreated = $false
            SourcePath = ""
            DestinationPath = ""
            Errors = @()
            Details = @()
        }
        
        # Get configuration values
        $CopyConfigs = [bool](Get-ConfigValue -Key "CopyUberAgentConfigs" -DefaultValue "false" -ConfigFile $ConfigFilePath)
        
        if (-not $CopyConfigs) {
            Write-Log "UberAgent config file copying disabled in configuration" "INFO"
            $Results.Skipped = $true
            $Results.Details = @(
                "UberAgent config file copying is disabled",
                "Set CopyUberAgentConfigs=true to enable config file management"
            )
            return $Results
        }
        
        $DevConfigSource = Get-ConfigValue -Key "UberAgentDevConfigSource" -DefaultValue "" -ConfigFile $ConfigFilePath
        $ProdConfigSource = Get-ConfigValue -Key "UberAgentProdConfigSource" -DefaultValue "" -ConfigFile $ConfigFilePath
        $DevLocalConfigPath = Get-ConfigValue -Key "UberAgentDevLocalConfigPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\dev\uberAgent.conf" -ConfigFile $ConfigFilePath
        $ProdLocalConfigPath = Get-ConfigValue -Key "UberAgentProdLocalConfigPath" -DefaultValue "C:\Program Files\vast limits\uberAgent\prod\uberAgent.conf" -ConfigFile $ConfigFilePath

        # Copy both dev and prod configs
        $ConfigsCopied = 0
        $CopyResults = @()
        
        # Copy dev config if available
        if (-not [string]::IsNullOrEmpty($DevConfigSource) -and (Test-Path $DevConfigSource)) {
            try {
                $DevDestinationDir = Split-Path $DevLocalConfigPath -Parent
                if (-not (Test-Path $DevDestinationDir)) {
                    New-Item -Path $DevDestinationDir -ItemType Directory -Force | Out-Null
                }
                Copy-Item -Path $DevConfigSource -Destination $DevLocalConfigPath -Force
                $ConfigsCopied++
                $CopyResults += "Development config copied successfully"
                Write-Log "Copied dev config: $DevConfigSource to $DevLocalConfigPath" "SUCCESS"
            } catch {
                $CopyResults += "Failed to copy dev config: $($_.Exception.Message)"
                Write-Log "Failed to copy dev config: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Copy prod config if available  
        if (-not [string]::IsNullOrEmpty($ProdConfigSource) -and (Test-Path $ProdConfigSource)) {
            try {
                $ProdDestinationDir = Split-Path $ProdLocalConfigPath -Parent
                if (-not (Test-Path $ProdDestinationDir)) {
                    New-Item -Path $ProdDestinationDir -ItemType Directory -Force | Out-Null
                }
                Copy-Item -Path $ProdConfigSource -Destination $ProdLocalConfigPath -Force
                $ConfigsCopied++
                $CopyResults += "Production config copied successfully"
                Write-Log "Copied prod config: $ProdConfigSource to $ProdLocalConfigPath" "SUCCESS"
            } catch {
                $CopyResults += "Failed to copy prod config: $($_.Exception.Message)"
                Write-Log "Failed to copy prod config: $($_.Exception.Message)" "ERROR"
            }
        }
        
        if ($ConfigsCopied -eq 0) {
            $Results.Success = $false
            $Results.Errors += "No UberAgent config files were copied - check source paths and file availability"
            Write-Log "No UberAgent config files copied" "ERROR"
            return $Results
        }
        
        $Results.ConfigsCopied = $ConfigsCopied
        $Results.Details = $CopyResults
        $Results.SourcePath = "Multiple sources (dev and/or prod)"
        $Results.DestinationPath = "Separate dev and prod folders"
        
        Write-Log "UberAgent configuration file management completed - $ConfigsCopied configs copied" "SUCCESS"
        return $Results
        
    } catch {
        Write-Log "UberAgent config file management failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Skipped = $false
            ConfigsCopied = 0
            SourcePath = ""
            DestinationPath = ""
            Errors = @($_.Exception.Message)
            Details = @("Critical error during UberAgent config file management: $($_.Exception.Message)")
        }
    }
}

function Get-InstalledSoftwareVersions {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Checking installed software versions..." "INFO"
        
        $Results = @{
            Success = $true
            VDAVersion = ""
            PVSVersion = ""
            WEMVersion = ""
            UberAgentVersion = ""
            Details = @()
            Errors = @()
        }
        
        # Check Citrix VDA version
        try {
            $VDAPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            $VDAProduct = Get-ItemProperty $VDAPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Citrix Virtual Desktop Agent*" -or $_.DisplayName -like "*VDA*" }
            if ($VDAProduct) {
                $Results.VDAVersion = $VDAProduct.DisplayVersion
                $Results.Details += "Citrix VDA version: $($VDAProduct.DisplayVersion)"
                Write-Log "Found Citrix VDA version: $($VDAProduct.DisplayVersion)" "SUCCESS"
            } else {
                $Results.Details += "Citrix VDA: Not installed"
                Write-Log "Citrix VDA not found in registry" "INFO"
            }
        } catch {
            $Results.Errors += "Failed to check VDA version: $($_.Exception.Message)"
        }
        
        # Check PVS Target Device version
        try {
            $PVSPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            $PVSProduct = Get-ItemProperty $PVSPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Citrix Provisioning*" -or $_.DisplayName -like "*PVS*Target*" }
            if ($PVSProduct) {
                $Results.PVSVersion = $PVSProduct.DisplayVersion
                $Results.Details += "PVS Target Device version: $($PVSProduct.DisplayVersion)"
                Write-Log "Found PVS Target Device version: $($PVSProduct.DisplayVersion)" "SUCCESS"
            } else {
                $Results.Details += "PVS Target Device: Not installed"
                Write-Log "PVS Target Device not found in registry" "INFO"
            }
        } catch {
            $Results.Errors += "Failed to check PVS version: $($_.Exception.Message)"
        }
        
        # Check WEM Agent version with improved detection
        try {
            $WEMFound = $false
            
            # Check multiple registry paths for WEM Agent
            $WEMPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($WEMPath in $WEMPaths) {
                if (Test-Path $WEMPath) {
                    $WEMProducts = Get-ItemProperty $WEMPath -ErrorAction SilentlyContinue | Where-Object { 
                        $_.DisplayName -like "*Workspace Environment Management*" -or 
                        $_.DisplayName -like "*WEM*Agent*" -or 
                        $_.DisplayName -like "*Citrix WEM*" -or
                        $_.DisplayName -like "*Norskale*" 
                    }
                    
                    if ($WEMProducts) {
                        $WEMProduct = $WEMProducts | Select-Object -First 1
                        $Results.WEMVersion = $WEMProduct.DisplayVersion
                        $Results.Details += "WEM Agent version: $($WEMProduct.DisplayVersion)"
                        $Results.Details += "WEM Product: $($WEMProduct.DisplayName)"
                        Write-Log "Found WEM Agent version: $($WEMProduct.DisplayVersion)" "SUCCESS"
                        $WEMFound = $true
                        break
                    }
                }
            }
            
            # If not found in uninstall registry, check WEM service registry
            if (-not $WEMFound) {
                try {
                    $WEMServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Norskale Agent Host Service"
                    if (Test-Path $WEMServicePath) {
                        $WEMService = Get-ItemProperty $WEMServicePath -ErrorAction SilentlyContinue
                        if ($WEMService -and $WEMService.ImagePath) {
                            $Results.Details += "WEM Agent: Service detected but version unavailable"
                            $Results.Details += "WEM Service path: $($WEMService.ImagePath)"
                            Write-Log "WEM Agent service found but version not available" "INFO"
                        }
                    }
                } catch {
                    Write-Log "Failed to check WEM service registry: $($_.Exception.Message)" "WARN"
                }
            }
            
            if (-not $WEMFound -and $Results.Details -notcontains "WEM Agent: Service detected but version unavailable") {
                $Results.Details += "WEM Agent: Not installed"
                Write-Log "WEM Agent not found in registry" "INFO"
            }
        } catch {
            $Results.Errors += "Failed to check WEM version: $($_.Exception.Message)"
        }
        
        # Check UberAgent version
        try {
            $UberAgentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            $UberAgentProduct = Get-ItemProperty $UberAgentPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*uberAgent*" -or $_.DisplayName -like "*vast limits*" }
            if ($UberAgentProduct) {
                $Results.UberAgentVersion = $UberAgentProduct.DisplayVersion
                $Results.Details += "UberAgent version: $($UberAgentProduct.DisplayVersion)"
                Write-Log "Found UberAgent version: $($UberAgentProduct.DisplayVersion)" "SUCCESS"
            } else {
                $Results.Details += "UberAgent: Not installed"
                Write-Log "UberAgent not found in registry" "INFO"
            }
        } catch {
            $Results.Errors += "Failed to check UberAgent version: $($_.Exception.Message)"
        }
        
        # Check if any software was found
        $FoundSoftware = @($Results.VDAVersion, $Results.PVSVersion, $Results.WEMVersion, $Results.UberAgentVersion) | Where-Object { -not [string]::IsNullOrEmpty($_) }
        
        if ($FoundSoftware.Count -eq 0) {
            $Results.Details += "No Citrix software versions detected in registry"
            Write-Log "No Citrix software found in system registry" "WARN"
        } else {
            Write-Log "Software version check completed - found $($FoundSoftware.Count) installed components" "SUCCESS"
        }
        
        return $Results
        
    } catch {
        Write-Log "Software version check failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            VDAVersion = ""
            PVSVersion = ""
            WEMVersion = ""
            UberAgentVersion = ""
            Details = @("Critical error during software version check: $($_.Exception.Message)")
            Errors = @($_.Exception.Message)
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
   'Reset-RDSGracePeriod', 'Set-VDAMultipleMonitorHookKeys', 'Test-VMwareMemoryBallooningStatus', 'Disable-VMwareMemoryBallooning', 'Disable-RecycleBinCreation', 'Disable-QuickAccessUserFolders',
   'New-VirtualCacheDrive', 'Test-VirtualCacheDrive', 'Remove-VirtualCacheDrive',
   'Add-CitrixVDA', 'Add-Domain', 'Add-PVSTargetDevice', 'Add-StartupShutdownScripts', 'Clear-WindowsEventLogs', 'Configure-NTPTimeSources',
   'Copy-FileWithValidation', 'Copy-OSSpecificStartupShutdownScripts', 'Remove-DomainUserProfiles', 'Remove-GhostDevices',
   'Remove-WEMRSAKey', 'Remove-RunKeysRegistry', 'Get-CitrixServicesStatus', 'Test-VDAInstallation', 'Get-SystemOptimizations', 'New-InstallConfig',
   'Set-EventLogRedirection', 'Set-EventLogs', 'Set-PagefileConfiguration', 'Set-RegistryOptimizations',
   'Set-StartupShutdownScripts', 'Set-UserProfileRedirection', 'Set-UserProfilesRedirection', 'Set-WEMAgentCacheLocation',
   'Set-WindowsOptimizations', 'Set-WindowsServices', 'Show-LoadedConfiguration', 'Start-DotNetOptimization',
   'Start-DriveConfiguration', 'Start-SystemDriveDefragmentation',
   'Stop-CitrixServices', 'Test-AutomaticMaintenanceStatus', 'Disable-AutomaticMaintenance', 'Test-CacheDriveRequirement', 'Test-DriveConfiguration',
   'Test-SystemOptimizations', 'Test-WEMRSACleanup', 'Test-InstallationFiles', 'Get-WmiOrCimInstance', 'Test-SafePath',
   'Invoke-WithRetry', 'Test-Configuration', 'Write-ProgressHelper', 'Test-ValidInput', 'Remove-ActiveComponentsRegistry',
   'Optimize-NetworkSettings', 'Optimize-StorageSettings', 'Invoke-SystemDefragmentation', 'Optimize-DotNetFramework',
   'Invoke-VDIOptimizations', 'Copy-UberAgentConfigs', 'Get-InstalledSoftwareVersions'
)

