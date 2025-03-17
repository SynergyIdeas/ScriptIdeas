# Compare-GroupPolicies.ps1
# Script to compare two Group Policy Objects and identify differences
# Usage: .\Compare-GroupPolicies.ps1 -ReferenceGPO "GPO1 Name" -DifferenceGPO "GPO2 Name" -OutputPath "C:\Reports"

param (
    [Parameter(Mandatory=$true)]
    [string]$ReferenceGPO,
    
    [Parameter(Mandatory=$true)]
    [string]$DifferenceGPO,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportHTML = $false
)

# Ensure the GroupPolicy module is loaded
if (-not (Get-Module -Name GroupPolicy -ErrorAction SilentlyContinue)) {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Write-Host "GroupPolicy module loaded successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to load GroupPolicy module. Make sure RSAT tools are installed."
        exit 1
    }
}

function Test-GPOExists {
    param ([string]$GPOName)
    
    $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    return ($null -ne $gpo)
}

function Get-FormattedDate {
    return Get-Date -Format "yyyyMMdd-HHmmss"
}

# Validate both GPOs exist
if (-not (Test-GPOExists -GPOName $ReferenceGPO)) {
    Write-Error "Reference GPO '$ReferenceGPO' does not exist."
    exit 1
}

if (-not (Test-GPOExists -GPOName $DifferenceGPO)) {
    Write-Error "Difference GPO '$DifferenceGPO' does not exist."
    exit 1
}

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Yellow
}

# Get the formatted timestamp for file naming
$timestamp = Get-FormattedDate
$outputFile = Join-Path -Path $OutputPath -ChildPath "GPO_Comparison_${ReferenceGPO}_vs_${DifferenceGPO}_$timestamp.txt"
$htmlFile = Join-Path -Path $OutputPath -ChildPath "GPO_Comparison_${ReferenceGPO}_vs_${DifferenceGPO}_$timestamp.html"
$xmlRefFile = Join-Path -Path $OutputPath -ChildPath "GPO_${ReferenceGPO}_$timestamp.xml"
$xmlDiffFile = Join-Path -Path $OutputPath -ChildPath "GPO_${DifferenceGPO}_$timestamp.xml"

# First, back up the GPOs to XML for further analysis
Write-Host "Backing up reference GPO '$ReferenceGPO' to XML..." -ForegroundColor Cyan
$refGPO = Get-GPO -Name $ReferenceGPO
$refGPO | Get-GPOReport -ReportType Xml -Path $xmlRefFile

Write-Host "Backing up difference GPO '$DifferenceGPO' to XML..." -ForegroundColor Cyan
$diffGPO = Get-GPO -Name $DifferenceGPO
$diffGPO | Get-GPOReport -ReportType Xml -Path $xmlDiffFile

# Get and compare GPO settings
Write-Host "Comparing GPO settings..." -ForegroundColor Cyan

# Analyze GPO metadata first
$refMeta = @{
    "DisplayName" = $refGPO.DisplayName
    "ID" = $refGPO.Id
    "CreationTime" = $refGPO.CreationTime
    "ModificationTime" = $refGPO.ModificationTime
    "Description" = $refGPO.Description
    "Owner" = $refGPO.Owner
    "DomainName" = $refGPO.DomainName
    "ComputerEnabled" = $refGPO.Computer.Enabled
    "UserEnabled" = $refGPO.User.Enabled
}

$diffMeta = @{
    "DisplayName" = $diffGPO.DisplayName
    "ID" = $diffGPO.Id
    "CreationTime" = $diffGPO.CreationTime
    "ModificationTime" = $diffGPO.ModificationTime
    "Description" = $diffGPO.Description
    "Owner" = $diffGPO.Owner
    "DomainName" = $diffGPO.DomainName
    "ComputerEnabled" = $diffGPO.Computer.Enabled
    "UserEnabled" = $diffGPO.User.Enabled
}

# Compare GPO settings using Group Policy cmdlets
$comparison = Compare-GPO -ReferenceGpo $refGPO -DifferenceGpo $diffGPO -IgnoreComments

# Start building the report
$report = [System.Collections.ArrayList]::new()
$report.Add("# Group Policy Comparison Report") | Out-Null
$report.Add("## Generated on: $(Get-Date)") | Out-Null
$report.Add("## Reference GPO: $ReferenceGPO") | Out-Null
$report.Add("## Difference GPO: $DifferenceGPO") | Out-Null
$report.Add("") | Out-Null

# Add metadata comparison
$report.Add("## Metadata Comparison") | Out-Null

foreach ($key in $refMeta.Keys) {
    $refValue = $refMeta[$key]
    $diffValue = $diffMeta[$key]
    
    if ($key -eq "ID" -or $key -eq "DisplayName") {
        # These are expected to be different
        $report.Add("- $key: [$refValue] vs [$diffValue] (Expected difference)") | Out-Null
    }
    elseif ($refValue -ne $diffValue) {
        $report.Add("- $key: [$refValue] vs [$diffValue] (DIFFERENT)") | Out-Null
    }
    else {
        $report.Add("- $key: [$refValue] (Same)") | Out-Null
    }
}

$report.Add("") | Out-Null

# Analyze GPO settings in detail using the XML reports
[xml]$refXml = Get-Content -Path $xmlRefFile
[xml]$diffXml = Get-Content -Path $xmlDiffFile

# Helper function to analyze policy sections
function Compare-PolicySection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SectionName,
        
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlNode]$RefNode,
        
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlNode]$DiffNode
    )
    
    $sectionReport = [System.Collections.ArrayList]::new()
    $sectionReport.Add("## $SectionName Settings") | Out-Null
    
    if ($null -eq $RefNode -and $null -eq $DiffNode) {
        $sectionReport.Add("- No settings configured in either GPO.") | Out-Null
        return $sectionReport
    }
    
    if ($null -eq $RefNode) {
        $sectionReport.Add("- No settings in Reference GPO, but settings exist in Difference GPO.") | Out-Null
        return $sectionReport
    }
    
    if ($null -eq $DiffNode) {
        $sectionReport.Add("- Settings exist in Reference GPO, but not in Difference GPO.") | Out-Null
        return $sectionReport
    }
    
    # Compare settings here - this is simplified and would need expansion for deep comparison
    $refSettings = $RefNode.SelectNodes(".//q1:Policy", $ns)
    $diffSettings = $DiffNode.SelectNodes(".//q1:Policy", $ns)
    
    $refSettingsDict = @{}
    foreach ($setting in $refSettings) {
        $refSettingsDict[$setting.name] = $setting
    }
    
    $diffSettingsDict = @{}
    foreach ($setting in $diffSettings) {
        $diffSettingsDict[$setting.name] = $setting
    }
    
    # Find settings in reference but not in difference
    foreach ($key in $refSettingsDict.Keys) {
        if (-not $diffSettingsDict.ContainsKey($key)) {
            $sectionReport.Add("- Setting '$key' exists in Reference GPO but not in Difference GPO.") | Out-Null
        }
    }
    
    # Find settings in difference but not in reference
    foreach ($key in $diffSettingsDict.Keys) {
        if (-not $refSettingsDict.ContainsKey($key)) {
            $sectionReport.Add("- Setting '$key' exists in Difference GPO but not in Reference GPO.") | Out-Null
        }
    }
    
    # Compare settings that exist in both
    foreach ($key in $refSettingsDict.Keys) {
        if ($diffSettingsDict.ContainsKey($key)) {
            $refSetting = $refSettingsDict[$key]
            $diffSetting = $diffSettingsDict[$key]
            
            # Compare setting states
            $refState = $refSetting.SelectSingleNode(".//q1:State", $ns)?.InnerText
            $diffState = $diffSetting.SelectSingleNode(".//q1:State", $ns)?.InnerText
            
            if ($refState -ne $diffState) {
                $sectionReport.Add("- Setting '$key' has different state: [$refState] vs [$diffState]") | Out-Null
            }
            
            # Compare setting values (simplified)
            $refValue = $refSetting.SelectSingleNode(".//q1:Value", $ns)?.InnerText
            $diffValue = $diffSetting.SelectSingleNode(".//q1:Value", $ns)?.InnerText
            
            if ($refValue -ne $diffValue) {
                $sectionReport.Add("- Setting '$key' has different value: [$refValue] vs [$diffValue]") | Out-Null
            }
        }
    }
    
    if ($sectionReport.Count -eq 1) {
        $sectionReport.Add("- No differences found in $SectionName settings.") | Out-Null
    }
    
    return $sectionReport
}

# Setup XML namespace for XPath queries
$ns = New-Object System.Xml.XmlNamespaceManager($refXml.NameTable)
$ns.AddNamespace("q1", "http://www.microsoft.com/GroupPolicy/Settings")

# Compare Computer Configuration
$report.Add("## Computer Configuration") | Out-Null
$refComputer = $refXml.GPO.Computer
$diffComputer = $diffXml.GPO.Computer

if ($refComputer.Enabled -ne $diffComputer.Enabled) {
    $report.Add("- Computer Configuration enabled: [$($refComputer.Enabled)] vs [$($diffComputer.Enabled)] (DIFFERENT)") | Out-Null
}

# Compare Registry Settings
$computerRegSettings = Compare-PolicySection -SectionName "Computer Registry" -RefNode $refXml.GPO.Computer.ExtensionData.Extension.Policy -DiffNode $diffXml.GPO.Computer.ExtensionData.Extension.Policy
$report.AddRange($computerRegSettings)

# Compare Security Settings
$computerSecSettings = Compare-PolicySection -SectionName "Computer Security" -RefNode $refXml.GPO.Computer.ExtensionData.Extension.SecurityOptions -DiffNode $diffXml.GPO.Computer.ExtensionData.Extension.SecurityOptions
$report.AddRange($computerSecSettings)

# Compare User Configuration
$report.Add("## User Configuration") | Out-Null
$refUser = $refXml.GPO.User
$diffUser = $diffXml.GPO.User

if ($refUser.Enabled -ne $diffUser.Enabled) {
    $report.Add("- User Configuration enabled: [$($refUser.Enabled)] vs [$($diffUser.Enabled)] (DIFFERENT)") | Out-Null
}

# Compare User Registry Settings
$userRegSettings = Compare-PolicySection -SectionName "User Registry" -RefNode $refXml.GPO.User.ExtensionData.Extension.Policy -DiffNode $diffXml.GPO.User.ExtensionData.Extension.Policy
$report.AddRange($userRegSettings)

# Add summary from Compare-GPO cmdlet
$report.Add("## Detailed Differences") | Out-Null
if ($comparison.Count -eq 0) {
    $report.Add("No differences detected by Compare-GPO cmdlet.") | Out-Null
}
else {
    foreach ($diff in $comparison) {
        $report.Add("- $($diff.DisplayName): $($diff.SettingName) - [$($diff.ReferenceState)] vs [$($diff.DifferenceState)]") | Out-Null
    }
}

# Output the report to the text file
$report | Out-File -FilePath $outputFile -Encoding utf8

Write-Host "GPO comparison complete." -ForegroundColor Green
Write-Host "Text report generated: $outputFile" -ForegroundColor Yellow

# Generate HTML report if requested
if ($ExportHTML) {
    Write-Host "Generating HTML report..." -ForegroundColor Cyan
    
    # Create HTML version of the report
    $htmlContent = $report -replace "^# (.*)", "<h1>`$1</h1>"
    $htmlContent = $htmlContent -replace "^## (.*)", "<h2>`$1</h2>"
    $htmlContent = $htmlContent -replace "^- (.*)", "<li>`$1</li>"
    $htmlContent = "<html><head><title>GPO Comparison Report</title><style>body{font-family:Arial,sans-serif;line-height:1.6;padding:20px;max-width:1200px;margin:0 auto;color:#333}h1{color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:10px}h2{color:#3498db;margin-top:30px}li{margin-bottom:5px}li:nth-child(odd){background-color:#f9f9f9;padding:5px}</style></head><body>" + ($htmlContent -join "") + "</body></html>"
    
    $htmlContent | Out-File -FilePath $htmlFile -Encoding utf8
    Write-Host "HTML report generated: $htmlFile" -ForegroundColor Yellow
}

# Also generate XML reports for both GPOs
Write-Host "XML reports generated:" -ForegroundColor Yellow
Write-Host "Reference GPO XML: $xmlRefFile" -ForegroundColor Yellow
Write-Host "Difference GPO XML: $xmlDiffFile" -ForegroundColor Yellow

Write-Host "Operation completed successfully." -ForegroundColor Green
