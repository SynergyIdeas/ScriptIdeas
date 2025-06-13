function Generate-CitrixReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$InstallResults,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ValidationResults = @{},
        
        [Parameter(Mandatory=$true)]
        [int]$Stage,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ".",
        
        [Parameter(Mandatory=$false)]
        [bool]$OpenInBrowser = $true
    )
    
    # Gather system information
    $ComputerName = $env:COMPUTERNAME
    $UserName = $env:USERNAME
    $ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $OSCaption = $OSInfo.Caption
        $TotalMemoryGB = [math]::Round($OSInfo.TotalVisibleMemorySize / 1MB, 2)
    } catch {
        $OSCaption = "Windows"
        $TotalMemoryGB = "Unknown"
    }
    
    # Calculate statistics
    $TotalComponents = $InstallResults.Keys.Count
    $SuccessfulComponents = 0
    $FailedComponents = 0
    $SkippedComponents = 0
    
    foreach ($ComponentName in $InstallResults.Keys) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            if ($Result.Success -eq $true) {
                $SuccessfulComponents++
            } elseif ($Result.Skipped -eq $true) {
                $SkippedComponents++
            } else {
                $FailedComponents++
            }
        }
    }
    
    $SuccessRate = if ($TotalComponents -gt 0) { [math]::Round(($SuccessfulComponents / $TotalComponents) * 100, 1) } else { 0 }
    
    # Generate HTML content
    $HTML = @()
    
    $HTML += '<!DOCTYPE html>'
    $HTML += '<html lang="en">'
    $HTML += '<head>'
    $HTML += '<meta charset="UTF-8">'
    $HTML += '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
    $HTML += "<title>Citrix Installation Report - Stage $Stage</title>"
    
    # Analytics dashboard CSS
    $HTML += '<style>'
    $HTML += '@import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap");'
    $HTML += '* { margin: 0; padding: 0; box-sizing: border-box; }'
    $HTML += 'body { font-family: "Inter", sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.5; }'
    
    # Header styles
    $HTML += '.header { background: white; border-bottom: 1px solid #e2e8f0; padding: 20px 32px; display: flex; justify-content: space-between; align-items: center; }'
    $HTML += '.header-left { display: flex; align-items: center; }'
    $HTML += '.logo { width: 48px; height: 48px; background: #3C1053; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 20px; margin-right: 20px; }'
    $HTML += '.header-title { font-size: 24px; font-weight: 600; color: #1e293b; margin: 0; }'
    $HTML += '.header-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; }'
    $HTML += '.stage-badge { background: #3C1053; color: white; padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: 500; }'
    $HTML += '.system-info { display: flex; gap: 24px; margin-top: 8px; }'
    $HTML += '.info-item { font-size: 12px; color: #64748b; }'
    
    # Container and layout
    $HTML += '.container { max-width: 1400px; margin: 0 auto; padding: 32px; }'
    $HTML += '.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 32px; margin-bottom: 32px; }'
    $HTML += '.chart-section { display: grid; gap: 24px; }'
    $HTML += '.sidebar-section { display: grid; gap: 24px; }'
    
    # Card styles
    $HTML += '.card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 24px; }'
    $HTML += '.card-header { display: flex; justify-content: between; align-items: center; margin-bottom: 20px; }'
    $HTML += '.card-title { font-size: 18px; font-weight: 600; color: #1e293b; margin: 0; }'
    $HTML += '.card-subtitle { font-size: 14px; color: #64748b; margin: 4px 0 0 0; }'
    
    # Stats cards
    $HTML += '.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }'
    $HTML += '.stat-card { background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 20px; text-align: center; }'
    $HTML += '.stat-number { font-size: 32px; font-weight: 700; margin-bottom: 4px; }'
    $HTML += '.stat-label { font-size: 14px; color: #64748b; }'
    $HTML += '.stat-success { color: #059669; }'
    $HTML += '.stat-error { color: #dc2626; }'
    $HTML += '.stat-warning { color: #d97706; }'
    $HTML += '.stat-info { color: #3C1053; }'
    
    # Progress bars
    $HTML += '.progress-section { }'
    $HTML += '.progress-item { margin-bottom: 16px; }'
    $HTML += '.progress-header { display: flex; justify-content: space-between; margin-bottom: 8px; }'
    $HTML += '.progress-label { font-size: 14px; font-weight: 500; color: #374151; }'
    $HTML += '.progress-value { font-size: 14px; font-weight: 600; }'
    $HTML += '.progress-bar { width: 100%; height: 8px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }'
    $HTML += '.progress-fill { height: 100%; border-radius: 4px; transition: width 1s ease; }'
    $HTML += '.progress-success { background: #059669; }'
    $HTML += '.progress-error { background: #dc2626; }'
    $HTML += '.progress-warning { background: #d97706; }'
    
    # Gauge chart
    $HTML += '.gauge-container { text-align: center; padding: 20px; }'
    $HTML += '.gauge { width: 240px; height: 140px; margin: 0 auto 16px; position: relative; }'
    $HTML += '.gauge svg { width: 100%; height: 100%; overflow: visible; }'
    $HTML += '.gauge-bg { fill: none; stroke: #e2e8f0; stroke-width: 16; }'
    $HTML += '.gauge-progress { fill: none; stroke: #3C1053; stroke-width: 16; stroke-linecap: round; transition: stroke-dashoffset 1s ease; }'
    $HTML += '.gauge-text { font-size: 24px; font-weight: 700; color: #1e293b; }'
    $HTML += '.gauge-label { font-size: 14px; color: #64748b; }'
    
    # Component list
    $HTML += '.components-list { }'
    $HTML += '.component-item { display: flex; align-items: center; padding: 12px 0; border-bottom: 1px solid #f1f5f9; }'
    $HTML += '.component-item:last-child { border-bottom: none; }'
    $HTML += '.component-status { width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; }'
    $HTML += '.status-success { background: #059669; }'
    $HTML += '.status-error { background: #dc2626; }'
    $HTML += '.status-warning { background: #d97706; }'
    $HTML += '.component-name { flex: 1; font-size: 14px; font-weight: 500; color: #374151; }'
    $HTML += '.component-result { font-size: 12px; color: #64748b; }'
    
    # Horizontal bar chart
    $HTML += '.chart-container { margin-top: 20px; }'
    $HTML += '.chart-bar-item { margin-bottom: 12px; }'
    $HTML += '.chart-bar-header { display: flex; justify-content: space-between; margin-bottom: 4px; }'
    $HTML += '.chart-bar-label { font-size: 14px; color: #374151; }'
    $HTML += '.chart-bar-value { font-size: 14px; font-weight: 600; color: #1e293b; }'
    $HTML += '.chart-bar { width: 100%; height: 6px; background: #f1f5f9; border-radius: 3px; overflow: hidden; }'
    $HTML += '.chart-bar-fill { height: 100%; border-radius: 3px; }'
    
    # List with numbers
    $HTML += '.numbered-list { }'
    $HTML += '.list-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; }'
    $HTML += '.list-name { font-size: 14px; color: #374151; }'
    $HTML += '.list-number { font-size: 14px; font-weight: 600; color: #1e293b; }'
    
    $HTML += '</style>'
    $HTML += '</head>'
    $HTML += '<body>'
    
    # Header
    $HTML += '<div class="header">'
    $HTML += '<div class="header-left">'
    $HTML += '<div class="logo">C</div>'
    $HTML += '<div>'
    $HTML += '<div class="header-title">Citrix Installation Dashboard</div>'
    $HTML += '<div class="header-subtitle">Platform deployment analytics and monitoring</div>'
    $HTML += '<div class="system-info">'
    $HTML += "<span class='info-item'>Computer: $ComputerName</span>"
    $HTML += "<span class='info-item'>User: $UserName</span>"
    $HTML += "<span class='info-item'>Generated: $ReportTime</span>"
    $HTML += "<span class='info-item'>OS: $OSCaption</span>"
    $HTML += "<span class='info-item'>Memory: $TotalMemoryGB GB</span>"
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += "<div class='stage-badge'>STAGE $Stage</div>"
    $HTML += '</div>'
    
    # Main container
    $HTML += '<div class="container">'
    
    # Stats cards
    $HTML += '<div class="stats-grid">'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-success'>$SuccessfulComponents</div>"
    $HTML += '<div class="stat-label">Successful</div>'
    $HTML += '</div>'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-error'>$FailedComponents</div>"
    $HTML += '<div class="stat-label">Failed</div>'
    $HTML += '</div>'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-warning'>$SkippedComponents</div>"
    $HTML += '<div class="stat-label">Skipped</div>'
    $HTML += '</div>'
    $HTML += '<div class="stat-card">'
    $HTML += "<div class='stat-number stat-info'>${SuccessRate}%</div>"
    $HTML += '<div class="stat-label">Success Rate</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Dashboard grid
    $HTML += '<div class="dashboard-grid">'
    
    # Left section - Progress bars
    $HTML += '<div class="chart-section">'
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div>'
    $HTML += '<div class="card-title">Component Installation Progress</div>'
    $HTML += '<div class="card-subtitle">Real-time installation status by component</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '<div class="progress-section">'
    
    # Generate progress bars for each component
    foreach ($ComponentName in $InstallResults.Keys) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            $progressClass = "progress-warning"
            $progressValue = 50
            $statusText = "In Progress"
            
            if ($Result.Success -eq $true) {
                $progressClass = "progress-success"
                $progressValue = 100
                $statusText = "Completed"
            } elseif ($Result.Skipped -eq $true) {
                $progressClass = "progress-warning"
                $progressValue = 0
                $statusText = "Skipped"
            } else {
                $progressClass = "progress-error"
                $progressValue = 25
                $statusText = "Failed"
            }
            
            $HTML += '<div class="progress-item">'
            $HTML += '<div class="progress-header">'
            $HTML += "<div class='progress-label'>$ComponentName</div>"
            $HTML += "<div class='progress-value'>$statusText</div>"
            $HTML += '</div>'
            $HTML += '<div class="progress-bar">'
            $HTML += "<div class='progress-fill $progressClass' style='width: ${progressValue}%;'></div>"
            $HTML += '</div>'
            $HTML += '</div>'
        }
    }
    
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Right section - Gauge and components
    $HTML += '<div class="sidebar-section">'
    
    # Success rate gauge
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div class="card-title">Overall Success Rate</div>'
    $HTML += '</div>'
    $HTML += '<div class="gauge-container">'
    $HTML += '<div class="gauge">'
    $circumference = 188.4 # Half circle circumference for radius 60
    $gaugeOffset = $circumference - ($circumference * $SuccessRate / 100)
    $HTML += '<svg viewBox="0 0 140 80">'
    $HTML += '<path class="gauge-bg" d="M 20 70 A 50 50 0 0 1 120 70" stroke-dasharray="157" stroke-dashoffset="0"></path>'
    $HTML += "<path class='gauge-progress' d='M 20 70 A 50 50 0 0 1 120 70' stroke-dasharray='157' stroke-dashoffset='$([math]::Round(157 - (157 * $SuccessRate / 100), 1))'></path>"
    $HTML += '</svg>'
    $HTML += '</div>'
    $HTML += "<div class='gauge-text'>${SuccessRate}%</div>"
    $HTML += '<div class="gauge-label">Installation Success</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    # Top components list
    $HTML += '<div class="card">'
    $HTML += '<div class="card-header">'
    $HTML += '<div class="card-title">Installation Components</div>'
    $HTML += '</div>'
    $HTML += '<div class="components-list">'
    
    foreach ($ComponentName in $InstallResults.Keys) {
        $Result = $InstallResults[$ComponentName]
        if ($Result -is [hashtable]) {
            $statusClass = "status-warning"
            $resultText = "Unknown"
            
            if ($Result.Success -eq $true) {
                $statusClass = "status-success"
                $resultText = "Success"
            } elseif ($Result.Skipped -eq $true) {
                $statusClass = "status-warning"
                $resultText = "Skipped"
            } else {
                $statusClass = "status-error"
                $resultText = "Failed"
            }
            
            $HTML += '<div class="component-item">'
            $HTML += "<div class='component-status $statusClass'></div>"
            $HTML += "<div class='component-name'>$ComponentName</div>"
            $HTML += "<div class='component-result'>$resultText</div>"
            $HTML += '</div>'
        }
    }
    
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    $HTML += '</div>'
    
    $HTML += '</div>' # Close container
    $HTML += '</body>'
    $HTML += '</html>'
    
    # Write HTML file
    try {
        $ReportFileName = "CitrixReport_Stage${Stage}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $ReportPath = Join-Path (Get-Location).Path $ReportFileName
        
        # Create file and write HTML content
        $HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
        
        # Verify file was created
        if (Test-Path $ReportPath) {
            Write-Host "HTML report generated: $ReportPath" -ForegroundColor Green
        } else {
            throw "File was not created at $ReportPath"
        }
        
        if ($OpenInBrowser) {
            try {
                # Use full file path with file:// protocol for Edge
                $FullPath = (Resolve-Path $ReportPath).Path
                $FileUrl = "file:///$($FullPath -replace '\\', '/')"
                
                Start-Process "msedge.exe" -ArgumentList $FileUrl -ErrorAction SilentlyContinue
                if ($?) {
                    Write-Host "Report opened in Microsoft Edge" -ForegroundColor Green
                } else {
                    # Fallback to default browser with full path
                    Start-Process $FullPath
                    Write-Host "Report opened in default browser" -ForegroundColor Green
                }
            } catch {
                Write-Host "Could not automatically open browser. Report saved to: $ReportPath" -ForegroundColor Yellow
            }
        }
        
        return $ReportPath
    } catch {
        Write-Error "Failed to generate HTML report: $($_.Exception.Message)"
        return $null
    }
}

# Function is ready to be dot-sourced by other scripts