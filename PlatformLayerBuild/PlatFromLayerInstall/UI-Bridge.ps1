# UI to PowerShell Bridge Script
# This script creates a web server that bridges the HTML/JS UI to the PowerShell installation script

# Set execution policy to Unrestricted for this script
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

Add-Type -AssemblyName System.Web

# Import the main platform layer installation script
$scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "PlatformLayerInstall.ps1"
. $scriptPath

# Create a simple HTTP server to handle requests from the UI
function Start-UIBridgeServer {
    param (
        [int]$Port = 8080,
        [string]$HtmlPath = (Join-Path -Path $PSScriptRoot -ChildPath "PlatformLayerUI.html")
    )
    
    # Create a listener on the specified port
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Start()
    
    Write-Host "Platform Layer Installation UI server started at http://localhost:$Port/"
    Write-Host "Press Ctrl+C to stop the server."
    
    try {
        while ($listener.IsListening) {
            # Wait for a request
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            # Get the requested URL
            $requestUrl = $request.Url.LocalPath
            
            # Check if it's an API call or a file request
            if ($requestUrl -eq "/api/execute") {
                # Handle API calls
                HandleApiRequest -Request $request -Response $response
            }
            elseif ($requestUrl -eq "/") {
                # Serve the main HTML page
                ServeFile -Path $HtmlPath -Response $response
            }
            elseif ($requestUrl -eq "/api/status") {
                # Return the current status
                HandleStatusRequest -Response $response
            }
            else {
                # Serve static files (CSS, JS, etc.)
                $filePath = Join-Path -Path $PSScriptRoot -ChildPath $requestUrl.TrimStart("/")
                if (Test-Path $filePath) {
                    ServeFile -Path $filePath -Response $response
                }
                else {
                    # Return 404 Not Found
                    $response.StatusCode = 404
                    $response.Close()
                }
            }
        }
    }
    finally {
        # Stop the listener
        $listener.Stop()
    }
}

# Function to serve a file
function ServeFile {
    param (
        [string]$Path,
        [System.Net.HttpListenerResponse]$Response
    )
    
    try {
        $content = [System.IO.File]::ReadAllBytes($Path)
        $Response.ContentLength64 = $content.Length
        
        # Set content type based on file extension
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        switch ($extension) {
            ".html" { $Response.ContentType = "text/html" }
            ".js" { $Response.ContentType = "application/javascript" }
            ".css" { $Response.ContentType = "text/css" }
            ".jpg" { $Response.ContentType = "image/jpeg" }
            ".png" { $Response.ContentType = "image/png" }
            ".svg" { $Response.ContentType = "image/svg+xml" }
            default { $Response.ContentType = "application/octet-stream" }
        }
        
        $Response.OutputStream.Write($content, 0, $content.Length)
    }
    catch {
        # Handle file access errors
        $Response.StatusCode = 500
    }
    finally {
        $Response.Close()
    }
}

# Global variable to store task status
$Global:TaskStatus = @{
    CurrentStage = "Pre-Install"
    CompletedTasks = 0
    PendingTasks = 18
    ErrorTasks = 0
    TaskResults = @{}
    LastLogMessage = ""
    InProgress = $false
}

# Path to the log file on the user's desktop
$Global:LogFilePath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "PlatformLayerInstall.log")

# Handle API requests from the UI
function HandleApiRequest {
    param (
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    
    try {
        # Read the request body
        $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
        $requestBody = $reader.ReadToEnd()
        $data = ConvertFrom-Json -InputObject $requestBody
        
        $Response.ContentType = "application/json"
        
        # Process the task
        $result = ExecuteTask -TaskId $data.taskId -TaskData $data
        
        # Convert result to JSON and send it back
        $jsonResult = ConvertTo-Json -InputObject $result -Depth 10
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonResult)
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        # Handle errors
        $errorResponse = @{
            success = $false
            message = "Error processing request: $_"
        }
        $jsonError = ConvertTo-Json -InputObject $errorResponse
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonError)
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        $Response.Close()
    }
}

# Handle status requests from the UI
function HandleStatusRequest {
    param (
        [System.Net.HttpListenerResponse]$Response
    )
    
    try {
        $Response.ContentType = "application/json"
        
        # Convert status to JSON and send it back
        $jsonStatus = ConvertTo-Json -InputObject $Global:TaskStatus -Depth 10
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonStatus)
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        # Handle errors
        $errorResponse = @{
            success = $false
            message = "Error getting status: $_"
        }
        $jsonError = ConvertTo-Json -InputObject $errorResponse
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonError)
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        $Response.Close()
    }
}

# Custom log function to capture and relay logs to the UI
function Write-UILog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [int]$TaskId = 0
    )
    
    # Call the original Write-Log function to maintain file logging
    Write-Log -Message $Message -Level $Level
    
    # Update last log message for UI
    $Global:TaskStatus.LastLogMessage = @{
        timestamp = Get-Date -Format "HH:mm:ss"
        message = $Message
        level = $Level.ToLower()
        taskId = $TaskId
    }
    
    # Also output to console for monitoring
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $consoleMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with colors
    switch ($Level) {
        "INFO" { Write-Host $consoleMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $consoleMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $consoleMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $consoleMessage -ForegroundColor Green }
    }
}

# Execute a specific task from the UI
function ExecuteTask {
    param (
        [int]$TaskId,
        [PSCustomObject]$TaskData
    )
    
    # Mark as in progress
    $Global:TaskStatus.InProgress = $true
    
    # Define the result object
    $result = @{
        success = $false
        message = ""
        taskId = $TaskId
        logs = @()
    }
    
    try {
        # Override the Write-Log function to capture logs
        New-Item -Path Function:\Original-Write-Log -Value (Get-Item Function:\Write-Log).ScriptBlock
        New-Item -Path Function:\Write-Log -Value ${function:Write-UILog} -Force
        
        # Map task ID to appropriate function
        switch ($TaskId) {
            # Pre-Install Tasks
            1 { 
                $networkPath = $TaskData.networkPath
                $result.success = Map-DriveAndCopyInstallers -networkPath $networkPath
                $result.message = "Drive mapping and installer copy completed"
            }
            2 { 
                $result.success = Check-DriveD
                $result.message = "D: drive check completed"
            }
            
            # Stage 1 Tasks
            3 { 
                $installerPath = $TaskData.installerPath
                $includeVdaPlugins = $TaskData.vdaPlugins
                $includeProfileManagement = $TaskData.profileMgmt
                $controllers = $TaskData.controllers
                $enableHdxPorts = [bool]$TaskData.enableHdxPorts
                $enableRealTimeTransport = [bool]$TaskData.enableRealTimeTransport
                $enableRemoteAssistance = [bool]$TaskData.enableRemoteAssistance
                
                $result.success = Install-CitrixVDA -installerPath $installerPath `
                                                    -includeVdaPlugins $includeVdaPlugins `
                                                    -includeProfileManagement $includeProfileManagement `
                                                    -controllers $controllers `
                                                    -enableHdxPorts:$enableHdxPorts `
                                                    -enableRealTimeTransport:$enableRealTimeTransport `
                                                    -enableRemoteAssistance:$enableRemoteAssistance
                $result.message = "Citrix VDA installation completed"
            }
            4 { 
                $installerPath = $TaskData.pvsPath
                $targetDeviceType = $TaskData.targetDeviceType
                $baseImage = [bool]$TaskData.baseImage
                $requirePvsClient = [bool]$TaskData.requirePvsClient
                $addFireKeeper = [bool]$TaskData.addFireKeeper
                
                $result.success = Install-CitrixPVS -installerPath $installerPath `
                                                   -targetDeviceType $targetDeviceType `
                                                   -baseImage:$baseImage `
                                                   -requirePvsClient:$requirePvsClient `
                                                   -addFireKeeper:$addFireKeeper
                $result.message = "Citrix PVS installation completed"
            }
            5 { 
                $installerPath = $TaskData.wemPath
                $configPort = $TaskData.configPort
                $servicePort = $TaskData.servicePort
                $brokerService = $TaskData.brokerService
                
                $result.success = Install-CitrixWEM -installerPath $installerPath `
                                                   -configPort $configPort `
                                                   -servicePort $servicePort `
                                                   -brokerService $brokerService
                $result.message = "Citrix WEM Agent installation completed"
            }
            6 { 
                $installerPath = $TaskData.uberPath
                $splunkServer = $TaskData.splunkServer
                $splunkToken = $TaskData.splunkToken
                
                $result.success = Install-UberAgent -installerPath $installerPath `
                                                   -splunkServer $splunkServer `
                                                   -splunkToken $splunkToken
                $result.message = "UberAgent installation completed"
            }
            7 { 
                $optimizerPath = $TaskData.optimizerPath
                $result.success = Run-CitrixOptimizer -optimizerPath $optimizerPath
                $result.message = "Citrix Optimizer completed"
            }
            8 { 
                $result.success = Run-KmsRearm
                $result.message = "KMS Licensing Rearm completed"
            }
            9 { 
                $result.success = Remove-GhostDevices
                $result.message = "Ghost Devices removal completed"
            }
            10 { 
                $pageFileSize = $TaskData.pageFileSize
                $result.success = Move-PageFile -pageFileSize $pageFileSize
                $result.message = "Page File moved to D: drive"
            }
            11 { 
                $result.success = Redirect-EventLogs
                $result.message = "Event Logs redirected to D:\EventLogs"
            }
            12 { 
                $scriptSourcePath = $TaskData.scriptSource
                $scriptDestPath = $TaskData.scriptDest
                $result.success = Copy-LoginScriptFiles -scriptSourcePath $scriptSourcePath -scriptDestPath $scriptDestPath
                $result.message = "Login Script Files copied"
            }
            13 { 
                $domain = $TaskData.domainName
                $user = $TaskData.domainUser
                $password = $TaskData.domainPassword
                $result.success = Join-DomainFunc -domain $domain -user $user -password $password
                $result.message = "Domain join completed"
            }
            
            # Stage 2 Tasks
            14 { 
                $result.success = Clear-EventLogsFunc
                $result.message = "Event Logs cleared"
            }
            15 { 
                $result.success = Clear-TempFiles
                $result.message = "Temp Files cleared"
            }
            16 { 
                $result.success = Empty-RecycleBin
                $result.message = "Recycle Bin emptied"
            }
            17 { 
                $result.success = Run-NgenOptimization
                $result.message = "NGEN Optimization completed"
            }
            18 { 
                $result.success = Finalize-AppLayer
                $result.message = "App Layer finalized"
            }
            
            # Special commands
            "reboot" {
                Write-UILog -Message "System will reboot in 10 seconds..." -Level "WARNING" -TaskId 0
                Start-Sleep -Seconds 5
                Write-UILog -Message "Initiating system reboot..." -Level "WARNING" -TaskId 0
                # Schedule reboot after a short delay to allow response to be sent
                Start-Job -ScriptBlock { Start-Sleep -Seconds 5; Restart-Computer -Force } | Out-Null
                $result.success = $true
                $result.message = "Reboot initiated"
            }
            default {
                $result.success = $false
                $result.message = "Unknown task ID: $TaskId"
            }
        }
        
        # Update task status
        if ($result.success) {
            $Global:TaskStatus.CompletedTasks++
            $Global:TaskStatus.PendingTasks--
        }
        else {
            $Global:TaskStatus.ErrorTasks++
            $Global:TaskStatus.PendingTasks--
        }
        
        # Update stage if needed
        if ($TaskId -ge 3 -and $TaskId -le 13) {
            $Global:TaskStatus.CurrentStage = "Install Stage 1"
        }
        elseif ($TaskId -ge 14) {
            $Global:TaskStatus.CurrentStage = "Stage 2"
        }
        
        # Store task result
        $Global:TaskStatus.TaskResults[$TaskId] = $result.success
    }
    catch {
        $result.success = $false
        $result.message = "Error executing task: $_"
        $Global:TaskStatus.ErrorTasks++
        $Global:TaskStatus.PendingTasks--
    }
    finally {
        # Restore original Write-Log function
        if (Get-Item Function:\Original-Write-Log -ErrorAction SilentlyContinue) {
            New-Item -Path Function:\Write-Log -Value (Get-Item Function:\Original-Write-Log).ScriptBlock -Force
            Remove-Item Function:\Original-Write-Log
        }
        
        # Mark as not in progress
        $Global:TaskStatus.InProgress = $false
    }
    
    return $result
}

# Start multiple stage execution
function Start-StageExecution {
    param (
        [ValidateSet("PreInstall", "Stage1", "Stage2")]
        [string]$Stage,
        [hashtable]$Settings
    )
    
    switch ($Stage) {
        "PreInstall" {
            # Execute Pre-Install tasks in sequence
            $result1 = ExecuteTask -TaskId 1 -TaskData $Settings
            if ($result1.success) {
                $result2 = ExecuteTask -TaskId 2 -TaskData $Settings
                return $result2.success
            }
            return $false
        }
        "Stage1" {
            # Execute Stage 1 tasks in sequence
            # This would be a long chain of task executions
            # Simplified for brevity
            return $false
        }
        "Stage2" {
            # Execute Stage 2 tasks in sequence
            # This would be a long chain of task executions
            # Simplified for brevity
            return $false
        }
    }
    
    return $false
}

# Add JavaScript to update the HTML UI based on PowerShell script output
function Update-JavaScriptForUI {
    param (
        [string]$HtmlPath
    )
    
    # Read the HTML file
    $htmlContent = Get-Content -Path $HtmlPath -Raw
    
    # Append JavaScript to connect to our PowerShell bridge
    $bridgeScript = @"
<script>
    // Function to call the PowerShell bridge API
    async function executePowerShellTask(taskId, settings = {}) {
        try {
            const response = await fetch('/api/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    taskId: taskId,
                    ...settings
                }),
            });
            
            return await response.json();
        } catch (error) {
            console.error('Error executing PowerShell task:', error);
            return { success: false, message: 'Network error: ' + error.message };
        }
    }
    
    // Function to poll status from the PowerShell bridge
    async function pollStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            // Update UI with status
            document.getElementById('completed-tasks').textContent = status.CompletedTasks;
            document.getElementById('pending-tasks').textContent = status.PendingTasks;
            document.getElementById('error-tasks').textContent = status.ErrorTasks;
            document.getElementById('stage-status').textContent = status.CurrentStage;
            
            // Process log message if available
            if (status.LastLogMessage && status.LastLogMessage.taskId > 0) {
                logToTask(status.LastLogMessage.taskId, status.LastLogMessage.message, status.LastLogMessage.level);
            }
        } catch (error) {
            console.error('Error polling status:', error);
        }
        
        // Continue polling
        setTimeout(pollStatus, 1000);
    }
    
    // Start polling when page loads
    document.addEventListener('DOMContentLoaded', function() {
        pollStatus();
        
        // Override the simulation functions to use PowerShell
        window.startPreInstallTasks = async function() {
            document.getElementById('stage-status').textContent = 'Pre-Install';
            
            const networkPath = document.getElementById('network-path').value;
            
            const task1Result = await executePowerShellTask(1, { 
                networkPath: networkPath 
            });
            
            if (task1Result.success) {
                logToTask(1, 'Task completed successfully', 'success');
                setTaskStatus(1, 'completed');
                
                const task2Result = await executePowerShellTask(2);
                if (task2Result.success) {
                    logToTask(2, 'D: drive detected', 'success');
                    setTaskStatus(2, 'completed');
                    
                    // Enable Stage 1 button
                    stage1StartBtn.disabled = false;
                    stage1StartBtn.classList.remove('btn-disabled');
                    stage1StartBtn.classList.add('btn-primary');
                } else {
                    logToTask(2, 'D: drive not detected. User action required.', 'error');
                    setTaskStatus(2, 'error');
                    dDriveModal.classList.add('show');
                }
            } else {
                logToTask(1, 'Failed to map drive and copy installers', 'error');
                setTaskStatus(1, 'error');
            }
            
            updateTaskCounters();
        };
        
        window.startStage1Tasks = async function() {
            document.getElementById('stage-status').textContent = 'Install Stage 1';
            
            // Task 3: Install Citrix VDA
            const vdaPath = document.getElementById('vda-path').value;
            const vdaPlugins = document.getElementById('vda-plugins').checked;
            const profileMgmt = document.getElementById('profile-mgmt').checked;
            
            const task3Result = await executePowerShellTask(3, {
                installerPath: vdaPath,
                vdaPlugins: vdaPlugins, 
                profileMgmt: profileMgmt
            });
            
            processTaskResult(3, task3Result, async function() {
                
                // Task 4: Install Citrix PVS
                const pvsPath = document.getElementById('pvs-path').value;
                const pvsOptions = document.getElementById('pvs-options').value;
                
                const task4Result = await executePowerShellTask(4, { 
                    pvsPath: pvsPath,
                    commandLineOptions: pvsOptions
                });
                
                processTaskResult(4, task4Result, async function() {
                    
                    // Task 5: Install Citrix WEM Agent
                    const wemPath = document.getElementById('wem-path').value;
                    const task5Result = await executePowerShellTask(5, { wemPath: wemPath });
                    
                    processTaskResult(5, task5Result, async function() {
                        
                        // Task 6: Install UberAgent
                        const uberPath = document.getElementById('uber-path').value;
                        const task6Result = await executePowerShellTask(6, { uberPath: uberPath });
                        
                        processTaskResult(6, task6Result, async function() {
                            
                            // Task 7: Run Citrix Optimizer
                            const optimizerPath = document.getElementById('optimizer-path').value;
                            const task7Result = await executePowerShellTask(7, { optimizerPath: optimizerPath });
                            
                            processTaskResult(7, task7Result, async function() {
                                
                                // Task 8: Run KMS Licensing Rearm
                                const task8Result = await executePowerShellTask(8);
                                
                                processTaskResult(8, task8Result, async function() {
                                    
                                    // Task 9: Remove Ghost Devices
                                    const task9Result = await executePowerShellTask(9);
                                    
                                    processTaskResult(9, task9Result, async function() {
                                        
                                        // Task 10: Move Page File to D: Drive
                                        const pageFileSize = document.getElementById('pagefile-size').value;
                                        const task10Result = await executePowerShellTask(10, { pageFileSize: pageFileSize });
                                        
                                        processTaskResult(10, task10Result, async function() {
                                            
                                            // Task 11: Redirect Event Logs
                                            const task11Result = await executePowerShellTask(11);
                                            
                                            processTaskResult(11, task11Result, async function() {
                                                
                                                // Task 12: Copy Login Script Files
                                                const scriptSource = document.getElementById('script-source').value;
                                                const scriptDest = document.getElementById('script-dest').value;
                                                const task12Result = await executePowerShellTask(12, { 
                                                    scriptSource: scriptSource,
                                                    scriptDest: scriptDest
                                                });
                                                
                                                processTaskResult(12, task12Result, async function() {
                                                    
                                                    // Task 13: Join Domain
                                                    const domainName = document.getElementById('domain-name').value;
                                                    const domainUser = document.getElementById('domain-user').value;
                                                    const domainPassword = document.getElementById('domain-password').value;
                                                    const task13Result = await executePowerShellTask(13, {
                                                        domainName: domainName,
                                                        domainUser: domainUser,
                                                        domainPassword: domainPassword
                                                    });
                                                    
                                                    processTaskResult(13, task13Result, function() {
                                                        rebootModal.classList.add('show');
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        };
        
        window.startStage2Tasks = async function() {
            document.getElementById('stage-status').textContent = 'Stage 2';
            
            // Task 14: Clear Event Logs
            const task14Result = await executePowerShellTask(14);
            
            processTaskResult(14, task14Result, async function() {
                
                // Task 15: Clear Temp Files
                const task15Result = await executePowerShellTask(15);
                
                processTaskResult(15, task15Result, async function() {
                    
                    // Task 16: Empty Recycle Bin
                    const task16Result = await executePowerShellTask(16);
                    
                    processTaskResult(16, task16Result, async function() {
                        
                        // Task 17: Run NGEN Optimization
                        const task17Result = await executePowerShellTask(17);
                        
                        processTaskResult(17, task17Result, async function() {
                            
                            // Task 18: Finalize App Layer
                            const task18Result = await executePowerShellTask(18);
                            
                            processTaskResult(18, task18Result, function() {
                                completionModal.classList.add('show');
                            });
                        });
                    });
                });
            });
        };
        
        // Helper function to process task results
        function processTaskResult(taskId, result, callback) {
            if (result.success) {
                setTaskStatus(taskId, 'completed');
                logToTask(taskId, result.message, 'success');
                if (callback) setTimeout(callback, 500);
            } else {
                setTaskStatus(taskId, 'error');
                logToTask(taskId, 'Error: ' + result.message, 'error');
            }
            updateTaskCounters();
        }
        
        // Reboot action
        document.getElementById('reboot-now').addEventListener('click', async function() {
            const rebootResult = await executePowerShellTask('reboot');
            if (rebootResult.success) {
                logToTask(0, 'System reboot initiated', 'warning');
                rebootModal.classList.remove('show');
            } else {
                logToTask(0, 'Failed to initiate reboot: ' + rebootResult.message, 'error');
            }
        });
    });
</script>
"@
    
    # Append the bridge script to the HTML file before the closing </body> tag
    $htmlContent = $htmlContent -replace '</body>', "$bridgeScript`n</body>"
    
    # Write the modified HTML file
    Set-Content -Path $HtmlPath -Value $htmlContent
}

# Main execution
Export-ModuleMember -Function Start-UIBridgeServer, Update-JavaScriptForUI
