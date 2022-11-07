function Get-EDRDeviceState {
    <#
    .SYNOPSIS
        Find Microsoft Defender Antivirus EDR state

    .DESCRIPTION
        Check to see if a device is running in EDR or passive mode

    .PARAMETER ComputerName
        Name of computer or computers you want to query

    .PARAMETER CheckServices
        Check diagtrack and sense services

    .PARAMETER DisableProgressBar
        Disables the progress bar

    .PARAMETER LoggingPath
        Parameter description

    .PARAMETER FailureLoggingPath
        Log file path

    .PARAMETER SaveResults
        Save results to file

    .PARAMETER ShowBlockMode
        Show only EDR Block mode results

    .PARAMETER ShowEngineVersions
        Show only engine version information

    .PARAMETER ShowSignatureResults
        Show signature information

    .EXAMPLE
		Get-EDRDeviceState -DisableProgressBar

		This will disable the progress bar in the UI

    .EXAMPLE
		Get-EDRDeviceState -ComputerName MachineOne, MachineTwo

		This will query for both MachineOne and MachineTwo

	.EXAMPLE
		Get-EDRDeviceState -Verbose

		This will run the script in verbose mode

    .EXAMPLE
		Get-EDRDeviceState -ShowBlockMode

		Display search results to the console with only machine name and EDR block status

    .EXAMPLE
		Get-EDRDeviceState -CheckServices

		Query the run state of the diagtrack and sense service

    .EXAMPLE
		Get-EDRDeviceState -SaveResults

		Query for EDR information and save results to disk

	.NOTES
		Data is saved to the $env:Temp location of the user that executed the script
        For more information: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-onboarding?view=o365-worldwide
    #>

    [CmdletBinding()]
    [OutputType('System.String')]
    [OutputType('System.IO.File')]
    [Alias('CheckEDR')]
    param(
        [object[]]
        $ComputerName,

        [switch]
        $CheckServices,

        [switch]
        $DisableProgressBar,

        [string]
        $LoggingPath = "$env:Temp\EDRDeviceState.csv",

        [string]
        $FailureLoggingPath = "$env:Temp\FailedConnections.csv",

        [switch]
        $SaveResults,

        [switch]
        $ShowBlockMode,

        [switch]
        $ShowEngineVersions,

        [switch]
        $ShowSignatureResults
    )

    begin {
        Write-Output "Starting EDR discovery process"
        $parameters = $PSBoundParameters
        $policyCounter = 0
        $progressCounter = 1
        $successfulConnectionsFound = 0
        $failedConnectionsFound = 0
        [System.Collections.ArrayList]$computerObjects = @()
        [System.Collections.ArrayList]$failedConnections = @()
    }

    process {
        try {
            if (-NOT ($ComputerName)) {
                Write-Verbose "No computer name passed in. Trying to retrieve full domain computer list"
                $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name -ErrorAction Stop
            }
            else {
                $computers = $ComputerName
            }
        }
        catch {
            Write-Output "Get-ADComputer needs to be run on an on-premise domain controller"
            return
        }

        try {
            foreach ($computer in $computers) {
                if (-NOT ($parameters.ContainsKey('DisableProgressBar'))) {
                    $policyCounter ++
                    Write-Progress -Activity "Querying: $computer. Total computers found: $($computers.Count)" -Status "Querying computer list #: $progressCounter" -PercentComplete ($progressCounter / $computers.count * 100)
                    $progressCounter ++
                }
                else {
                    Write-Verbose "Progress bar has been disabled"
                }

                if (-NOT ($connection = Invoke-Command -ComputerName $computer -ScriptBlock { Get-MPComputerStatus } -ErrorAction SilentlyContinue -ErrorVariable FailedConnection)) {
                    $failure = [PSCustomObject]@{
                        MachineName = $computer
                        ErrorId     = $FailedConnection.FullyQualifiedErrorId
                        Exception   = $FailedConnection.Exception.Message
                    }
                    $failedConnectionsFound ++
                    $null = $failedConnections.Add($failure)
                    return
                }
                else {
                    if ($connection.AMRunningMode -eq 'Normal') { $edrMode = 'Defender in Active Mode' } else { $edrMode = 'Defender in Passive Mode' }

                    $machineInfo = [PSCustomObject]@{
                        MachineName                     = $computer
                        'EDR Block Mode'                = $edrMode
                        AMServiceEnabled                = $connection.AMServiceEnabled
                        AntispywareEnabled              = $connection.AntispywareEnabled
                        BehaviorMonitorEnabled          = $connection.BehaviorMonitorEnabled
                        TamperProtectionSource          = $connection.TamperProtectionSource
                        AMEngineVersion                 = $connection.AMEngineVersion
                        AMProductVersion                = $connection.AMProductVersion
                        AMServiceVersion                = $connection.AMServiceVersion
                        AntispywareSignatureVersion     = $connection.AntispywareSignatureVersion
                        DefenderSignaturesOutOfDate     = $connection.DefenderSignaturesOutOfDate
                        AntispywareSignatureLastUpdated = $connection.AntispywareSignatureLastUpdated

                    }
                    $successfulConnectionsFound ++
                    $null = $computerObjects.Add($machineInfo)
                }
            }

            if ($parameters.ContainsKey('ShowBlockMode')) { $computerObjects | Select-Object MachineName, 'EDR Block Mode' | Sort-Object -Property MachineName | Format-Table }
            if ($parameters.ContainsKey('ShowEngineVersions')) { $computerObjects | Select-Object MachineName, AMServiceEnabled, AMEngineVersion, AMProductVersion, AMServiceVersion | Sort-Object -Property MachineName | Format-Table }
            if ($parameters.ContainsKey('ShowSignatureResults')) { $computerObjects | Select-Object MachineName, AntispywareSignatureVersion, AntispywareSignatureLastUpdated, DefenderSignaturesOutOfDate | Sort-Object -Property MachineName | Format-Table }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            # Service checks
            if ($parameters.ContainsKey('CheckServices')) {
                $services = @('diagtrack', 'sense')
                foreach ($service in $services) {
                    Write-Output "Checking state of $($service) service"
                    Start-Process -FilePath "C:\Windows\System32\sc.exe" -ArgumentList "qc $($service)" -NoNewWindow -RedirectStandardOutput "$env:Temp\$($service).txt" -Wait -ErrorAction SilentlyContinue
                    $scStatus = Get-Content "$env:Temp\$($service).txt"
                    if ((($scStatus -replace '\s+')[4] -split '([0-9]{1})')[2] -eq 'AUTO_START') { Write-Output "$($service) service check: GOOD" }
                    else { Write-Output "ERROR: $($service) service check: failed! Service is not set to AUTO_START. Please run: sc config $($service) start=auto" }
                }
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            if ($parameters.ContainsKey('SaveResults')) {
                [PSCustomObject]$computerObjects | Export-Csv -Path $LoggingPath -ErrorAction Stop -Encoding UTF8 -NoTypeInformation -Append
                [PSCustomObject]$failedConnections | Export-Csv -Path $FailureLoggingPath -ErrorAction Stop -Encoding UTF8 -NoTypeInformation -Append
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }
    }

    end {
        Write-Output "There were $($successfulConnectionsFound) successful connections "
        Write-Output "There were $($failedConnectionsFound) failed connections"
        if ($parameters.ContainsKey('SaveResults')) {
            Write-Output "Saving registry data to $($LoggingPath)"
            Write-Output "Saving failed connection data to $($FailureLoggingPath)"
        }
        Write-Output "EDR discovery process completed!"
    }
}
