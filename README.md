# Get-EDRDeviceState

Checks the Microsoft Defender Antivirus EDR state

## Getting started

Copy this script down and save it to a local directory and run the following command: Import-Module Get-EDRDeviceState.ps1

## Examples

- EXAMPLE 1: Get-EDRDeviceState -DisableProgressBar

    This will disable the progress bar in the UI

- EXAMPLE 2: Get-EDRDeviceState -ComputerName MachineOne, MachineTwo

    This will query for both MachineOne and MachineTwo

- EXAMPLE 3: Get-EDRDeviceState -Verbose

    This will run the script in verbose mode

- EXAMPLE 4: Get-EDRDeviceState -ShowBlockMode

    Display search results to the console with only machine name and EDR block status

- EXAMPLE 5: Get-EDRDeviceState -CheckServices

    Query the run state of the diagtrack and sense service

- EXAMPLE 6: Get-EDRDeviceState -SaveResults

    Query for EDR information and save results to disk
