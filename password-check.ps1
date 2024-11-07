<#
.SYNOPSIS
Checks if a password has been exposed in known data breaches.

.DESCRIPTION
This script checks if a given password has been exposed in known data breaches using the Have I Been Pwned API.
If no password is provided via parameter, the script will prompt securely for the password.

.PARAMETER Password
The password to check. If not provided, the script will prompt for it securely.

.EXAMPLE
.\check-password.ps1 -Password "MySecurePassword123"
Checks if "MySecurePassword123" has been exposed in known data breaches.

.EXAMPLE
.\check-password.ps1
Prompts securely for a password and checks if it has been exposed in known data breaches.

.NOTES
Author: Viorel Ciucu
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true)]
    [string]$Password
)

function Get-Usage {
    Write-Output "Usage: .\check-password.ps1 [-Password <string>]"
    Write-Output "Checks if a password has been exposed in known data breaches"
    Write-Output ""
    Write-Output "If no password is provided via parameter, script will prompt securely"
    exit 1
}

# If no password provided, prompt securely
if (-not $Password) {
    $SecurePassword = Read-Host -Prompt "Enter password to check" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

# Validate input
if ([string]::IsNullOrWhiteSpace($Password)) {
    Write-Error "Error: Password cannot be empty"
    exit 1
}

try {
    # Calculate SHA1 hash
    $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $HashBytes = $SHA1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
    $Hash = [System.BitConverter]::ToString($HashBytes).Replace("-", "")

    # Clear password from memory
    $Password = $null
    [System.GC]::Collect()

    # Split hash into prefix and suffix
    $Prefix = $Hash.Substring(0, 5)
    $Suffix = $Hash.Substring(5)

    # Set up web request
    $Uri = "https://api.pwnedpasswords.com/range/$Prefix"

    # Make request with retry logic
    $MaxRetries = 3
    $RetryCount = 0
    $Success = $false

    while (-not $Success -and $RetryCount -lt $MaxRetries) {
        try {
            $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop
            $Success = $true
        }
        catch {
            $RetryCount++
            if ($RetryCount -eq $MaxRetries) {
                Write-Error "Error: Failed to connect to HaveIBeenPwned API after $MaxRetries attempts"
                exit 1
            }
            Start-Sleep -Seconds 2
        }
    }

    # Process the response
    $Hashes = $Response -split '\r?\n'
    $Found = $false
    $Count = 0

    foreach ($Line in $Hashes) {
        $HashSuffix = ($Line -split ':')[0]
        if ($HashSuffix -eq $Suffix) {
            $Found = $true
            $Count = [int]($Line -split ':')[1]
            break
        }
    }

    # Output results
    if ($Found) {
        Write-Warning "This password has been exposed in data breaches!"
        Write-Output "It appears $Count times in known breaches."
        Write-Output "Recommendation: Please choose a different password."
        exit 1
    }
    else {
        Write-Output "Password not found in known data breaches."
        Write-Output "Note: This doesn't guarantee the password is secure, just that it hasn't been exposed in known breaches."
        exit 0
    }
}
catch {
    Write-Error "An unexpected error occurred: $_"
    exit 1
}
finally {
    # Ensure sensitive data is cleared
    if ($SecurePassword) {
        $SecurePassword.Dispose()
    }
    $SHA1.Dispose()
}
