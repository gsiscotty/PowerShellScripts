#Requires -Version 5.1
<#
.SYNOPSIS
Validates a PFX password first, then imports the certificate if valid.

.DESCRIPTION
- Prompts for a PFX source path
- Prompts securely for the password
- Validates the password using Get-PfxData
- Imports the PFX only if validation succeeds
- Shows a clearer message if the password is wrong or if the PFX is protected for a specific AD principal

.NOTES
Run this script in an elevated PowerShell session if importing to LocalMachine.
#>

[CmdletBinding()]
param()

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK]   $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg {
    param([string]$Message)
    Write-Host "[ERR]  $Message" -ForegroundColor Red
}

function Invoke-PfxImport {
    Write-Host ""
    Write-Host "PFX validation and import tool" -ForegroundColor White
    Write-Host "--------------------------------" -ForegroundColor DarkGray

    $sourcePath = Read-Host "Enter full path to the PFX file"

    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        throw "No source path was entered."
    }

    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "The file does not exist: $sourcePath"
    }

    $defaultStore = "Cert:\LocalMachine\My"
    $storeLocation = Read-Host "Enter target certificate store or press Enter for default [$defaultStore]"
    if ([string]::IsNullOrWhiteSpace($storeLocation)) {
        $storeLocation = $defaultStore
    }

    $password = Read-Host "Enter PFX password" -AsSecureString

    Write-Info "Validating PFX and password..."
    try {
        $null = Get-PfxData -FilePath $sourcePath -Password $password -ErrorAction Stop
        Write-Ok "Password validation succeeded."
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match "requires either a different password or membership in an Active Directory principal") {
            Write-ErrMsg "Validation failed."
            Write-Host "Cause: The PFX is not importable with this password alone." -ForegroundColor Red
            Write-Host "It was likely protected for a specific Active Directory principal or exported with different protection settings." -ForegroundColor Red
            exit 1
        }
        elseif ($msg -match "network password is not correct|password") {
            Write-ErrMsg "Validation failed."
            Write-Host "Cause: The password appears to be incorrect." -ForegroundColor Red
            exit 1
        }
        else {
            Write-ErrMsg "Validation failed."
            Write-Host "Cause: $msg" -ForegroundColor Red
            exit 1
        }
    }

    Write-Info "Importing certificate into $storeLocation ..."
    try {
        $result = Import-PfxCertificate -FilePath $sourcePath -CertStoreLocation $storeLocation -Password $password -ErrorAction Stop

        if ($null -ne $result) {
            Write-Ok "Import completed successfully."
            $result | Select-Object Thumbprint, Subject, FriendlyName, PSParentPath | Format-List
        }
        else {
            Write-WarnMsg "Import command returned no certificate object, but no terminating error occurred."
        }
    }
    catch {
        $msg = $_.Exception.Message

        Write-ErrMsg "Import failed."

        if ($msg -match "Access is denied|requested operation requires elevation") {
            Write-Host "Cause: PowerShell likely needs to be started as Administrator for the selected store." -ForegroundColor Red
        }
        elseif ($msg -match "requires either a different password or membership in an Active Directory principal") {
            Write-Host "Cause: The PFX appears to be protected for a specific Active Directory principal." -ForegroundColor Red
        }
        else {
            Write-Host "Cause: $msg" -ForegroundColor Red
        }

        exit 1
    }
}

function Invoke-PfxExport {
    Write-Host ""
    Write-Host "Certificate to PFX export tool" -ForegroundColor White
    Write-Host "------------------------------" -ForegroundColor DarkGray

    $defaultStore = "Cert:\LocalMachine\My"
    $storeLocation = Read-Host "Enter source certificate store or press Enter for default [$defaultStore]"
    if ([string]::IsNullOrWhiteSpace($storeLocation)) {
        $storeLocation = $defaultStore
    }

    if (-not (Test-Path -LiteralPath $storeLocation)) {
        throw "The certificate store path does not exist: $storeLocation"
    }

    $lookupValue = Read-Host "Enter certificate thumbprint (preferred) or part of subject"
    if ([string]::IsNullOrWhiteSpace($lookupValue)) {
        throw "No certificate lookup value was entered."
    }

    $lookupValue = $lookupValue.Trim()
    $thumbprintPattern = '^[A-Fa-f0-9]{40}$'
    $cert = $null

    if ($lookupValue -match $thumbprintPattern) {
        $normalizedThumbprint = $lookupValue.ToUpperInvariant()
        $cert = Get-ChildItem -Path $storeLocation -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $normalizedThumbprint } |
            Select-Object -First 1
    }
    else {
        $matches = Get-ChildItem -Path $storeLocation -ErrorAction Stop |
            Where-Object { $_.Subject -like "*$lookupValue*" }

        if (($matches | Measure-Object).Count -gt 1) {
            Write-Info "Multiple certificates matched. Showing candidates:"
            $matches | Select-Object Thumbprint, Subject, NotAfter | Format-Table -AutoSize
            throw "More than one certificate matched '$lookupValue'. Use a thumbprint to select a single certificate."
        }

        $cert = $matches | Select-Object -First 1
    }

    if ($null -eq $cert) {
        throw "No certificate was found in $storeLocation for '$lookupValue'."
    }

    if (-not $cert.HasPrivateKey) {
        throw "The selected certificate does not contain a private key and cannot be exported as PFX."
    }

    Write-Info ("Selected certificate: {0}" -f $cert.Subject)
    Write-Info ("Thumbprint: {0}" -f $cert.Thumbprint)

    $destinationPath = Read-Host "Enter full output path for the exported PFX file"
    if ([string]::IsNullOrWhiteSpace($destinationPath)) {
        throw "No destination path was entered."
    }

    if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
        $overwriteChoice = Read-Host "Output file already exists. Overwrite? (Y/N)"
        if ($overwriteChoice -notmatch '^(Y|y)$') {
            throw "Export was cancelled because overwrite was declined."
        }
    }

    $password = Read-Host "Enter password to protect the exported PFX" -AsSecureString

    Write-Info "Exporting certificate to PFX..."
    $exported = Export-PfxCertificate -Cert $cert.PSPath -FilePath $destinationPath -Password $password -ErrorAction Stop

    if ($null -eq $exported) {
        throw "Export-PfxCertificate returned no result."
    }

    # Validate the exported file immediately to confirm password protection and integrity.
    Write-Info "Validating exported PFX..."
    $null = Get-PfxData -FilePath $destinationPath -Password $password -ErrorAction Stop
    Write-Ok "Export completed and validation succeeded."
    Write-Host "Saved file: $destinationPath" -ForegroundColor Green
}

try {
    Write-Host ""
    Write-Host "PFX tool" -ForegroundColor White
    Write-Host "--------" -ForegroundColor DarkGray
    Write-Host "1) Import PFX (validate password first)" -ForegroundColor White
    Write-Host "2) Export certificate to PFX" -ForegroundColor White
    Write-Host "Q) Quit" -ForegroundColor White
    Write-Host ""

    $action = Read-Host "Choose an action (1/2/Q)"

    switch -Regex ($action) {
        '^\s*1\s*$' { Invoke-PfxImport; break }
        '^\s*2\s*$' { Invoke-PfxExport; break }
        '^\s*q\s*$' {
            Write-Info "No action selected. Exiting."
            break
        }
        default {
            throw "Invalid selection. Enter 1, 2, or Q."
        }
    }
}
catch {
    Write-ErrMsg $_.Exception.Message
    exit 1
}
