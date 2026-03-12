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
            throw "Import validation failed."
        }
        elseif ($msg -match "network password is not correct|password") {
            Write-ErrMsg "Validation failed."
            Write-Host "Cause: The password appears to be incorrect." -ForegroundColor Red
            throw "Import validation failed."
        }
        else {
            Write-ErrMsg "Validation failed."
            Write-Host "Cause: $msg" -ForegroundColor Red
            throw "Import validation failed."
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

        throw "Import failed."
    }
}

function Invoke-PfxExport {
    Write-Host ""
    Write-Host "Certificate to PFX export tool" -ForegroundColor White
    Write-Host "------------------------------" -ForegroundColor DarkGray

    $preferredStore = "Cert:\LocalMachine\Shielded VM Local Certificates"
    $fallbackStore = "Cert:\LocalMachine\My"
    $defaultStore = if (Test-Path -LiteralPath $preferredStore) { $preferredStore } else { $fallbackStore }

    if ($defaultStore -eq $preferredStore) {
        Write-Info "Default source store detected for vTPM/shielded VM certificates: $preferredStore"
    }
    else {
        Write-WarnMsg "vTPM/shielded VM store was not found. Falling back to: $fallbackStore"
    }

    $storeLocation = Read-Host "Enter source certificate store or press Enter for default [$defaultStore]"
    if ([string]::IsNullOrWhiteSpace($storeLocation)) {
        $storeLocation = $defaultStore
    }

    if (-not (Test-Path -LiteralPath $storeLocation)) {
        throw "The certificate store path does not exist: $storeLocation"
    }

    $availableCerts = @(Get-ChildItem -Path $storeLocation -ErrorAction Stop | Where-Object { $_.HasPrivateKey })
    if ($availableCerts.Count -eq 0) {
        throw "No certificates with private keys were found in $storeLocation."
    }

    $localHost = $env:COMPUTERNAME
    $escapedHost = [regex]::Escape($localHost)
    $hostScopedCerts = @($availableCerts | Where-Object { $_.Subject -match $escapedHost })
    $hostVmCerts = @($hostScopedCerts | Where-Object { $_.Subject -match 'Encryption Certificate|Signing Certificate' })

    Write-Info "Host context: $localHost"
    Write-Info "Default filter exports host-related VM certificates (Encryption + Signing)."

    $filterChoice = Read-Host "Filter certificates: [H]ost VM certs (default), [E]ncryption, [S]igning, [A]ll"
    $displayCerts = $availableCerts
    switch -Regex ($filterChoice) {
        '^\s*h\s*$' { $displayCerts = $hostVmCerts; break }
        '^\s*e\s*$' { $displayCerts = @($availableCerts | Where-Object { $_.Subject -match 'Encryption Certificate' }); break }
        '^\s*s\s*$' { $displayCerts = @($availableCerts | Where-Object { $_.Subject -match 'Signing Certificate' }); break }
        '^\s*a\s*$' { $displayCerts = $availableCerts; break }
        default { $displayCerts = $hostVmCerts; break }
    }

    if ($displayCerts.Count -eq 0) {
        Write-WarnMsg "No certificates matched the selected filter. Showing all certificates with private keys."
        $displayCerts = $availableCerts
    }

    Write-Info "Available certificates (with private key):"
    $indexedCerts = for ($i = 0; $i -lt $displayCerts.Count; $i++) {
        [PSCustomObject]@{
            Number     = $i + 1
            Thumbprint = $displayCerts[$i].Thumbprint
            Subject    = $displayCerts[$i].Subject
            NotAfter   = $displayCerts[$i].NotAfter
        }
    }
    Write-Host ""
    Write-Host ("{0,-6} {1,-40} {2}" -f "Number", "Thumbprint", "Subject")
    foreach ($item in $indexedCerts) {
        $line = "{0,-6} {1,-40} {2}" -f $item.Number, $item.Thumbprint, $item.Subject
        if ($item.Subject -match 'Encryption Certificate') {
            Write-Host $line -ForegroundColor Green
        }
        elseif ($item.Subject -match 'Signing Certificate') {
            Write-Host $line -ForegroundColor Yellow
        }
        else {
            Write-Host $line -ForegroundColor White
        }
    }
    Write-Host ""

    $recommendedCert = $indexedCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
    $exportMode = Read-Host "Export mode: [A]ll listed certificates (default) or [S]ingle certificate"

    if ($exportMode -notmatch '^\s*s\s*$') {
        $destinationFolder = Read-Host "Enter output folder for exported PFX files"
        if ([string]::IsNullOrWhiteSpace($destinationFolder)) {
            throw "No destination folder was entered."
        }

        if (-not (Test-Path -LiteralPath $destinationFolder)) {
            New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
        }

        $overwriteChoice = Read-Host "Overwrite existing files? (Y/N, default N)"
        $allowOverwrite = $overwriteChoice -match '^(Y|y)$'
        $password = Read-Host "Enter password to protect the exported PFX files" -AsSecureString

        $successCount = 0
        $skipCount = 0
        $failCount = 0

        foreach ($cert in $displayCerts) {
            $safeSubject = ($cert.Subject -replace '^CN=', '' -replace '[^A-Za-z0-9._-]', '_').Trim('_')
            if ([string]::IsNullOrWhiteSpace($safeSubject)) {
                $safeSubject = "certificate"
            }

            $shortThumbprint = if ($cert.Thumbprint.Length -ge 12) { $cert.Thumbprint.Substring(0, 12) } else { $cert.Thumbprint }
            $fileName = "{0}_{1}.pfx" -f $safeSubject, $shortThumbprint
            $destinationPath = Join-Path $destinationFolder $fileName

            if ((Test-Path -LiteralPath $destinationPath -PathType Leaf) -and -not $allowOverwrite) {
                Write-WarnMsg "Skipped existing file: $destinationPath"
                $skipCount++
                continue
            }

            try {
                Write-Info "Exporting: $($cert.Subject)"
                $exported = Export-PfxCertificate -Cert $cert.PSPath -FilePath $destinationPath -Password $password -ErrorAction Stop
                if ($null -eq $exported) {
                    throw "Export-PfxCertificate returned no result."
                }

                # Validate each exported file to confirm password protection and integrity.
                $null = Get-PfxData -FilePath $destinationPath -Password $password -ErrorAction Stop
                Write-Ok "Saved: $destinationPath"
                $successCount++
            }
            catch {
                Write-ErrMsg ("Failed to export {0}: {1}" -f $cert.Subject, $_.Exception.Message)
                $failCount++
            }
        }

        Write-Host ""
        Write-Ok ("Export finished. Success: {0}, Skipped: {1}, Failed: {2}" -f $successCount, $skipCount, $failCount)
        if ($failCount -gt 0) {
            Write-WarnMsg "Some certificates failed to export. Review errors above."
        }

        return
    }

    Write-Info ("Recommended: #{0} (latest expiration: {1})" -f $recommendedCert.Number, $recommendedCert.NotAfter)

    $lookupValue = Read-Host "Enter certificate number, thumbprint, or part of subject (press Enter for recommended #$($recommendedCert.Number))"
    if ([string]::IsNullOrWhiteSpace($lookupValue)) {
        $lookupValue = [string]$recommendedCert.Number
    }

    $lookupValue = $lookupValue.Trim()
    $thumbprintPattern = '^[A-Fa-f0-9]{40}$'
    $cert = $null

    if ($lookupValue -match '^\d+$') {
        $selectionNumber = [int]$lookupValue
        if ($selectionNumber -lt 1 -or $selectionNumber -gt $displayCerts.Count) {
            throw "Selection number $selectionNumber is out of range. Choose a number between 1 and $($displayCerts.Count)."
        }
        $cert = $displayCerts[$selectionNumber - 1]
    }
    elseif ($lookupValue -match $thumbprintPattern) {
        $normalizedThumbprint = $lookupValue.ToUpperInvariant()
        $cert = $displayCerts |
            Where-Object { $_.Thumbprint -eq $normalizedThumbprint } |
            Select-Object -First 1
    }
    else {
        $matches = $displayCerts |
            Where-Object { $_.Subject -like "*$lookupValue*" }

        if (($matches | Measure-Object).Count -gt 1) {
            Write-Info "Multiple certificates matched. Showing candidates:"
            $matches | Select-Object Thumbprint, Subject, NotAfter | Format-Table -AutoSize
            throw "More than one certificate matched '$lookupValue'. Use a number or thumbprint to select a single certificate."
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

while ($true) {
    Write-Host ""
    Write-Host "PFX tool" -ForegroundColor White
    Write-Host "--------" -ForegroundColor DarkGray
    Write-Host "1) Import PFX (validate password first)" -ForegroundColor White
    Write-Host "2) Export certificate to PFX" -ForegroundColor White
    Write-Host "Q) Quit" -ForegroundColor White
    Write-Host ""

    $action = Read-Host "Choose an action (1/2/Q)"
    $userChoseQuit = $false

    try {
        switch -Regex ($action) {
            '^\s*1\s*$' { Invoke-PfxImport; break }
            '^\s*2\s*$' { Invoke-PfxExport; break }
            '^\s*q\s*$' {
                $userChoseQuit = $true
                Write-Info "Exiting."
                break
            }
            default {
                Write-WarnMsg "Invalid selection. Enter 1, 2, or Q."
            }
        }
    }
    catch {
        Write-ErrMsg $_.Exception.Message
    }

    if ($userChoseQuit) {
        break
    }

    $nextStep = Read-Host "What next? Press Enter for main menu or Q to quit"
    if ($nextStep -match '^\s*q\s*$') {
        Write-Info "Exiting."
        break
    }
}
