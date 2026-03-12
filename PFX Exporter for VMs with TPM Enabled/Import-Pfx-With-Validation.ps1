#Requires -Version 5.1
# ScriptVersion: 1.7.0
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

$ScriptVersion = "1.7.0"
$ScriptDownloadUrl = "https://raw.githubusercontent.com/gsiscotty/PowerShellScripts/main/PFX%20Exporter%20for%20VMs%20with%20TPM%20Enabled/Import-Pfx-With-Validation.ps1"

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

function Test-IsNewerVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalVersion,

        [Parameter(Mandatory = $true)]
        [string]$RemoteVersion
    )

    try {
        return ([version]$RemoteVersion -gt [version]$LocalVersion)
    }
    catch {
        Write-WarnMsg "Version format comparison failed. Skipping update check."
        return $false
    }
}

function Invoke-ScriptUpdateCheck {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-WarnMsg "Cannot determine script path for self-update check. Skipping."
        return $false
    }

    Write-Info ("Checking for updates (current version: {0})..." -f $ScriptVersion)
    try {
        $cacheBuster = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $response = Invoke-WebRequest -Uri ("{0}?v={1}" -f $ScriptDownloadUrl, $cacheBuster) -UseBasicParsing -ErrorAction Stop
        $remoteContent = $response.Content

        if ([string]::IsNullOrWhiteSpace($remoteContent)) {
            throw "Downloaded update payload is empty."
        }

        $versionMatch = [regex]::Match($remoteContent, '(?m)^\s*#\s*ScriptVersion:\s*([0-9]+(?:\.[0-9]+){1,3})\s*$')
        if (-not $versionMatch.Success) {
            Write-WarnMsg "Could not detect remote script version. Skipping update."
            return $false
        }

        $remoteVersion = $versionMatch.Groups[1].Value
        if (-not (Test-IsNewerVersion -LocalVersion $ScriptVersion -RemoteVersion $remoteVersion)) {
            Write-Info "No update available."
            return $false
        }

        Write-WarnMsg ("A newer version is available: {0} (current: {1})" -f $remoteVersion, $ScriptVersion)
        $downloadChoice = Read-Host "Download and replace current script now? (Y/N, default N)"
        if ($downloadChoice -notmatch '^(Y|y)$') {
            Write-Info "Update skipped by user."
            return $false
        }

        $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("Import-Pfx-With-Validation.{0}.ps1" -f [guid]::NewGuid().ToString("N"))
        [System.IO.File]::WriteAllText($tempPath, $remoteContent, [System.Text.Encoding]::UTF8)
        Copy-Item -LiteralPath $tempPath -Destination $PSCommandPath -Force
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue

        Write-Ok ("Script updated to version {0}." -f $remoteVersion)
        $restartChoice = Read-Host "Restart script now to use the new version? (Y/N, default Y)"
        if ([string]::IsNullOrWhiteSpace($restartChoice) -or $restartChoice -match '^(Y|y)$') {
            & $PSCommandPath
            return $true
        }

        Write-Info "Continuing current session. New version will be used next run."
        return $false
    }
    catch {
        Write-WarnMsg ("Update check failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Get-DefaultVmStoreInfo {
    $preferredStore = "Cert:\LocalMachine\Shielded VM Local Certificates"
    $fallbackStore = "Cert:\LocalMachine\My"
    $defaultStore = if (Test-Path -LiteralPath $preferredStore) { $preferredStore } else { $fallbackStore }

    [PSCustomObject]@{
        PreferredStore = $preferredStore
        FallbackStore  = $fallbackStore
        DefaultStore   = $defaultStore
        IsPreferred    = ($defaultStore -eq $preferredStore)
    }
}

function Invoke-PfxListDefaultStore {
    Write-Host ""
    Write-Host "VM certificate store list" -ForegroundColor White
    Write-Host "-------------------------" -ForegroundColor DarkGray

    $storeInfo = Get-DefaultVmStoreInfo
    $storeLocation = $storeInfo.DefaultStore

    if ($storeInfo.IsPreferred) {
        Write-Info "Listing certificates from default vTPM/shielded VM store: $storeLocation"
    }
    else {
        Write-WarnMsg "vTPM/shielded VM store was not found. Listing fallback store: $storeLocation"
    }

    if (-not (Test-Path -LiteralPath $storeLocation)) {
        throw "The certificate store path does not exist: $storeLocation"
    }

    $availableCerts = @(Get-ChildItem -Path $storeLocation -ErrorAction Stop | Where-Object { $_.HasPrivateKey })
    if ($availableCerts.Count -eq 0) {
        Write-WarnMsg "No certificates with private keys were found in $storeLocation."
        return
    }

    Write-Info "Certificates with private key:"
    Write-Host ""
    Write-Host ("{0,-6} {1,-40} {2,-22} {3}" -f "Number", "Thumbprint", "NotAfter", "Subject")

    for ($i = 0; $i -lt $availableCerts.Count; $i++) {
        $cert = $availableCerts[$i]
        $line = "{0,-6} {1,-40} {2,-22} {3}" -f ($i + 1), $cert.Thumbprint, $cert.NotAfter, $cert.Subject

        if ($cert.Subject -match 'Encryption Certificate') {
            Write-Host $line -ForegroundColor Green
        }
        elseif ($cert.Subject -match 'Signing Certificate') {
            Write-Host $line -ForegroundColor Yellow
        }
        else {
            Write-Host $line -ForegroundColor White
        }
    }
}

function Invoke-PfxPostImportValidation {
    Write-Host ""
    Write-Host "Post-import VM certificate readiness check" -ForegroundColor White
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray

    $storeInfo = Get-DefaultVmStoreInfo
    $storeLocation = $storeInfo.DefaultStore
    $localHost = $env:COMPUTERNAME
    $escapedHost = [regex]::Escape($localHost)

    if ($storeInfo.IsPreferred) {
        Write-Info "Checking default vTPM/shielded VM store: $storeLocation"
    }
    else {
        Write-WarnMsg "vTPM/shielded VM store was not found. Checking fallback store: $storeLocation"
    }

    $storeChoice = Read-Host "Use this store? (Y/N, default Y)"
    if ($storeChoice -match '^(N|n)$') {
        $customStore = Read-Host "Enter certificate store path to validate"
        if (-not [string]::IsNullOrWhiteSpace($customStore)) {
            $storeLocation = $customStore
        }
    }

    if (-not (Test-Path -LiteralPath $storeLocation)) {
        throw "The certificate store path does not exist: $storeLocation"
    }

    $allCerts = @(Get-ChildItem -Path $storeLocation -ErrorAction Stop)
    $hostCerts = @($allCerts | Where-Object { $_.Subject -match $escapedHost })
    $encryptionCerts = @($hostCerts | Where-Object { $_.Subject -match 'Encryption Certificate' -and $_.HasPrivateKey })
    $signingCerts = @($hostCerts | Where-Object { $_.Subject -match 'Signing Certificate' -and $_.HasPrivateKey })

    $now = Get-Date
    $validEncryption = @($encryptionCerts | Where-Object { $_.NotAfter -gt $now })
    $validSigning = @($signingCerts | Where-Object { $_.NotAfter -gt $now })

    Write-Info ("Host context: {0}" -f $localHost)
    Write-Info ("Encryption certs with private key: {0} (valid: {1})" -f $encryptionCerts.Count, $validEncryption.Count)
    Write-Info ("Signing certs with private key: {0} (valid: {1})" -f $signingCerts.Count, $validSigning.Count)

    if ($hostCerts.Count -gt 0) {
        Write-Info "Host-related certs found in selected store:"
        $hostCerts |
            Select-Object Thumbprint, Subject, HasPrivateKey, NotAfter |
            Sort-Object Subject, NotAfter |
            Format-Table -AutoSize
    }
    else {
        Write-WarnMsg "No host-related certificates found for this host in selected store."
    }

    if ($validEncryption.Count -gt 0 -and $validSigning.Count -gt 0) {
        Write-Ok "Readiness check passed: both Encryption and Signing certificates are present, valid, and include private keys."
        return $true
    }

    Write-WarnMsg "Readiness check failed: both valid cert types are required before starting replicated encrypted VMs."
    return $false
}

function Invoke-PfxImport {
    Write-Host ""
    Write-Host "PFX validation and import tool" -ForegroundColor White
    Write-Host "--------------------------------" -ForegroundColor DarkGray

    $storeInfo = Get-DefaultVmStoreInfo
    $defaultStore = $storeInfo.DefaultStore

    if ($storeInfo.IsPreferred) {
        Write-Info "Default target store detected for vTPM/shielded VM certificates: $($storeInfo.PreferredStore)"
    }
    else {
        Write-WarnMsg "vTPM/shielded VM store was not found. Falling back to: $($storeInfo.FallbackStore)"
    }

    $storeLocation = Read-Host "Enter target certificate store or press Enter for default [$defaultStore]"
    if ([string]::IsNullOrWhiteSpace($storeLocation)) {
        $storeLocation = $defaultStore
    }

    if (-not (Test-Path -LiteralPath $storeLocation)) {
        throw "The certificate store path does not exist: $storeLocation"
    }

    $existingStoreCerts = @(Get-ChildItem -Path $storeLocation -ErrorAction Stop | Where-Object { $_.HasPrivateKey })
    if ($existingStoreCerts.Count -gt 0) {
        Write-Info "Existing certificates with private key in target store:"
        $existingStoreCerts |
            Select-Object Thumbprint, Subject, NotAfter |
            Sort-Object Subject, NotAfter |
            Format-Table -AutoSize
    }
    else {
        Write-WarnMsg "No certificates with private keys currently found in target store."
    }

    $importMode = Read-Host "Import mode: [A]utomatically import both VM cert types (default) or [S]ingle PFX"
    $password = Read-Host "Enter PFX password" -AsSecureString

    function Import-ValidatedPfxFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath,

            [Parameter(Mandatory = $true)]
            [System.Security.SecureString]$Password,

            [Parameter(Mandatory = $true)]
            [string]$StoreLocation
        )

        Write-Info "Validating PFX and password: $FilePath"
        $pfxData = $null
        try {
            $pfxData = Get-PfxData -FilePath $FilePath -Password $Password -ErrorAction Stop
            Write-Ok "Password validation succeeded."
        }
        catch {
            $msg = $_.Exception.Message

            if ($msg -match "requires either a different password or membership in an Active Directory principal") {
                Write-ErrMsg "Validation failed."
                Write-Host "Cause: The PFX is not importable with this password alone." -ForegroundColor Red
                Write-Host "It was likely protected for a specific Active Directory principal or exported with different protection settings." -ForegroundColor Red
                throw "Import validation failed for file: $FilePath"
            }
            elseif ($msg -match "network password is not correct|password") {
                Write-ErrMsg "Validation failed."
                Write-Host "Cause: The password appears to be incorrect." -ForegroundColor Red
                throw "Import validation failed for file: $FilePath"
            }
            else {
                Write-ErrMsg "Validation failed."
                Write-Host "Cause: $msg" -ForegroundColor Red
                throw "Import validation failed for file: $FilePath"
            }
        }

        $incomingCert = $pfxData.EndEntityCertificates | Select-Object -First 1
        if ($null -eq $incomingCert) {
            throw "Validated PFX did not contain an end-entity certificate: $FilePath"
        }

        Write-Info ("Incoming certificate subject: {0}" -f $incomingCert.Subject)
        Write-Info ("Incoming certificate thumbprint: {0}" -f $incomingCert.Thumbprint)

        $sameSubjectCerts = @(Get-ChildItem -Path $StoreLocation -ErrorAction Stop |
            Where-Object { $_.Subject -eq $incomingCert.Subject })
        $shouldRemoveOlderSameSubject = $false

        if ($sameSubjectCerts.Count -gt 0) {
            Write-Info "Matching existing certificate(s) with same subject found:"
            $sameSubjectCerts |
                Select-Object Thumbprint, Subject, NotAfter |
                Sort-Object NotAfter -Descending |
                Format-Table -AutoSize

            $sameThumbprint = $sameSubjectCerts | Where-Object { $_.Thumbprint -eq $incomingCert.Thumbprint } | Select-Object -First 1
            if ($null -ne $sameThumbprint) {
                Write-WarnMsg "Identical certificate already exists in target store. Skipping import (not needed)."
                return "Skipped"
            }

            $latestExisting = $sameSubjectCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
            if ($incomingCert.NotAfter -gt $latestExisting.NotAfter) {
                Write-Info ("New certificate expires later than latest existing one ({0} > {1})." -f $incomingCert.NotAfter, $latestExisting.NotAfter)
                $replaceChoice = Read-Host "Import new cert and remove older same-subject cert(s)? (Y/N, default Y)"
                if ([string]::IsNullOrWhiteSpace($replaceChoice) -or $replaceChoice -match '^(Y|y)$') {
                    $shouldRemoveOlderSameSubject = $true
                }
            }
            else {
                $importChoice = Read-Host "Existing same-subject cert is same/newer expiry. Import anyway? (Y/N, default N)"
                if ($importChoice -notmatch '^(Y|y)$') {
                    Write-WarnMsg "Import skipped because replacement is not needed."
                    return "Skipped"
                }
            }
        }

        Write-Info "Importing certificate into $StoreLocation ..."
        try {
            $result = Import-PfxCertificate -FilePath $FilePath -CertStoreLocation $StoreLocation -Password $Password -ErrorAction Stop

            if ($null -ne $result) {
                Write-Ok "Import completed successfully."
                $result | Select-Object Thumbprint, Subject, FriendlyName, PSParentPath | Format-List
            }
            else {
                Write-WarnMsg "Import command returned no certificate object, but no terminating error occurred."
            }

            if ($shouldRemoveOlderSameSubject -and $sameSubjectCerts.Count -gt 0) {
                foreach ($oldCert in $sameSubjectCerts) {
                    try {
                        Remove-Item -LiteralPath $oldCert.PSPath -ErrorAction Stop
                        Write-Ok ("Removed older certificate: {0}" -f $oldCert.Thumbprint)
                    }
                    catch {
                        Write-WarnMsg ("Could not remove older certificate {0}: {1}" -f $oldCert.Thumbprint, $_.Exception.Message)
                    }
                }
            }

            return "Imported"
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

            throw "Import failed for file: $FilePath"
        }
    }

    if ($importMode -match '^\s*s\s*$') {
        $sourcePath = Read-Host "Enter full path to the PFX file"
        if ([string]::IsNullOrWhiteSpace($sourcePath)) {
            throw "No source path was entered."
        }
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "The file does not exist: $sourcePath"
        }

        $singleResult = Import-ValidatedPfxFile -FilePath $sourcePath -Password $password -StoreLocation $storeLocation
        Write-Info ("Single import result: {0}" -f $singleResult)
        $validateNow = Read-Host "Run post-import readiness check now? (Y/N, default Y)"
        if ([string]::IsNullOrWhiteSpace($validateNow) -or $validateNow -match '^(Y|y)$') {
            $null = Invoke-PfxPostImportValidation
        }
        return
    }

    $sourceFolder = Read-Host "Enter folder path containing exported VM PFX files"
    if ([string]::IsNullOrWhiteSpace($sourceFolder)) {
        throw "No source folder path was entered."
    }
    if (-not (Test-Path -LiteralPath $sourceFolder -PathType Container)) {
        throw "The folder does not exist: $sourceFolder"
    }

    $pfxFiles = @(Get-ChildItem -LiteralPath $sourceFolder -Filter "*.pfx" -File -ErrorAction Stop)
    if ($pfxFiles.Count -eq 0) {
        throw "No PFX files were found in folder: $sourceFolder"
    }

    $encryptionCandidates = @($pfxFiles | Where-Object { $_.Name -match 'Encryption' } | Sort-Object LastWriteTime -Descending)
    $signingCandidates = @($pfxFiles | Where-Object { $_.Name -match 'Signing' } | Sort-Object LastWriteTime -Descending)

    if ($encryptionCandidates.Count -eq 0 -or $signingCandidates.Count -eq 0) {
        Write-WarnMsg "Could not detect both Encryption and Signing PFX files by filename."
        Write-Info "Detected files:"
        $pfxFiles | Select-Object Name, LastWriteTime | Format-Table -AutoSize
        throw "Automatic import requires at least one Encryption and one Signing PFX file in the selected folder."
    }

    $filesToImport = @(
        $encryptionCandidates[0]
        $signingCandidates[0]
    )

    Write-Info "Auto-selected files for import:"
    $filesToImport | Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize

    $confirmImport = Read-Host "Import both selected files now? (Y/N, default Y)"
    if (-not [string]::IsNullOrWhiteSpace($confirmImport) -and $confirmImport -notmatch '^(Y|y)$') {
        throw "Automatic import was cancelled."
    }

    $successCount = 0
    $skipCount = 0
    $failCount = 0

    foreach ($file in $filesToImport) {
        try {
            $result = Import-ValidatedPfxFile -FilePath $file.FullName -Password $password -StoreLocation $storeLocation
            if ($result -eq "Skipped") {
                $skipCount++
            }
            else {
                $successCount++
            }
        }
        catch {
            Write-ErrMsg $_.Exception.Message
            $failCount++
        }
    }

    Write-Host ""
    Write-Ok ("Auto-import finished. Success: {0}, Skipped: {1}, Failed: {2}" -f $successCount, $skipCount, $failCount)
    if ($failCount -gt 0) {
        Write-WarnMsg "One or more files failed to import. Review errors above."
    }

    $validateNow = Read-Host "Run post-import readiness check now? (Y/N, default Y)"
    if ([string]::IsNullOrWhiteSpace($validateNow) -or $validateNow -match '^(Y|y)$') {
        $null = Invoke-PfxPostImportValidation
    }
}

function Invoke-PfxExport {
    Write-Host ""
    Write-Host "Certificate to PFX export tool" -ForegroundColor White
    Write-Host "------------------------------" -ForegroundColor DarkGray

    $storeInfo = Get-DefaultVmStoreInfo
    $defaultStore = $storeInfo.DefaultStore

    if ($storeInfo.IsPreferred) {
        Write-Info "Default source store detected for vTPM/shielded VM certificates: $($storeInfo.PreferredStore)"
    }
    else {
        Write-WarnMsg "vTPM/shielded VM store was not found. Falling back to: $($storeInfo.FallbackStore)"
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

if (Invoke-ScriptUpdateCheck) {
    return
}

while ($true) {
    Write-Host ""
    Write-Host "PFX tool" -ForegroundColor White
    Write-Host "--------" -ForegroundColor DarkGray
    Write-Host "1) Import PFX (validate password first)" -ForegroundColor White
    Write-Host "2) Export certificate to PFX" -ForegroundColor White
    Write-Host "3) List certificates in default VM store" -ForegroundColor White
    Write-Host "4) Validate target readiness (post-import)" -ForegroundColor White
    Write-Host "Q) Quit" -ForegroundColor White
    Write-Host ""

    $action = Read-Host "Choose an action (1/2/3/4/Q)"
    $userChoseQuit = $false

    try {
        switch -Regex ($action) {
            '^\s*1\s*$' { Invoke-PfxImport; break }
            '^\s*2\s*$' { Invoke-PfxExport; break }
            '^\s*3\s*$' { Invoke-PfxListDefaultStore; break }
            '^\s*4\s*$' { $null = Invoke-PfxPostImportValidation; break }
            '^\s*q\s*$' {
                $userChoseQuit = $true
                Write-Info "Exiting."
                break
            }
            default {
                Write-WarnMsg "Invalid selection. Enter 1, 2, 3, 4, or Q."
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
