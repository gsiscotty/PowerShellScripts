# PFX Import/Export Tool (TPM VM Friendly)

PowerShell script to safely **import** or **export** PFX certificates with interactive prompts.

## What this script does

- Asks what action to perform before doing anything (`Import`, `Export`, or `Quit`)
- Validates PFX password before import
- Imports certificate into a selected certificate store
- Exports a certificate with private key to a password-protected PFX
- Validates the exported PFX immediately after export

## File

- `Import-Pfx-With-Validation.ps1`

## Requirements

- Windows PowerShell 5.1 or newer
- Run PowerShell as Administrator when working with `LocalMachine` stores

## How to use (local)

1. Open PowerShell.
2. Change to the script folder:

```powershell
Set-Location "C:\path\to\PowerShellScripts\PFX Exporter for VMs with TPM Enabled"
```

3. Run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Import-Pfx-With-Validation.ps1
```

4. Choose:
   - `1` to import PFX
   - `2` to export certificate to PFX
   - `Q` to exit

## How to download directly in PowerShell

One-line download command:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/gsiscotty/PowerShellScripts/796bd949cbf4b4a09a67df3ba9ab6d9fd8c3a9ab/PFX%20Exporter%20for%20VMs%20with%20TPM%20Enabled/Import-Pfx-With-Validation.ps1" -OutFile "$HOME\Downloads\Import-Pfx-With-Validation.ps1"
```

Then run:

```powershell
Set-Location "$HOME\Downloads"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Import-Pfx-With-Validation.ps1
```

Use this raw file URL:

```text
https://raw.githubusercontent.com/gsiscotty/PowerShellScripts/796bd949cbf4b4a09a67df3ba9ab6d9fd8c3a9ab/PFX%20Exporter%20for%20VMs%20with%20TPM%20Enabled/Import-Pfx-With-Validation.ps1
```

Download command:

```powershell
$url = "https://raw.githubusercontent.com/gsiscotty/PowerShellScripts/796bd949cbf4b4a09a67df3ba9ab6d9fd8c3a9ab/PFX%20Exporter%20for%20VMs%20with%20TPM%20Enabled/Import-Pfx-With-Validation.ps1"
$folder = "$HOME\Downloads\PfxTool"
$outFile = Join-Path $folder "Import-Pfx-With-Validation.ps1"
New-Item -ItemType Directory -Path $folder -Force | Out-Null
Invoke-WebRequest -Uri $url -OutFile $outFile
```

Run after download:

```powershell
Set-Location "$HOME\Downloads\PfxTool"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Import-Pfx-With-Validation.ps1
```

## Git quick start (commit/push)

```bash
git init
git add .
git commit -m "Add PFX import/export script docs and ignore rules"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## Security notes

- Do not commit private keys or PFX files to source control.
- Keep certificate passwords out of scripts and logs.
