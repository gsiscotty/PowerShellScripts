# PFX Import/Export Tool (TPM VM Friendly)

PowerShell script to safely **import** or **export** PFX certificates with interactive prompts.

## What this script does

- Asks what action to perform before doing anything (`Import`, `Export`, or `Quit`)
- Validates PFX password before import
- Imports certificate into a selected certificate store
- Import mode can automatically import both VM cert types (Encryption + Signing)
- Exports a certificate with private key to a password-protected PFX
- By default exports host-related VM certificates for the current host (`$env:COMPUTERNAME`)
- Includes both VM **Encryption** and VM **Signing** certificates in default host export
- Validates the exported PFX immediately after export
- Includes dedicated list and post-import readiness validation actions
- Checks GitHub for a newer script version on launch and prompts to update

## File

- `Import-Pfx-With-Validation.ps1`

## Requirements

- Windows PowerShell 5.1 or newer
- Run PowerShell as Administrator when working with `LocalMachine` stores

## Quick start (download and run)

1. Open PowerShell.
2. Download the script:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/gsiscotty/PowerShellScripts/main/PFX%20Exporter%20for%20VMs%20with%20TPM%20Enabled/Import-Pfx-With-Validation.ps1" -OutFile "$HOME\Downloads\Import-Pfx-With-Validation.ps1"
```

3. Run it:

```powershell
Set-Location "$HOME\Downloads"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Import-Pfx-With-Validation.ps1
```

4. Choose:
   - `1` to import PFX
   - `2` to export certificate to PFX
   - `3` to list certificates in default VM store
   - `4` to validate target readiness after import
   - `Q` to exit

## Which certificates should I export?

- If you are on `GSISRVHYP05`, export certificates related to `GSISRVHYP05`.
- For replication/move scenarios, export both:
  - `Shielded VM Encryption Certificate`
  - `Shielded VM Signing Certificate`
- The script default filter (`H`) is designed for this: host-related VM certs (Encryption + Signing).

## If already cloned locally

```powershell
Set-Location "C:\path\to\PowerShellScripts\PFX Exporter for VMs with TPM Enabled"
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
