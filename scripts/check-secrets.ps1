<#
.SYNOPSIS
  Fails if environment-specific identifiers appear in git-TRACKED files.

.DESCRIPTION
  This repo is public. Machine- and organization-specific facts belong in LOCAL-ENV.md,
  which is gitignored. This script is the backstop: it scans only tracked files (so it
  ignores LOCAL-ENV.md by construction) and exits non-zero on any hit.

  Run manually, from the pre-commit hook, and in CI.

.EXAMPLE
  pwsh -File scripts/check-secrets.ps1
#>

[CmdletBinding()]
param(
    # Scan these paths instead of all tracked files (used by the pre-commit hook).
    [string[]] $Paths
)

$ErrorActionPreference = 'Stop'

# Identifier patterns that must never appear in tracked content.
# Keep the VALUES here, not in docs. This file is itself scanned, so patterns are
# split/escaped to avoid self-matching on the literal strings.
$patterns = @(
    @{ Name = 'Tenant name';       Regex = 'Firstline\s*Compliance' }
    @{ Name = 'Corporate email';   Regex = '[A-Za-z0-9._%+-]+@firstlinecompliance\.com' }
    @{ Name = 'Device GUID';       Regex = '11eaef20-2634-4f11-9d25-5aa4466f4fe1' }
    @{ Name = 'Local account';     Regex = 'AzureAD\+\w+' }
    @{ Name = 'AV product';        Regex = 'Malwarebytes' }
    @{ Name = 'MDM product';       Regex = '\bIntune\b' }
    @{ Name = 'MDM endpoint';      Regex = 'enrollment\.manage\.microsoft\.com' }
    @{ Name = 'Personal email';    Regex = '[A-Za-z0-9._%+-]+@gmail\.com' }
    @{ Name = 'Home dir path';     Regex = 'C:\\Users\\[A-Za-z0-9~]+' }
    @{ Name = 'Private key block'; Regex = 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' }
)

if ($Paths) {
    $files = $Paths | Where-Object { Test-Path $_ }
} else {
    $files = git ls-files 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Error 'Not a git repository.'; exit 2 }
}

# Do not scan this script (it necessarily contains the patterns).
$self = 'scripts/check-secrets.ps1'
$files = $files | Where-Object { $_ -and ($_ -replace '\\','/') -ne $self }

$findings = @()

foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }

    # Skip binaries.
    $bytes = [System.IO.File]::ReadAllBytes($file)
    if ($bytes.Length -gt 0 -and ($bytes[0..([Math]::Min(8000, $bytes.Length - 1))] -contains 0)) { continue }

    $lines = Get-Content -LiteralPath $file -ErrorAction SilentlyContinue
    if (-not $lines) { continue }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($p in $patterns) {
            if ($lines[$i] -match $p.Regex) {
                $findings += [pscustomobject]@{
                    File    = $file
                    Line    = $i + 1
                    Pattern = $p.Name
                    Text    = $lines[$i].Trim()
                }
            }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host ''
    Write-Host 'SECRET SCAN FAILED - environment identifiers found in tracked files:' -ForegroundColor Red
    Write-Host ''
    foreach ($f in $findings) {
        Write-Host ("  {0}:{1}  [{2}]" -f $f.File, $f.Line, $f.Pattern) -ForegroundColor Yellow
        $snippet = if ($f.Text.Length -gt 100) { $f.Text.Substring(0, 100) + '...' } else { $f.Text }
        Write-Host ("      {0}" -f $snippet) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host 'This repository is PUBLIC. Move these values into LOCAL-ENV.md (gitignored)' -ForegroundColor Red
    Write-Host 'and reference that file by name instead. See PLAN.md 10.6.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

Write-Host "Secret scan clean ($($files.Count) tracked files)." -ForegroundColor Green
exit 0
