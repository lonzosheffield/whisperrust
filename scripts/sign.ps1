<#
.SYNOPSIS
  Sign the WhisperRust binary with the local development certificate.

.DESCRIPTION
  Phase 0 criterion (d). Self-signed, per PLAN.md 10.2 - a commercial certificate was
  deliberately NOT purchased, because signing addresses SmartScreen and tamper-evidence,
  and does nothing about behavioral AV detection of a keyboard hook. For a tool that runs
  on one machine, a self-signed certificate installed into that machine's trust store
  gets the full benefit for no money.

  Creates the certificate on first run and reuses it afterwards.

.NOTES
  Making the signature TRUSTED requires importing the certificate into
  Cert:\LocalMachine\Root, which needs elevation. Under governance rule G-3 that is a
  MUST-STOP action, so this script prints the command rather than running it.
#>

$ErrorActionPreference = 'Stop'
$subject = 'CN=WhisperRust Development'
$exe = Join-Path $PSScriptRoot '..\target\release\whisperrust.exe' | Resolve-Path -ErrorAction SilentlyContinue

if (-not $exe) { Write-Error 'Build first: cargo build --release'; exit 1 }

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
if (-not $cert) {
    Write-Host 'Creating development certificate...'
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA -KeyLength 3072 -NotAfter (Get-Date).AddYears(3)
}
Write-Host "Certificate: $($cert.Thumbprint)"

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1

if ($signtool) {
    & $signtool.FullName sign /fd SHA256 /sha1 $cert.Thumbprint /d 'WhisperRust' $exe
} else {
    Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -HashAlgorithm SHA256 | Out-Null
}

$sig = Get-AuthenticodeSignature $exe
Write-Host ""
Write-Host "Signature status: $($sig.Status)"
Write-Host "Signer:           $($sig.SignerCertificate.Subject)"

if ($sig.Status -ne 'Valid') {
    Write-Host ""
    Write-Host "Status is not Valid because the certificate is not in the machine trust store."
    Write-Host "That import needs ELEVATION, which is a MUST-STOP action under G-3, so run it"
    Write-Host "yourself from an admin PowerShell if you want the signature to verify:"
    Write-Host ""
    Write-Host "  `$c = Get-ChildItem Cert:\CurrentUser\My | ? { `$_.Subject -eq '$subject' }"
    Write-Host "  Export-Certificate -Cert `$c -FilePath `$env:TEMP\whisperrust.cer | Out-Null"
    Write-Host "  Import-Certificate -FilePath `$env:TEMP\whisperrust.cer -CertStoreLocation Cert:\LocalMachine\Root"
    Write-Host ""
    Write-Host "Signing does NOT stop antivirus flagging a keyboard hook - see PLAN.md 10.2."
}
