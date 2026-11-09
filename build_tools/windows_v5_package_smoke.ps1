param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,
    [Parameter(Mandatory = $true)]
    [string]$TempRoot
)

$ErrorActionPreference = "Stop"
$exe = (Resolve-Path -LiteralPath $ExecutablePath).Path
$smokeRoot = Join-Path $TempRoot ("hse2-v5-package-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $smokeRoot | Out-Null

$primary = Join-Path $smokeRoot "primary.txt"
$secondary = Join-Path $smokeRoot "secondary.txt"
$replacement = Join-Path $smokeRoot "replacement.txt"
$legacyPrimary = Join-Path $smokeRoot "legacy-primary.txt"
$legacySecondary = Join-Path $smokeRoot "legacy-secondary.txt"
Set-Content -LiteralPath $primary -Value "primary package smoke" -NoNewline
Set-Content -LiteralPath $secondary -Value "secondary package smoke" -NoNewline
Set-Content -LiteralPath $replacement -Value "replacement v5 package smoke" -NoNewline
Set-Content -LiteralPath $legacyPrimary -Value "legacy v4 primary package smoke" -NoNewline
Set-Content -LiteralPath $legacySecondary -Value "legacy v4 secondary package smoke" -NoNewline

$primaryPassword = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) # pragma: allowlist secret
$secondaryPassword = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) # pragma: allowlist secret
$newPrimaryPassword = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) # pragma: allowlist secret
$v5Container = Join-Path $smokeRoot "source-v5.hse2"
@($primaryPassword, $primaryPassword, $secondaryPassword, $secondaryPassword) |
    & $exe hse2 v5-create --passwords-stdin --output $v5Container `
        --primary-file "primary.txt=$primary" --secondary-file "secondary.txt=$secondary"
if ($LASTEXITCODE -ne 0) { throw "Packaged v5-create smoke failed" }
$v5SourceDigest = (Get-FileHash -LiteralPath $v5Container -Algorithm SHA256).Hash

foreach ($view in @(
    @{ Name = "primary"; Password = $primaryPassword; Expected = $primary },
    @{ Name = "secondary"; Password = $secondaryPassword; Expected = $secondary }
)) {
    $verified = @($view.Password | & $exe hse2 v5-verify --password-stdin --input $v5Container)
    if ($LASTEXITCODE -ne 0) { throw "Packaged v5 $($view.Name)-verify smoke failed" }
    $verifiedResult = ($verified -join [Environment]::NewLine) | ConvertFrom-Json
    if (-not $verifiedResult.payload_authenticated -or $verifiedResult.plaintext_written) {
        throw "Packaged v5 $($view.Name)-verify returned unexpected status"
    }
    $restored = Join-Path $smokeRoot ("source-" + $view.Name + "-restored")
    $view.Password | & $exe hse2 v5-open --password-stdin --input $v5Container --output-dir $restored
    if ($LASTEXITCODE -ne 0) { throw "Packaged v5 $($view.Name)-open smoke failed" }
    if ((Get-FileHash -LiteralPath (Join-Path $restored ($view.Name + ".txt"))).Hash -ne
        (Get-FileHash -LiteralPath $view.Expected).Hash) {
        throw "Packaged v5 $($view.Name) restored bytes differ"
    }
}

$previewTarget = Join-Path $smokeRoot "v5-preview-target"
$previewOutput = @($primaryPassword | & $exe hse2 v5-preview --password-stdin `
    --input $v5Container --output-dir $previewTarget)
if ($LASTEXITCODE -ne 0) { throw "Packaged v5-preview smoke failed" }
$preview = ($previewOutput -join [Environment]::NewLine) | ConvertFrom-Json
if ($preview.view_slot -ne 0 -or $preview.file_count -ne 1 -or $preview.output_exists) {
    throw "Packaged v5-preview returned unexpected metadata"
}
if (Test-Path -LiteralPath $previewTarget) { throw "Packaged v5-preview unexpectedly wrote plaintext" }

$passwordUpdated = Join-Path $smokeRoot "password-updated-v5.hse2"
@($primaryPassword, $newPrimaryPassword, $newPrimaryPassword) |
    & $exe hse2 v5-password-update --passwords-stdin --input $v5Container --output $passwordUpdated
if ($LASTEXITCODE -ne 0) { throw "Packaged v5-password-update smoke failed" }
foreach ($view in @(
    @{ Name = "primary"; Password = $newPrimaryPassword; Expected = $primary },
    @{ Name = "secondary"; Password = $secondaryPassword; Expected = $secondary }
)) {
    $restored = Join-Path $smokeRoot ("password-updated-" + $view.Name + "-restored")
    $view.Password | & $exe hse2 v5-open --password-stdin --input $passwordUpdated --output-dir $restored
    if ($LASTEXITCODE -ne 0) { throw "Packaged v5 updated-$($view.Name)-open smoke failed" }
    if ((Get-FileHash -LiteralPath (Join-Path $restored ($view.Name + ".txt"))).Hash -ne
        (Get-FileHash -LiteralPath $view.Expected).Hash) {
        throw "Packaged v5 password update changed $($view.Name) bytes"
    }
}

$replaced = Join-Path $smokeRoot "replaced-v5.hse2"
$newPrimary = Join-Path $smokeRoot "new-primary-restored"
$newPeer = Join-Path $smokeRoot "new-peer-restored"
$newPrimaryPassword | & $exe hse2 v5-replace --password-stdin --input $passwordUpdated `
    --output $replaced --file "primary.txt=$replacement"
if ($LASTEXITCODE -ne 0) { throw "Packaged v5-replace smoke failed" }
$newPrimaryPassword | & $exe hse2 v5-open --password-stdin --input $replaced --output-dir $newPrimary
if ($LASTEXITCODE -ne 0) { throw "Packaged v5 replaced-primary open smoke failed" }
if ((Get-FileHash -LiteralPath (Join-Path $newPrimary "primary.txt")).Hash -ne
    (Get-FileHash -LiteralPath $replacement).Hash) { throw "Packaged v5 replacement bytes differ" }
$secondaryPassword | & $exe hse2 v5-open --password-stdin --input $replaced --output-dir $newPeer
if ($LASTEXITCODE -ne 0) { throw "Packaged v5 replaced-peer open smoke failed" }
if ((Get-FileHash -LiteralPath (Join-Path $newPeer "secondary.txt")).Hash -ne
    (Get-FileHash -LiteralPath $secondary).Hash) { throw "Packaged v5 replacement changed peer bytes" }

$compacted = Join-Path $smokeRoot "compacted-v5.hse2"
@($newPrimaryPassword, $secondaryPassword) |
    & $exe hse2 v5-compact --passwords-stdin --input $replaced --output $compacted --profile compatible
if ($LASTEXITCODE -ne 0) { throw "Packaged v5-compact smoke failed" }
$compactedPrimary = Join-Path $smokeRoot "compacted-primary-restored"
$compactedPeer = Join-Path $smokeRoot "compacted-peer-restored"
$newPrimaryPassword | & $exe hse2 v5-open --password-stdin --input $compacted --output-dir $compactedPrimary
if ($LASTEXITCODE -ne 0) { throw "Packaged v5 compacted-primary open smoke failed" }
if ((Get-FileHash -LiteralPath (Join-Path $compactedPrimary "primary.txt")).Hash -ne
    (Get-FileHash -LiteralPath $replacement).Hash) { throw "Packaged v5 compact changed primary bytes" }
$secondaryPassword | & $exe hse2 v5-open --password-stdin --input $compacted --output-dir $compactedPeer
if ($LASTEXITCODE -ne 0) { throw "Packaged v5 compacted-peer open smoke failed" }
if ((Get-FileHash -LiteralPath (Join-Path $compactedPeer "secondary.txt")).Hash -ne
    (Get-FileHash -LiteralPath $secondary).Hash) { throw "Packaged v5 compact changed peer bytes" }

$v4Container = Join-Path $smokeRoot "source-v4.hse2"
@($primaryPassword, $primaryPassword, $secondaryPassword, $secondaryPassword) |
    & $exe hse2 v4-create --passwords-stdin --output $v4Container --capacity-records 2 `
        --primary-file "primary.txt=$legacyPrimary" --secondary-file "secondary.txt=$legacySecondary"
if ($LASTEXITCODE -ne 0) { throw "Packaged v4-create migration fixture failed" }
$v4SourceDigest = (Get-FileHash -LiteralPath $v4Container -Algorithm SHA256).Hash
$migrated = Join-Path $smokeRoot "migrated-v5.hse2"
@($primaryPassword, $secondaryPassword) |
    & $exe hse2 v4-to-v5 --passwords-stdin --input $v4Container --output $migrated --profile compatible
if ($LASTEXITCODE -ne 0) { throw "Packaged v4-to-v5 smoke failed" }
if ((Get-FileHash -LiteralPath $v4Container -Algorithm SHA256).Hash -ne $v4SourceDigest) {
    throw "Packaged v4-to-v5 changed its v4 source"
}
foreach ($view in @(
    @{ Name = "primary"; Expected = $legacyPrimary },
    @{ Name = "secondary"; Expected = $legacySecondary }
)) {
    $restored = Join-Path $smokeRoot ("migrated-" + $view.Name + "-restored")
    $viewPassword = if ($view.Name -eq "primary") { $primaryPassword } else { $secondaryPassword }
    $viewPassword | & $exe hse2 v5-open --password-stdin --input $migrated --output-dir $restored
    if ($LASTEXITCODE -ne 0) { throw "Packaged v4-to-v5 $($view.Name)-open smoke failed" }
    if ((Get-FileHash -LiteralPath (Join-Path $restored ($view.Name + ".txt"))).Hash -ne
        (Get-FileHash -LiteralPath $view.Expected).Hash) {
        throw "Packaged v4-to-v5 $($view.Name) bytes differ"
    }
}

if ((Get-FileHash -LiteralPath $v5Container -Algorithm SHA256).Hash -ne $v5SourceDigest) {
    throw "Packaged v5 maintenance changed the original v5 source"
}
