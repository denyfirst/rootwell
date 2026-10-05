$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This check requires Windows.' }
$fixture = (& go run ./scripts/generate-browser-pfx-fixture.go | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Synthetic fixture generation failed.' }
$pfxBytes = [Convert]::FromBase64String($fixture.encrypted_input_pfx)
$certificate = $null
try {
    # Ephemeral import exercises the Windows parser without writing a key store.
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxBytes, $fixture.password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    if (-not $certificate.HasPrivateKey) { throw 'Windows did not import the matching key.' }
    $pem = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($fixture.certificate))
    $expectedDER = [Convert]::FromBase64String(($pem -replace '-----[^-]+-----', '' -replace '\s', ''))
    if ([Convert]::ToBase64String($certificate.RawData) -ne [Convert]::ToBase64String($expectedDER)) {
        throw 'Windows imported a different certificate.'
    }
    Write-Output 'Windows ephemeral PFX import from an encrypted input key passed.'
} finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
    [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
    $fixture = $null
}
