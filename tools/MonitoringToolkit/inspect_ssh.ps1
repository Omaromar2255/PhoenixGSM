try {
    $asm = [System.Reflection.Assembly]::LoadFrom("C:\SKAPPLE_PRO\SK APPLE PRO.exe")
    $mod = $asm.ManifestModule
    $field = [System.Reflection.BindingFlags]'NonPublic,Instance'
    # Read user strings by checking tokens in 0x70000000 range
    Write-Host "Scanning UserStrings heap..."
    $results = @()
    for ($i = 1; $i -lt 50000; $i++) {
        $token = 0x70000000 -bor $i
        try {
            $s = $mod.ResolveString($token)
            if ($s -and ($s -match 'alpine|root|2222|mount_apfs|iproxy|mnt1|mnt2|seputil|FairPlay|data_ark|commcenter|activation_record|IC-Info|plutil|chflags|launchctl')) {
                $results += $s
            }
        } catch {
            # reached end of table
            if ($i -gt 1000 -and $results.Count -eq 0) { break }
        }
    }
    Write-Host "Found $($results.Count) matching strings:"
    $results | Select-Object -Unique -First 40 | ForEach-Object { Write-Host "  - $_" }
} catch {
    Write-Host "ERROR: $_"
}
