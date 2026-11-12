param(
    [Parameter(Mandatory=$true)][string]$Output,
    [ValidateSet('ci','baseline','matrix','soak')][string]$Profile='ci',
    [ValidateSet('native','wireguard')][string]$Suite='native',
    [ValidateRange(1,1000000)][int]$Repeat=1,
    [ValidateSet(0,24,72)][int]$SoakHours=0
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$out=[IO.Path]::GetFullPath($Output)
if ($out -eq $root -or $out.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Output must be outside the source tree' }
New-Item -ItemType Directory -Force $out | Out-Null
if (@(Get-ChildItem -LiteralPath $out -Force).Count) {throw 'Use a fresh output directory; existing evidence is preserved'}
$utf8=New-Object Text.UTF8Encoding($false)
function Save-Json($Path,$Value) { [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30)+"`n",$utf8) }
Push-Location $root
try {
    $goOS=(& go env GOOS).Trim(); $goArch=(& go env GOARCH).Trim()
    if ($LASTEXITCODE -ne 0 -or $goOS -ne 'windows' -or [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'A native Windows Go toolchain and host are required' }
    $env:CGO_ENABLED='0'; $env:GOTOOLCHAIN='local'; $env:GOFLAGS='-mod=readonly'; $env:GOTELEMETRY='off'
    $env:TEMP=Join-Path $out 'runtime';$env:TMP=$env:TEMP;$env:GOTMPDIR=$env:TEMP
    New-Item -ItemType Directory -Force $env:TEMP | Out-Null
    Save-Json (Join-Path $out 'environment.json') @{
        commit=(& git rev-parse HEAD);status=(& git status --short);go=(& go version);goarch=$goArch;
        os=[Environment]::OSVersion.ToString();processor=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors);
        native=$true;profile=$Profile;suite=$Suite;command=[Environment]::CommandLine;classification='BASELINE';slo='NONE';
        network='unmodified native Windows loopback; no netem, MTU or WAN qualification'
    }
    $binary=Join-Path $out ($Suite+'-perf.exe')
    $package='./internal/splicore/engine/native';$test='TestP2NetworkBaseline'
    if ($Suite -eq 'wireguard') {$package='./internal/splicore/wireguardendpoint';$test='TestP2WireGuardBaseline'}
    & go test -c -mod=readonly '-tags=with_quic,with_utls,with_gvisor' -o $binary $package 2>&1 | Out-File (Join-Path $out 'build.log') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows benchmark build failed' }
    $profiles=Get-Content (Join-Path $PSScriptRoot 'profiles.json') -Raw | ConvertFrom-Json
    $scenarios=@()
    foreach ($row in $profiles.profiles.$Profile) {
        if ($Suite -eq 'wireguard' -and $row.protocol -ne 'vless-tcp') {continue}
        $scenario=[ordered]@{}
        foreach ($property in $profiles.defaults.PSObject.Properties) {$scenario[$property.Name]=$property.Value}
        foreach ($property in $row.PSObject.Properties) {$scenario[$property.Name]=$property.Value}
        if ($Suite -eq 'wireguard') {$scenario['protocol']='wireguard';$scenario['name']='wireguard'+$scenario['name'].Substring(9)}
        $scenarios+=$scenario
    }
    $deadline=[DateTime]::UtcNow.AddHours($SoakHours);$iteration=0;$runs=@();$failed=$false
    do {
        $stem='{0:D5}-clean' -f $iteration
        $config=Join-Path $out ($stem+'-config.json');Save-Json $config $scenarios
        $env:SPLICORE_PERF_CONFIG=$config;$env:SPLICORE_PERF_RAW=Join-Path $out ($stem+'-raw.jsonl')
        $stamp=[DateTime]::UtcNow
        & $binary -test.v "-test.run=^$test`$" -test.timeout=30m 2>&1 | Out-File (Join-Path $out ($stem+'-test.log')) -Encoding utf8
        $code=$LASTEXITCODE
        $rows=@(Get-Content $env:SPLICORE_PERF_RAW | ForEach-Object {$_|ConvertFrom-Json})
        $runs+=@{name=$stem;exit_code=$code;elapsed_seconds=([DateTime]::UtcNow-$stamp).TotalSeconds;
                 measured_connections=@($rows|Where-Object {$_.kind -eq 'connection'}).Count;
                 scenario_outcomes=@($rows|Where-Object {$_.kind -eq 'outcome'});
                 raw=$env:SPLICORE_PERF_RAW}
        if ($code -ne 0) {$failed=$true}
        $iteration++
        Save-Json (Join-Path $out 'summary.json') @{classification=$(if ($failed){'FAIL'}else{'BASELINE'});runs=$runs;
            soak_requested_hours=$SoakHours;soak_status=$(if ($SoakHours -and [DateTime]::UtcNow -ge $deadline){'EXECUTED'}else{'NOT EXECUTED'})}
        Write-Output "$stem exit=$code"
    } while (!$failed -and $(if($SoakHours){[DateTime]::UtcNow -lt $deadline}else{$iteration -lt $Repeat}))
    if ($failed) { throw 'Native Windows benchmark failed; raw evidence retained' }
} finally { Pop-Location }
