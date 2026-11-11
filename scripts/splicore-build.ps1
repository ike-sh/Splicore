param(
    [ValidateSet('build','test','vet','clean')][string]$Action = 'build',
    [string]$Output = '',
    [string]$ProductVersion = 'devel',
    [string]$BuildTime = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')),
    [string]$TargetOS = 'windows',
    [string]$TargetArch = 'amd64',
    [string]$Commit = '',
    [ValidateSet('','true','false')][string]$SourceDirty = '',
    [string]$Go = 'go'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $projectRoot 'build'

function Invoke-Native([string]$Executable, [string[]]$NativeArguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $quoted = foreach ($arg in $NativeArguments) {
        if ($arg.Contains('"') -or $arg.EndsWith('\')) { throw 'Unsupported native build argument' }
        if ($arg -match '\s') { '"' + $arg + '"' } else { $arg }
    }
    $psi.Arguments = [string]::Join(' ', [string[]]$quoted)
    $psi.WorkingDirectory = $projectRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    if (!$process.Start()) { throw 'Native build tool did not start' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $global:LASTEXITCODE = $process.ExitCode
    $outText = $stdout.Result
    $errText = $stderr.Result
    $process.Dispose()
    if ($errText) { [Console]::Error.Write($errText) }
    if ($global:LASTEXITCODE -ne 0) {
        if ($outText) { [Console]::Error.Write($outText) }
        throw "Native build tool failed: exit $global:LASTEXITCODE"
    }
    return $outText
}

if ($Action -eq 'clean') {
    if (Test-Path -LiteralPath $buildRoot) { Remove-Item -LiteralPath $buildRoot -Recurse -Force }
    exit 0
}
if ("$TargetOS/$TargetArch" -notin @('windows/amd64','windows/arm64','linux/amd64','linux/arm64')) { throw 'Unsupported build target' }
if ($ProductVersion -notmatch '^[A-Za-z0-9.+-]+$' -or $BuildTime -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { throw 'Invalid build metadata' }
$tags = 'with_quic,with_utls,with_gvisor'
if (!$Output) {
    $name = if ($TargetOS -eq 'windows') { 'splicore.exe' } else { 'splicore' }
    $Output = Join-Path (Join-Path $buildRoot "$TargetOS-$TargetArch") $name
}
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) {
    if (!(Test-Path -LiteralPath ($Output + '.sha256'))) { throw 'Refusing to overwrite an untracked build output' }
    $expected = (Get-Content -LiteralPath ($Output + '.sha256') -Raw).Trim()
    if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or $expected -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash) { throw 'Existing output differs from the recorded build hash' }
}
$overrides = @{
    GOENV='off'; GOTOOLCHAIN='local'; GOTELEMETRY='off'; CGO_ENABLED='0'; GOOS=$TargetOS; GOARCH=$TargetArch;
    GOTMPDIR=(Join-Path $buildRoot 'tmp'); TMP=(Join-Path $buildRoot 'tmp'); TEMP=(Join-Path $buildRoot 'tmp')
}
foreach ($key in @('GOCACHE','GOMODCACHE','GOPATH')) {
    $existing = [Environment]::GetEnvironmentVariable($key, 'Process')
    $overrides[$key] = if ($existing) { $existing } else { Join-Path $buildRoot $key.ToLowerInvariant() }
}
$prior = @{}
foreach ($key in $overrides.Keys) { $prior[$key] = [Environment]::GetEnvironmentVariable($key,'Process') }
Push-Location $projectRoot
try {
    foreach ($key in $overrides.Keys) { [Environment]::SetEnvironmentVariable($key,$overrides[$key],'Process') }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output),$overrides.GOTMPDIR | Out-Null
    $goVersion = (Invoke-Native $Go @('env','GOVERSION')).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go\d+\.\d+\.\d+$' -or [version]$goVersion.Substring(2) -lt [version]'1.26.3') { throw 'Splicore requires Go 1.26.3 or newer' }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (!$Commit) {
        if (!$git) { throw 'Git is required, or supply the verified source -Commit and -SourceDirty explicitly' }
        $Commit = (Invoke-Native $git.Source @('rev-parse','HEAD')).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source commit' }
    }
    if ($Commit -notmatch '^[0-9a-f]{40}$') { throw 'Invalid source commit' }
    if (!$SourceDirty) {
        if ($git) {
            $changes = Invoke-Native $git.Source @('status','--porcelain')
            if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect worktree' }
            $SourceDirty = if ($changes) { 'true' } else { 'false' }
        } else { $SourceDirty = 'true' }
    }
    $vp = 'github.com/ike-sh/Splicore/internal/splicore/version'
    $flags = "-X=$vp.ProductVersion=$ProductVersion -X=$vp.Commit=$Commit -X=$vp.Dirty=$SourceDirty -X=$vp.BuildTime=$BuildTime -X=$vp.BuildTags=$tags"
    Write-Output (Invoke-Native $Go @('build','-mod=readonly','-trimpath',"-tags=$tags","-ldflags=$flags",'-o',$Output,'./cmd/splicore'))
    if ($LASTEXITCODE -ne 0) { throw 'Core build failed' }
    [IO.File]::WriteAllText(($Output + '.sha256'), ((Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash.ToLowerInvariant() + "`n"))
    Write-Output "Built $Output ($TargetOS/$TargetArch, CGO=0, commit=$Commit, dirty=$SourceDirty)"
    if ($Action -ne 'build') {
        $hostOS = (Invoke-Native $Go @('env','GOHOSTOS')).Trim(); $hostArch = (Invoke-Native $Go @('env','GOHOSTARCH')).Trim()
        if ($TargetOS -ne $hostOS -or $TargetArch -ne $hostArch) { throw 'Tests/vet require a native target' }
        if ($Action -eq 'test') {
            $previousBinary = $env:SPLICORE_RUNTIME_BINARY
            try {
                $env:SPLICORE_RUNTIME_BINARY = $Output
                Write-Output (Invoke-Native $Go @('test','-mod=readonly','-count=1','-timeout=1200s','-p=1',"-tags=$tags",'./...'))
                if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
            } finally { $env:SPLICORE_RUNTIME_BINARY = $previousBinary }
        } else {
            Write-Output (Invoke-Native $Go @('vet','-mod=readonly',"-tags=$tags",'./...'))
            if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
        }
    }
} finally {
    foreach ($key in $prior.Keys) { [Environment]::SetEnvironmentVariable($key,$prior[$key],'Process') }
    Pop-Location
}
