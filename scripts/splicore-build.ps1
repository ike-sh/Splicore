param(
    [string]$Output = (Join-Path ([IO.Path]::GetTempPath()) 'splicore.exe'),
    [string]$ProductVersion = 'devel',
    [string]$BuildTime = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
)
$ErrorActionPreference = 'Stop'
if ($ProductVersion -notmatch '^[A-Za-z0-9.+-]+$' -or $BuildTime -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
    throw 'Invalid version or UTC build timestamp'
}
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $goVersion = (& go env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go(\d+)\.(\d+)(?:\.(\d+))?$') { throw 'Cannot identify Go toolchain' }
    $goMinimum = [version]'1.26.3'
    $goActual = [version]($goVersion.Substring(2))
    if ($goActual -lt $goMinimum) { throw 'Splicore requires Go 1.26.3 or newer' }
    $commit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot identify Git source' }
    $dirty = if ((& git status --porcelain)) { 'true' } else { 'false' }
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect source status' }
    $versionPackage = 'github.com/sagernet/sing-box/internal/splicore/version'
    $linkFlags = "-X $versionPackage.ProductVersion=$ProductVersion -X $versionPackage.Commit=$commit -X $versionPackage.Dirty=$dirty -X $versionPackage.BuildTime=$BuildTime"
    & go build -trimpath -ldflags $linkFlags -o $Output ./cmd/splicore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
