param([switch]$AllowDirty,[switch]$VerifyMain)
$ErrorActionPreference = 'Stop'
function Invoke-GuardProcess([string]$Executable, [string[]]$Arguments) {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Unsupported preflight argument' }
        if ($argument -match '\s') { '"' + $argument + '"' } else { $argument }
    }
    $start.Arguments = [string]::Join(' ', [string[]]$quoted)
    $start.WorkingDirectory = (Get-Location).Path
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (!$process.Start()) { throw 'Preflight process did not start' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $script:guardExitCode = $process.ExitCode
    $process.Dispose()
    if ($stderr.Result) { [Console]::Error.Write($stderr.Result) }
    return $stdout.Result
}
foreach ($candidate in @('python3', 'python', 'py')) {
    $executable = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($executable -and $executable.Source -notmatch 'WindowsApps') {
        $guardArguments = @((Join-Path $PSScriptRoot 'guard.py'), 'start')
        if ($AllowDirty) { $guardArguments += '--allow-dirty' }
        if ($VerifyMain) { $guardArguments += '--verify-main' }
        Write-Output (Invoke-GuardProcess $executable.Source $guardArguments)
        exit $script:guardExitCode
    }
}
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if ($wsl) {
    # WSL Python is also supported when Windows has no native Python install.
    $windowsRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $linuxRoot = Invoke-GuardProcess $wsl.Source @('--exec', 'wslpath', '-u', $windowsRoot)
    if ($script:guardExitCode -ne 0) { throw 'Cannot map the checkout to WSL' }
    $linuxDirectory = Invoke-GuardProcess $wsl.Source @('--exec', 'wslpath', '-u', (Get-Location).Path)
    if ($script:guardExitCode -ne 0) { throw 'Cannot map the current directory to WSL' }
    $wslArguments = @('--cd', $linuxDirectory.Trim(), '--exec', 'python3', ($linuxRoot.Trim() + '/scripts/dev/guard.py'), 'start')
    if ($AllowDirty) { $wslArguments += '--allow-dirty' }
    if ($VerifyMain) { $wslArguments += '--verify-main' }
    Write-Output (Invoke-GuardProcess $wsl.Source $wslArguments)
    exit $script:guardExitCode
}
throw 'Splicore preflight requires Python 3.9+ (native, or in WSL) on PATH.'
