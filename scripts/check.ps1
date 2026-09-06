[CmdletBinding()]
param(
    [ValidateSet('all', 'test', 'race', 'vet', 'fuzz', 'build', 'format')]
    [string[]]$Check = @('all'),
    [string]$GoBin,
    [string]$CCompiler,
    [string]$CacheRoot = (Join-Path ([System.IO.Path]::GetTempPath()) 'proxy-gateway-go'),
    [string[]]$Packages = @('./...'),
    [string]$Run = '',
    [switch]$VerboseTests
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    if ($GoBin) {
        $resolvedGoBin = (Resolve-Path -LiteralPath $GoBin).Path
        $env:PATH = $resolvedGoBin + [System.IO.Path]::PathSeparator + $env:PATH
    }
    if ($CCompiler) {
        $env:CC = (Resolve-Path -LiteralPath $CCompiler).Path
        $env:PATH = (Split-Path -Parent $env:CC) + [System.IO.Path]::PathSeparator + $env:PATH
    }
    $goCommand = (Get-Command go -CommandType Application -ErrorAction Stop).Source
    $env:CGO_ENABLED = '1'
    $env:GOTOOLCHAIN = 'local'
    $env:GOMODCACHE = Join-Path $CacheRoot 'mod'
    $env:GOCACHE = Join-Path $CacheRoot 'build'

    function Invoke-GoCheck {
        param([string[]]$Arguments)
        & $goCommand @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Go check failed with exit code $LASTEXITCODE."
        }
    }

    Invoke-GoCheck -Arguments @('version')
    $steps = $Check
    if ($steps -contains 'all') {
        $steps = @('test', 'race', 'vet', 'fuzz', 'build', 'format')
    }
    foreach ($step in $steps) {
        Write-Host "Running $step"
        switch ($step) {
            { $_ -in 'test', 'race' } {
                $testArguments = @('test', '-count=1', '-timeout=3m')
                if ($step -eq 'race') { $testArguments += '-race' }
                if ($VerboseTests) { $testArguments += '-v' }
                if ($Run) { $testArguments += @('-run', $Run) }
                Invoke-GoCheck -Arguments ($testArguments + $Packages)
            }
            'vet' { Invoke-GoCheck -Arguments (@('vet') + $Packages) }
            'fuzz' {
                Invoke-GoCheck -Arguments @('test', './internal/trojan', '-run=^$', '-fuzz=FuzzParseRequest', '-fuzztime=30s', '-parallel=2')
            }
            'build' {
                [System.IO.Directory]::CreateDirectory((Join-Path $projectRoot 'build')) | Out-Null
                Invoke-GoCheck -Arguments @('build', '-trimpath', '-o', 'build/proxy-gateway.exe', './cmd/gateway')
            }
            'format' {
                $gofmtCommand = Join-Path (Split-Path -Parent $goCommand) 'gofmt.exe'
                $unformatted = & $gofmtCommand -l cmd internal test
                if ($LASTEXITCODE -ne 0 -or $unformatted) {
                    throw "Go formatting check failed: $unformatted"
                }
            }
        }
    }
} finally {
    Pop-Location
}
