# Clones StormLib at a pinned tag and builds StormLib.dll (x64, Release) with the CMake bundled in Visual Studio.
# Output: tools/.stormlib/build/Release/StormLib.dll
param(
    [string]$Tag = 'v9.40'
)

$ErrorActionPreference = 'Stop'

$root = Join-Path $PSScriptRoot '.stormlib'
$src = Join-Path $root 'src'
$build = Join-Path $root 'build'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found: $vswhere" }
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio with C++ tools not found.' }
$cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if (-not (Test-Path $cmake)) { throw "CMake not found: $cmake" }

if (-not (Test-Path $src)) {
    git clone --depth 1 --branch $Tag https://github.com/ladislav-zezula/StormLib.git $src
    if ($LASTEXITCODE -ne 0) { throw "git clone failed ($LASTEXITCODE)" }
}

& $cmake -S $src -B $build -A x64 -DBUILD_SHARED_LIBS=ON -DSTORM_SKIP_INSTALL=ON
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($LASTEXITCODE)" }

& $cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($LASTEXITCODE)" }

$dll = Join-Path $build 'Release\StormLib.dll'
if (-not (Test-Path $dll)) { throw "StormLib.dll not produced: $dll" }
Write-Output $dll
