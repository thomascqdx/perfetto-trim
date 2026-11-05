# Build dist\pftrim.exe (single file, console) with PyInstaller from .venv.
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root ".venv\Scripts\python.exe"
$src = Join-Path $root "src"
$build = Join-Path $root "build"
New-Item -ItemType Directory -Force $build | Out-Null

$ver = & $py -c "import sys; sys.path.insert(0, r'$src'); import pftrim; print(pftrim.__version__)"
$parts = ($ver.Split(".") + @("0", "0", "0", "0"))[0..3] -join ", "
$vf = Join-Path $build "version_info.txt"
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($parts), prodvers=($parts),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('080404b0', [
      StringStruct('CompanyName', 'sagereal'),
      StringStruct('FileDescription', 'Perfetto Trim'),
      StringStruct('FileVersion', '$ver'),
      StringStruct('InternalName', 'pftrim'),
      StringStruct('OriginalFilename', 'pftrim.exe'),
      StringStruct('ProductName', 'Perfetto Trim'),
      StringStruct('ProductVersion', '$ver')])]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
"@ | Set-Content -Encoding UTF8 $vf

& $py -m PyInstaller --noconfirm --clean --onefile --console `
    --name pftrim `
    --paths $src `
    --add-data "$src\pftrim\web\static;pftrim\web\static" `
    --hidden-import tkinter --hidden-import tkinter.filedialog `
    --version-file $vf `
    --distpath (Join-Path $root "dist") `
    --workpath $build `
    --specpath $build `
    (Join-Path $root "scripts\pftrim_entry.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }
Write-Host "built dist\pftrim.exe ($ver)"
