param(
    [Parameter(Mandatory = $true)] [string] $Executable,
    [Parameter(Mandatory = $true)] [string] $Destination
)

$ErrorActionPreference = 'Stop'
$binary = Get-Item -LiteralPath $Executable
if ($binary.Name -ne 'pw-2FA-passkeys.exe') {
    throw 'Supply the path to the built pw-2FA-passkeys.exe.'
}

$assets = Join-Path $Destination 'Assets'
New-Item -ItemType Directory -Path $assets -Force | Out-Null
Copy-Item -LiteralPath $binary.FullName -Destination $Destination
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Destination $Destination

Add-Type -AssemblyName System.Drawing
$icon = [Drawing.SystemIcons]::Application.ToBitmap()
try {
    foreach ($asset in @{ 'Store.png' = 50; 'Tile.png' = 150; 'App.png' = 44 }.GetEnumerator()) {
        $bitmap = [Drawing.Bitmap]::new($icon, $asset.Value, $asset.Value)
        try {
            $bitmap.Save((Join-Path $assets $asset.Key), [Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $bitmap.Dispose()
        }
    }
} finally {
    $icon.Dispose()
}

Get-Item -LiteralPath (Join-Path $Destination 'AppxManifest.xml')
