param([switch]$Check)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$target = [System.IO.Path]::GetFullPath((Join-Path $root 'AliyunCDT.scripting'))
if (-not $target.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Package target must stay inside the project'
}
$files = @('script.json', 'index.tsx', 'widget.tsx', 'app_intents.tsx', 'aliyun.ts', 'config.ts', 'medium_widget.tsx', 'monitor_runtime.ts', 'bill_queries.ts')
$utf8 = [System.Text.UTF8Encoding]::new($false)
function Get-SourceBytes([string]$name) {
    $text = [System.IO.File]::ReadAllText((Join-Path $root $name)).Replace("`r`n", "`n")
    return ,$utf8.GetBytes($text)
}

if (-not $Check) {
    $stream = [System.IO.File]::Open($target, [System.IO.FileMode]::Create)
    $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $files) {
            $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $content = Get-SourceBytes $name
            $output = $entry.Open()
            try { $output.Write($content, 0, $content.Length) } finally { $output.Dispose() }
        }
    } finally {
        $archive.Dispose()
        $stream.Dispose()
    }
}

$archive = [System.IO.Compression.ZipFile]::OpenRead($target)
try {
    if ($archive.Entries.Count -ne $files.Count) { throw 'Unexpected package entry count' }
    foreach ($name in $files) {
        $entry = $archive.GetEntry($name)
        if ($null -eq $entry) { throw "Missing package entry: $name" }
        $input = $entry.Open()
        $buffer = [System.IO.MemoryStream]::new()
        try {
            $input.CopyTo($buffer)
            $expected = Get-SourceBytes $name
            if ([Convert]::ToBase64String($buffer.ToArray()) -cne [Convert]::ToBase64String($expected)) {
                throw "Package source is out of date: $name"
            }
        } finally {
            $input.Dispose()
            $buffer.Dispose()
        }
    }
} finally { $archive.Dispose() }
Write-Output "Package matches all $($files.Count) source entries"
