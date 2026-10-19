# Output encryption is independent of source and diagnostic authority.
function Assert-EpbOutputFile([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer) { throw 'Output must be a regular file.' }
  $cursor = $item
  while ($null -ne $cursor) {
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Output reparse paths are forbidden.' }
    $cursor = if ($cursor -is [IO.DirectoryInfo]) { $cursor.Parent } else { $cursor.Directory }
  }
  return $item
}
function Assert-EpbOutputManifest($Manifest) {
  $keys = 'assets,builder,notes,project,revision,run,run_attempt,source,tag,title,version'
  if ((@($Manifest.PSObject.Properties.Name | Sort-Object) -join ',') -cne $keys -or $Manifest.version -ne 1 -or
      [string]$Manifest.project -cnotmatch '^p[0-9a-f]{32}$' -or [string]$Manifest.revision -cnotmatch '^[0-9a-f]{32}$' -or
      [string]$Manifest.builder -cnotmatch '^[0-9a-f]{40}$' -or [string]$Manifest.source -cnotmatch '^[0-9a-f]{40}$' -or
      [string]$Manifest.run -cnotmatch '^[1-9][0-9]{0,18}$' -or [string]$Manifest.run_attempt -cnotmatch '^[1-9][0-9]{0,8}$' -or
      [string]$Manifest.tag -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$' -or
      [string]::IsNullOrWhiteSpace([string]$Manifest.title) -or ([string]$Manifest.title).Length -gt 256 -or
      ([string]$Manifest.notes).Length -gt 32768) { throw 'Output manifest identity is invalid.' }
  $assets = @($Manifest.assets)
  if ($assets.Count -lt 1 -or $assets.Count -gt 64) { throw 'Output asset inventory is outside the bounded profile.' }
  $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [int64]$total = 0
  foreach ($asset in $assets) {
    if ((@($asset.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'bytes,name,sha256' -or
        [string]$asset.name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$' -or ($asset.name -ieq 'manifest.json' -or $asset.name -match '^(?i:CON|NUL|AUX|PRN|COM[1-9]|LPT[1-9])(?:\.|$)' -or $asset.name.EndsWith('.')) -or
        -not $names.Add([string]$asset.name) -or [int64]$asset.bytes -le 0 -or [string]$asset.sha256 -cnotmatch '^[0-9a-f]{64}$') {
      throw 'Output asset declaration is invalid.'
    }
    $total += [int64]$asset.bytes
    if ($total -gt 512MB) { throw 'Output exceeds the supported 512 MiB profile; use the approved large-file path.' }
  }
}
function New-EpbOutputStage {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Tag,[Parameter(Mandatory)][string]$SourceSha,
    [Parameter(Mandatory)][string[]]$Assets,[Parameter(Mandatory)][string]$Title,[Parameter(Mandatory)][string]$Notes)
  if ($env:OUTPUT_MODE -cne 'handoff') { throw 'Encrypted output handoff is not enabled.' }
  $root = Join-Path $env:RUNNER_TEMP "epb-$env:PROJECT_ID/output-stage"
  if (Test-Path -LiteralPath $root) { throw 'Output staging already exists.' }
  $inventory = @(); $files = @()
  foreach ($path in $Assets) {
    $item = Assert-EpbOutputFile $path
    $files += $item
    $inventory += [pscustomobject][ordered]@{name=$item.Name;bytes=[int64]$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  $manifest = [pscustomobject][ordered]@{version=1;source=$SourceSha;builder=$env:BUILDER_SHA;project=$env:PROJECT_ID;revision=$env:PROJECT_REV;run=$env:GITHUB_RUN_ID;run_attempt=$env:GITHUB_RUN_ATTEMPT;tag=$Tag;title=$Title;notes=$Notes;assets=$inventory}
  Assert-EpbOutputManifest $manifest
  [void][IO.Directory]::CreateDirectory($root)
  foreach ($file in $files) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $root $file.Name) }
  $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Encoding utf8NoBOM
}
function Protect-EpbOutputStage {
  param([string]$Stage,[string]$Destination,[string]$Secret,[string]$Project,[string]$Revision,[ref]$Ownership)
  if ($null -ne $Ownership) { $Ownership.Value=$false }
  $manifestFile = Assert-EpbOutputFile (Join-Path $Stage 'manifest.json')
  if ($manifestFile.Length -gt 64KB) { throw 'Output manifest exceeds its bound.' }
  $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw | ConvertFrom-Json
  Assert-EpbOutputManifest $manifest
  if ($manifest.project -cne $Project -or $manifest.revision -cne $Revision) { throw 'Output stage identity mismatch.' }
  $expected = @('manifest.json') + @($manifest.assets | ForEach-Object { $_.name })
  $actual = @(Get-ChildItem -LiteralPath $Stage -Force | ForEach-Object { $_.Name } | Sort-Object)
  if (($actual -join ',') -cne (@($expected | Sort-Object) -join ',')) { throw 'Output staging contains undeclared files.' }
  foreach ($asset in $manifest.assets) {
    $file = Assert-EpbOutputFile (Join-Path $Stage $asset.name)
    if ($file.Length -ne $asset.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $asset.sha256) { throw 'Output asset changed after staging.' }
  }
  if (Test-Path -LiteralPath $Destination) { throw 'Output ciphertext destination already exists.' }
  $Destination=[IO.Path]::GetFullPath($Destination)
  $parent=[IO.Path]::GetDirectoryName($Destination)
  $cursor=Get-Item -LiteralPath $parent -Force
  while ($null -ne $cursor) {
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Output destination parent is a reparse path.' }
    $cursor=$cursor.Parent
  }
  $claim=Join-Path $parent ('output-claim-'+[Guid]::NewGuid().ToString('N'))
  if (Test-Path -LiteralPath $claim) { throw 'Output claim already exists.' }
  [void][IO.Directory]::CreateDirectory($claim)
  try {
    # Moving an owned new directory fails if another producer claimed the target.
    # Both resolved paths remain in this one verified parent.
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($claim)) -cne $parent) { throw 'Output claim escaped its parent.' }
    [IO.Directory]::Move($claim,$Destination)
    if ($null -ne $Ownership) { $Ownership.Value=$true }
  } finally {
    if ([IO.Directory]::Exists($claim)) { [IO.Directory]::Delete($claim,$false) }
  }
  $archive = Join-Path (Split-Path -Parent $Stage) 'output.zip'
  $cipher = Join-Path (Split-Path -Parent $Stage) 'output.bin'
  try {
    Add-Type -AssemblyName System.IO.Compression
    [IO.Compression.ZipFile]::CreateFromDirectory($Stage,$archive,[IO.Compression.CompressionLevel]::NoCompression,$false)
    if ((Get-Item -LiteralPath $archive).Length -gt 512MB) { throw 'Output archive exceeds the supported 512 MiB envelope profile.' }
    Write-EpbAuthenticatedEnvelope -InputPath $archive -OutputPath $cipher -Secret $Secret -ProjectId $Project -Revision $Revision
    $input = [IO.File]::OpenRead($cipher)
    try {
      $buffer = New-Object byte[] 1048576
      $index = 0
      while ($input.Position -lt $input.Length) {
        $part = [IO.File]::Open((Join-Path $Destination ('output.part.{0:d4}' -f $index)),[IO.FileMode]::CreateNew)
        try {
          [int64]$left = [Math]::Min(50000000,$input.Length-$input.Position)
          while ($left -gt 0) { $read = $input.Read($buffer,0,[int][Math]::Min($buffer.Length,$left)); if ($read -le 0) { throw 'Output ciphertext read failed.' }; $part.Write($buffer,0,$read); $left -= $read }
        } finally { $part.Dispose() }
        $index++
      }
    } finally { $input.Dispose() }
  } finally {
    foreach ($path in @($archive,$cipher)) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }
  }
}
