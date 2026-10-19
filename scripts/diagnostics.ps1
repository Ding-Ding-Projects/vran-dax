[CmdletBinding()]
param([ValidateSet('Functions','Collect')][string]$Mode='Functions',
  [scriptblock]$TrustedCrypto,[scriptblock]$TrustedPolicy)

function Get-EpbDiagnosticContext([string]$Project,[string]$Revision,[string]$BuilderSha,[string]$RunId,[string]$Attempt) {
  if($Project -cnotmatch '^p[0-9a-f]{32}$' -or $Revision -cnotmatch '^[0-9a-f]{32}$' -or
    $BuilderSha -cnotmatch '^[0-9a-f]{40}$' -or $RunId -cnotmatch '^[1-9][0-9]{0,19}$' -or $Attempt -cnotmatch '^[1-9][0-9]{0,8}$') {
    throw 'Diagnostic context is invalid.'
  }
  "EPB-DIAGNOSTICS-v1`n$Project`n$Revision`n$BuilderSha`n$RunId`n$Attempt"
}
function Get-EpbDiagnosticKey([string]$Secret,[string]$Context) {
  [byte[]]$key=[Convert]::FromBase64String($Secret)
  if($key.Length -ne 32){throw 'Diagnostic authority is invalid.'}
  $mac=[Security.Cryptography.HMACSHA256]::new($key)
  try {[Convert]::ToBase64String($mac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Context)))}
  finally{$mac.Dispose();[Array]::Clear($key,0,$key.Length)}
}
function Assert-EpbDiagnosticRegularPath([string]$Path) {
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer){throw 'Diagnostic input is not a regular file.'}
  $cursor=$item
  while($null -ne $cursor){
    if(($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Diagnostic reparse paths are forbidden.'}
    $cursor=if($cursor -is [IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}
  }
}
function Assert-EpbDiagnosticDirectoryParent([string]$Path) {
  $cursor=[IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
  while($null -ne $cursor){
    if($cursor.Exists -and ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Diagnostic reparse directories are forbidden.'}
    $cursor=$cursor.Parent
  }
}
function Write-EpbDiagnosticEnvelope {
  param([string]$LogPath,[string]$OutputPath,[string]$Secret,$Policy,[string]$BuilderSha,[string]$RunId,[string]$Attempt)
  Assert-EpbDiagnosticPolicy $Policy
  if(-not $Policy.enabled){return $false}
  $context=Get-EpbDiagnosticContext $Policy.project $Policy.revision $BuilderSha $RunId $Attempt
  Assert-EpbDiagnosticRegularPath $LogPath
  Assert-EpbDiagnosticDirectoryParent (Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath)))
  $plain=$OutputPath+'.'+[Guid]::NewGuid().ToString('N')+'.plain'
  $input=$null;$output=$null;$derived=$null
  [byte[]]$buffer=New-Object byte[] 65536
  $oldLimit=$script:EpbEnvelopeMaxPlaintextBytes;$oldEnvelope=$script:EpbEnvelopeMaxBytes
  try {
    $input=[IO.File]::Open($LogPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    [long]$total=$input.Length;[long]$tail=[Math]::Min($total,1048576)
    $metadata=[ordered]@{version=1;project=$Policy.project;revision=$Policy.revision;builder_sha=$BuilderSha;run_id=$RunId;attempt=$Attempt;source_commit=$Policy.source_commit;archive_sha256=$Policy.archive_sha256;conclusion='failure';original_bytes=$total;tail_bytes=$tail;truncated=($total -gt $tail)}
    [byte[]]$json=[Text.Encoding]::UTF8.GetBytes(($metadata|ConvertTo-Json -Compress))
    if($json.Length -gt 8192){throw 'Diagnostic metadata exceeds its bound.'}
    $output=[IO.File]::Open($plain,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $length=ConvertTo-EpbUInt32BigEndian ([uint32]$json.Length)
    $output.Write($length,0,4);$output.Write($json,0,$json.Length)
    $input.Position=$total-$tail
    while(($read=$input.Read($buffer,0,[int][Math]::Min($buffer.Length,$tail))) -gt 0){$output.Write($buffer,0,$read);$tail-=$read}
    if($tail -ne 0){throw 'Diagnostic input changed.'}
    $output.Dispose();$output=$null;$input.Dispose();$input=$null
    $script:EpbEnvelopeMaxPlaintextBytes=[long]1056772;$script:EpbEnvelopeMaxBytes=[long]1056861
    $derived=Get-EpbDiagnosticKey $Secret $context
    Write-EpbAuthenticatedEnvelope -InputPath $plain -OutputPath $OutputPath -Secret $derived -ProjectId $Policy.project -Revision $Policy.revision
    return $true
  } finally {
    if($null -ne $input){$input.Dispose()};if($null -ne $output){$output.Dispose()}
    if([IO.File]::Exists($plain)){[IO.File]::Delete($plain)}
    $derived=$null;[Array]::Clear($buffer,0,$buffer.Length)
    $script:EpbEnvelopeMaxPlaintextBytes=$oldLimit;$script:EpbEnvelopeMaxBytes=$oldEnvelope
  }
}
function Read-EpbDiagnosticEnvelope {
  param([string]$InputPath,[string]$OutputPath,[string]$Secret,$Policy,[string]$BuilderSha,[string]$RunId,[string]$Attempt)
  Assert-EpbDiagnosticPolicy $Policy
  if(-not $Policy.enabled){throw 'Diagnostic collection was not enabled.'}
  if(Test-Path -LiteralPath $OutputPath){throw 'Diagnostic evidence already exists.'}
  $context=Get-EpbDiagnosticContext $Policy.project $Policy.revision $BuilderSha $RunId $Attempt
  $plain=$OutputPath+'.'+[Guid]::NewGuid().ToString('N')+'.plain'
  $oldLimit=$script:EpbEnvelopeMaxPlaintextBytes;$oldEnvelope=$script:EpbEnvelopeMaxBytes
  $derived=$null;$input=$null;$output=$null;$completed=$false;$ownsOutput=$false
  try {
    $script:EpbEnvelopeMaxPlaintextBytes=[long]1056772;$script:EpbEnvelopeMaxBytes=[long]1056861
    $derived=Get-EpbDiagnosticKey $Secret $context
    Read-EpbAuthenticatedEnvelope -InputPath $InputPath -OutputPath $plain -Secret $derived -ProjectId $Policy.project -Revision $Policy.revision
    $input=[IO.File]::OpenRead($plain)
    [byte[]]$length=New-Object byte[] 4
    if($input.Read($length,0,4) -ne 4){throw 'Diagnostic metadata is unavailable.'}
    if([BitConverter]::IsLittleEndian){[Array]::Reverse($length)}
    $count=[BitConverter]::ToUInt32($length,0)
    if($count -gt 8192 -or $count -lt 2 -or $input.Length -lt (4+$count)){throw 'Diagnostic metadata exceeds its bound.'}
    [byte[]]$json=New-Object byte[] $count
    if($input.Read($json,0,$json.Length) -ne $json.Length){throw 'Diagnostic metadata is incomplete.'}
    $metadata=[Text.UTF8Encoding]::new($false,$true).GetString($json)|ConvertFrom-Json -ErrorAction Stop
    if((@($metadata.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'archive_sha256,attempt,builder_sha,conclusion,original_bytes,project,revision,run_id,source_commit,tail_bytes,truncated,version' -or
      $metadata.version -ne 1 -or $metadata.project -cne $Policy.project -or $metadata.revision -cne $Policy.revision -or
      $metadata.builder_sha -cne $BuilderSha -or $metadata.run_id -cne $RunId -or $metadata.attempt -cne $Attempt -or
      $metadata.source_commit -cne $Policy.source_commit -or $metadata.archive_sha256 -cne $Policy.archive_sha256 -or
      $metadata.conclusion -cne 'failure' -or $metadata.truncated -isnot [bool] -or
      $metadata.original_bytes -lt 0 -or $metadata.tail_bytes -ne [Math]::Min([long]$metadata.original_bytes,1048576) -or
      $metadata.truncated -ne ($metadata.original_bytes -gt $metadata.tail_bytes) -or
      ($input.Length-$input.Position) -ne $metadata.tail_bytes){throw 'Diagnostic source or run binding does not match.'}
    $output=[IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $ownsOutput=$true
    $input.CopyTo($output);$output.Dispose();$output=$null;$completed=$true
    return $metadata
  }finally{
    if($null -ne $input){$input.Dispose()};if($null -ne $output){$output.Dispose()}
    if([IO.File]::Exists($plain)){[IO.File]::Delete($plain)}
    if($ownsOutput -and -not $completed -and [IO.File]::Exists($OutputPath)){[IO.File]::Delete($OutputPath)}
    $derived=$null;$script:EpbEnvelopeMaxPlaintextBytes=$oldLimit;$script:EpbEnvelopeMaxBytes=$oldEnvelope
  }
}

if($Mode -eq 'Collect'){
  $ErrorActionPreference='Stop'
  $workspace=$null;$stage=$null
  $ready=$false;$pathsValidated=$false;$ownsStage=$false
  try {
    [void](Get-EpbDiagnosticContext $env:PROJECT_ID $env:PROJECT_REV $env:BUILDER_SHA $env:GITHUB_RUN_ID $env:GITHUB_RUN_ATTEMPT)
    $workspace=Join-Path $env:RUNNER_TEMP "epb-$env:PROJECT_ID"
    $stage=Join-Path $env:RUNNER_TEMP "diagnostics-$env:PROJECT_ID"
    Assert-EpbDiagnosticDirectoryParent $workspace
    Assert-EpbDiagnosticDirectoryParent $stage
    $pathsValidated=$true
    if($null -eq $TrustedCrypto -or $null -eq $TrustedPolicy){throw 'Verified diagnostic helpers are required.'}
    . $TrustedCrypto
    . $TrustedPolicy
    if($env:EXPECTED_REVISION -cne $env:PROJECT_REV){throw 'Diagnostic revision changed.'}
    if([string]::IsNullOrWhiteSpace($env:DIAGNOSTICS_POLICY)){throw 'Diagnostic policy is unavailable.'}
    $policy=$env:DIAGNOSTICS_POLICY|ConvertFrom-Json -ErrorAction Stop
    Assert-EpbDiagnosticPolicy $policy
    if($policy.project -cne $env:PROJECT_ID -or $policy.revision -cne $env:PROJECT_REV){throw 'Diagnostic policy binding changed.'}
    if($policy.enabled){
      $archivePath=Join-Path $workspace 'workspace.zip'
      Assert-EpbDiagnosticRegularPath $archivePath
      $archiveStream=[IO.File]::Open($archivePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
      $archiveHash=[Security.Cryptography.SHA256]::Create()
      try{$actualArchive=([BitConverter]::ToString($archiveHash.ComputeHash($archiveStream))).Replace('-','').ToLowerInvariant()}finally{$archiveStream.Dispose();$archiveHash.Dispose()}
      if($actualArchive -cne $policy.archive_sha256){throw 'Diagnostic source archive changed.'}
      if(Test-Path -LiteralPath $stage){throw 'Diagnostic staging already exists.'}
      [void][IO.Directory]::CreateDirectory($stage)
      $ownsStage=$true
      Assert-EpbDiagnosticDirectoryParent $stage
      'stage_owned=true'|Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8
      $ready=Write-EpbDiagnosticEnvelope -LogPath (Join-Path $workspace 'project-body.log') -OutputPath (Join-Path $stage 'diagnostics.bin') -Secret $env:BUILD_BUNDLE_KEY -Policy $policy -BuilderSha $env:BUILDER_SHA -RunId $env:GITHUB_RUN_ID -Attempt $env:GITHUB_RUN_ATTEMPT
    }
  }catch{Write-Host 'Encrypted diagnostic collection unavailable.'}
  finally{
    $env:BUILD_BUNDLE_KEY=$null;$env:DIAGNOSTICS_POLICY=$null
    if($pathsValidated){Remove-Item -LiteralPath (Join-Path $workspace 'project-body.log') -Force -ErrorAction SilentlyContinue}
    if($ownsStage -and -not $ready -and (Test-Path -LiteralPath $stage)){Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue}
  }
  if($ready){'ready=true'|Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8}
}
