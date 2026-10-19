# Private owner records use a separate authentication domain from release policy.
function Resolve-EpbDiagnosticMode($Owner,[bool]$Enable,[bool]$Disable) {
  if($Enable -and $Disable){throw 'Diagnostic enable and disable are mutually exclusive.'}
  if($Disable){return $false}
  if($Enable){return $true}
  if($null -ne $Owner){return [bool]$Owner.policy.enabled}
  return $false
}
function Get-EpbDiagnosticPolicyMac([string]$Body,[string]$Secret) {
  [byte[]]$key=[Convert]::FromBase64String($Secret)
  $mac=[Security.Cryptography.HMACSHA256]::new($key)
  try { [Convert]::ToBase64String($mac.ComputeHash([Text.Encoding]::UTF8.GetBytes("EPB-DIAGNOSTIC-OWNER-v1`n$Body"))) }
  finally {$mac.Dispose();[Array]::Clear($key,0,$key.Length)}
}
function Assert-EpbDiagnosticPolicy($Policy) {
  $fields=@('archive_sha256','enabled','project','revision','source_commit','version')
  if ($null -eq $Policy) { throw 'Diagnostic policy is missing.' }
  foreach($name in @('project','revision','source_commit','archive_sha256')){if($Policy.$name -isnot [string]){throw 'Diagnostic policy field is invalid.'}}
  if((@($Policy.PSObject.Properties.Name|Sort-Object)-join ',') -cne ($fields-join ',') -or
    $Policy.version -ne 1 -or $Policy.enabled -isnot [bool] -or
    $Policy.project -cnotmatch '^p[0-9a-f]{32}$' -or $Policy.revision -cnotmatch '^[0-9a-f]{32}$' -or
    $Policy.source_commit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
    $Policy.archive_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Diagnostic policy is invalid.'}
}
function Read-EpbDiagnosticOwnerRecord([string]$Path,[string]$Secret,[string]$Project,[string]$Builder) {
  if(-not [IO.File]::Exists($Path)){return $null}
  if((Get-Item -LiteralPath $Path).Length -gt 8192){throw 'Diagnostic owner record exceeds its bound.'}
  try {$record=[IO.File]::ReadAllText($Path)|ConvertFrom-Json -ErrorAction Stop} catch {throw 'Diagnostic owner record is invalid.'}
  if((@($record.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'body,mac'){throw 'Diagnostic owner record is invalid.'}
  $body=[string]$record.body
  $expected=Get-EpbDiagnosticPolicyMac $body $Secret
  try {$actualBytes=[Convert]::FromBase64String([string]$record.mac);$expectedBytes=[Convert]::FromBase64String($expected)}catch{throw 'Diagnostic owner authentication failed.'}
  if(-not(Test-EpbFixedTimeEqual $actualBytes $expectedBytes)){throw 'Diagnostic owner authentication failed.'}
  $value=$body|ConvertFrom-Json -ErrorAction Stop
  if((@($value.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'builder,builder_sha,policy' -or
    $value.builder -cne $Builder.ToLowerInvariant() -or $value.builder_sha -cnotmatch '^[0-9a-f]{40}$') {throw 'Diagnostic owner binding is invalid.'}
  Assert-EpbDiagnosticPolicy $value.policy
  if($value.policy.project -cne $Project){throw 'Diagnostic owner project changed.'}
  return $value
}
function Write-EpbDiagnosticOwnerRecord([string]$Path,$Policy,[string]$Builder,[string]$BuilderSha,[string]$Secret) {
  Assert-EpbDiagnosticPolicy $Policy
  if($Builder -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $BuilderSha -cnotmatch '^[0-9a-f]{40}$'){throw 'Diagnostic owner destination is invalid.'}
  $body=[ordered]@{builder=$Builder.ToLowerInvariant();builder_sha=$BuilderSha;policy=$Policy}|ConvertTo-Json -Compress -Depth 5
  $text=[ordered]@{body=$body;mac=(Get-EpbDiagnosticPolicyMac $body $Secret)}|ConvertTo-Json -Compress
  $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
  try {
    [IO.File]::WriteAllText($temporary,$text,[Text.UTF8Encoding]::new($false))
    if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
  }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
