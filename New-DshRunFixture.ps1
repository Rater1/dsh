# Requires PowerShell 7 and the Windows .NET Framework x64 compiler.
param([ValidatePattern('^[a-zA-Z0-9._-]{1,20}$')][string]$AgentAccount = 'dsh-run')

$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Run setup with PowerShell 7 on Windows.'
}

$holder = [Security.Principal.WindowsIdentity]::GetCurrent().User
$agent = ([Security.Principal.NTAccount]::new([Environment]::MachineName, $AgentAccount)).Translate([Security.Principal.SecurityIdentifier])
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
if ($holder.Equals($agent)) { throw 'Use distinct holder and Agent accounts.' }

$compiler = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $compiler
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw 'The installed compiler must have a valid Microsoft signature.'
}
$source = Join-Path $PSScriptRoot 'Check-DshRunFixture.cs'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Checker source is missing.' }

function Set-FixtureAccess([string]$Path, [bool]$AgentCanRead) {
    $item = Get-Item -LiteralPath $Path
    $acl = if ($item.PSIsContainer) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($holder, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    if ($AgentCanRead) {
        # This rule applies to the named item only. It is not inherited by private files.
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($agent, 'ReadAndExecute', 'Allow'))
    }
    [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
}

$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('DshRun-Acl-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
Set-FixtureAccess $root $false
Write-Host "Synthetic fixture directory: $root"

$private = Join-Path $root 'credential.fixture'
$config = Join-Path $root 'service.fixture.json'
$marker = Join-Path $root 'public.txt'
$identities = Join-Path $root 'identities.txt'
$checker = Join-Path $root 'Check-DshRunFixture.exe'
[IO.File]::WriteAllText($private, 'SYNTHETIC-CREDENTIAL-ONLY-' + [Guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText($config, '{"fixture":true}')
[IO.File]::WriteAllText($marker, 'Public synthetic control')
[IO.File]::WriteAllLines($identities, [string[]]@($holder.Value, $agent.Value))
& $compiler '/nologo' '/target:exe' '/optimize+' "/out:$checker" $source
if ($LASTEXITCODE -ne 0) { throw 'Checker compilation failed.' }

foreach ($item in @($private, $config)) { Set-FixtureAccess $item $false }
foreach ($item in @($marker, $identities, $checker)) { Set-FixtureAccess $item $true }
Set-FixtureAccess $root $true

& $checker
if ($LASTEXITCODE -ne 0) { throw 'Holder check failed.' }
Write-Host "Checker to run as the Agent account: $checker"
