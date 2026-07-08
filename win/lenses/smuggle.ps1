<#
.SYNOPSIS
  honey (Windows) lens: smuggle — detect scanner-evasion smuggling in agent-skill
  and instruction files. PowerShell mirror of lenses/smuggle.sh (uses native .NET
  Unicode enumeration, so it needs no perl).

.DESCRIPTION
  Flags what static pattern scanners miss:
    • invisible Unicode  — tag chars U+E0000–E007F (ASCII smuggling)
    • bidirectional overrides — U+202A–202E / U+2066–2069 (Trojan Source)
    • zero-width          — U+200B/200C/2060/180E (excludes emoji ZWJ U+200D)
    • remote includes     — instructions to fetch/read a remote URL at runtime

.PARAMETER RunDir
  Run directory to write lens-smuggle.json into.
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

if (-not $RunDir) { Write-Error 'usage: smuggle.ps1 -RunDir <dir>'; exit 2 }

$home_ = Get-HoneyHome
$defaultRoots = @(
    (Join-Path $home_ '.claude\skills'), (Join-Path $home_ '.claude\plugins'),
    (Join-Path $home_ '.claude\scheduled-tasks'), (Join-Path $home_ '.config\claude\skills')
) -join ';'
$roots = (Get-HoneySetting 'HONEY_SKILL_ROOTS' $defaultRoots) -split ';' | Where-Object { $_ }
$excludeRe = Get-HoneySettingRaw 'HONEY_SMUGGLE_EXCLUDE' '[\\/](node_modules|\.git|vendor|\.pnpm)[\\/]'
$exts = '.md','.markdown','.txt','.json','.yaml','.yml','.sh','.py','.js','.ts','.html'
$urlRe = [regex]'(?i)(curl|wget|fetch|download|retrieve|read|load|import|include|open)\b[^\n]{0,60}https?://'

$findings = New-Object System.Collections.ArrayList
function Add-Finding { param($Sev,$Title,$File,$Line,$Detail)
    [void]$findings.Add([pscustomobject]@{ severity=$Sev; title=$Title; location="${File}:${Line}"; detail=$Detail; ref='scanner-evasion' })
}

$scanned = 0
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $exts -contains $_.Extension.ToLower() -and $_.FullName -notmatch $excludeRe } |
        ForEach-Object {
            $file = $_.FullName
            $n = 0
            foreach ($line in [System.IO.File]::ReadLines($file)) {
                $n++
                foreach ($rune in $line.EnumerateRunes()) {
                    $cp = $rune.Value
                    if ($cp -ge 0xE0000 -and $cp -le 0xE007F) {
                        Add-Finding 'high' 'Invisible Unicode (tag chars)' $file $n ("ASCII-smuggling codepoint U+{0:X4} — carries hidden instructions invisible to humans and byte scanners" -f $cp); break
                    }
                }
                foreach ($rune in $line.EnumerateRunes()) {
                    $cp = $rune.Value
                    if (($cp -ge 0x202A -and $cp -le 0x202E) -or ($cp -ge 0x2066 -and $cp -le 0x2069)) {
                        Add-Finding 'high' 'Bidirectional override (Trojan Source)' $file $n ("bidi control U+{0:X4} can reorder how text renders vs. is interpreted" -f $cp); break
                    }
                }
                foreach ($rune in $line.EnumerateRunes()) {
                    $cp = $rune.Value
                    if ($cp -eq 0x200B -or $cp -eq 0x200C -or $cp -eq 0x2060 -or $cp -eq 0x180E) {
                        Add-Finding 'medium' 'Zero-width character' $file $n ("hidden zero-width codepoint U+{0:X4} (possible token smuggling)" -f $cp); break
                    }
                }
                if ($urlRe.IsMatch($line)) {
                    Add-Finding 'medium' 'Remote include instruction' $file $n 'instructs the agent to fetch/read a remote URL - content the on-disk scan never sees'
                }
            }
            $scanned++
        }
}

$note = "scanned $scanned agent-skill/instruction file(s) under $($roots -join ';') for invisible/bidi/zero-width Unicode + remote-include instructions"
if ($scanned -eq 0) { $note = "no agent-skill/instruction files found under: $($roots -join ';')" }
$status = if (@($findings).Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens 'smuggle' -ToolVersion '1' -Status $status -Findings @($findings) -Note $note | Out-Null
Write-HoneyConsole "lens smuggle: status written ($(@($findings).Count) finding(s))"
exit 0
