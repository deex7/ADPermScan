#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Builds an interactive "bubble map" of AD OU permissions as a standalone HTML file.

.DESCRIPTION
    * Enumerates every OU in the current domain (and the domain object itself).
    * Reads each container's DACL via Get-Acl LDAP://... and walks up the parent
      chain to determine which ACEs are INHERITED by each OU, honouring
      "Protected from inheritance" on intermediate containers.
    * For every ACE it records: principal (resolved through nested groups in the
      browser), Allow/Deny, ActiveDirectoryRights, propagation flags
      (child OUs / child objects / this-OU only) and target object class GUIDs.
    * Emits ONE self-contained HTML file (no CDN/internet needed):
        - Bubble per OU: size = # permission rows, colour = highest privilege tier
        - Filter dropdown by group name using TRANSITIVE (nested) membership
        - OU name search, legend with live counts, pan/zoom, hover tooltips,
          click for a full permissions table (incl. "inherited from" source and
          nested member/user counts).

.PARAMETER OutputFile
    Where to write the HTML report (default: AD-BubbleMap.html next to this script).

.PARAMETER ScopeDNs
    Optional. Restrict DACL collection to OUs under these DN(s) for speed in very
    large domains. Inherited permissions are still traced all the way up to the root.

.PARAMETER ExplicitOnly
    If set, do NOT walk ancestors: each OU shows only its own explicit ACEs
    (smaller/faster, but no "inherited from" information).

.NOTES
    Run as a Domain Admin on a DC or a machine with RSAT + AD module and the
    ability to read security descriptors. Reading every DACL is sequential; expect
    roughly 50-100 ms per container (a few thousand OUs = several minutes).
#>

param(
    [string]$OutputFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'AD-BubbleMap.html' } else { Join-Path (Get-Location) 'AD-BubbleMap.html' },
    [string[]]$ScopeDNs = @(),
    [switch]$ExplicitOnly
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------------------
# 0. Environment checks / domain info
# ---------------------------------------------------------------------------
Write-Host "Resolving current domain..." -ForegroundColor Cyan
$domain   = Get-ADDomain
$domDN    = $domain.DistinguishedName          # DC=contoso,DC=com
$domDNLc  = $domDN.ToLower()

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object System.Security.Principal.WindowsPrincipal($me)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You are not elevated. Reading DACLs of arbitrary objects requires SeSecurityPrivilege (run as Domain Admin on a DC)."
}

# ---------------------------------------------------------------------------
# 1. Small helpers
# ---------------------------------------------------------------------------
function Get-ParentDN([string]$dn) {
    if (-not $dn) { return '' }
    $i = $dn.IndexOf(',')
    if ($i -lt 1) { return '' }
    return $dn.Substring($i + 1).Trim()
}

$ouNameByDn = @{}   # lower DN -> display name (populated after OU enumeration)

function Get-DNDisplayName([string]$dn) {
    if (-not $dn) { return '' }
    $k = $dn.ToLower()
    if ($ouNameByDn.ContainsKey($k)) { return $ouNameByDn[$k] }
    if ($k -eq $domDNLc)             { return $domain.Name }
    # Fallback: value of the RDN (e.g. "Users" from OU=Users,...)
    $i = $dn.IndexOf(',')
    $rdn = if ($i -ge 0) { $dn.Substring(0, $i) } else { $dn }
    $p = $rdn.IndexOf('=')
    if ($p -ge 0) { return $rdn.Substring($p + 1).Trim() }
    return $rdn
}

# ---------------------------------------------------------------------------
# 2. Enumerate OUs (metadata for ALL; ACLs later, optionally scoped)
# ---------------------------------------------------------------------------
Write-Host "Enumerating organizational units..." -ForegroundColor Cyan
$ous = @(Get-ADOrganizationalUnit -Filter * | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; DN = $_.DistinguishedName }
})
foreach ($o in $ous) { $ouNameByDn["$($o.DN)".ToLower()] = $o.Name }

if ($ScopeDNs.Count -gt 0) {
    $scopes = @($ScopeDNs | ForEach-Object { "$_".ToLower() })
    Write-Host "Scoping to: $($ScopeDNs -join ', ')" -ForegroundColor Cyan
    $ous = @($ous | Where-Object {
        foreach ($s in $scopes) { if ("$($_.DN)".ToLower().StartsWith($s)) { return $true } }
        return $false
    })
}
Write-Host "  OUs found: $($ous.Count)" -ForegroundColor DarkCyan

# ---------------------------------------------------------------------------
# 3. Entities (groups + users) and direct group membership edges.
#    Nested resolution happens client-side from these edges.
# ---------------------------------------------------------------------------
Write-Host "Enumerating groups and users..." -ForegroundColor Cyan

$entities = [System.Collections.Generic.List[object]]::new()   # { t:'G'|'U'|'O', n: name }
$entKey   = @{}                                                # "t|name" -> index
$edges    = [System.Collections.Generic.List[object]]::new()   # [parentGroupIdx, memberIdx]

function Add-Entity([string]$type, [string]$name) {
    if (-not $name) { $name = '?' }
    $k = "$($type.ToLower())|$($name.ToLower())"
    if ($entKey.ContainsKey($k)) { return $entKey[$k] }
    [void]$entities.Add([pscustomobject]@{ t = $type; n = $name })
    $idx = $entities.Count - 1
    $entKey[$k] = $idx
    return $idx
}

function Register-Alias($idx, [string]$type, [string]$name) {
    if (-not $name) { return }
    $k = "$($type.ToLower())|$($name.ToLower())"
    if (-not $entKey.ContainsKey($k)) { $entKey[$k] = $idx }
}

function Resolve-PrincipalName([string]$raw) {
    # Returns entity index, or -1 when the principal is irrelevant (SELF / unresolvable empty).
    if (-not $raw) { return -1 }
    if ($raw -match '^S-1-\d') {
        try { $raw = (New-Object System.Security.Principal.SecurityIdentifier $raw).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    }
    $k = "$raw".ToLower().Trim()
    if (-not $k -or $k -eq 'self' -or $k.EndsWith('\self')) { return -1 }

    foreach ($t in @('g','u')) {
        if ($entKey.ContainsKey("$t|$k")) { return $entKey["$t|$k"] }
    }
    # ACE names are usually "DOMAIN\Name" - retry with the bare name
    $bs = $k.LastIndexOf('\')
    if ($bs -ge 0) {
        $base = $k.Substring($bs + 1)
        foreach ($t in @('g','u')) {
            if ($entKey.ContainsKey("$t|$base")) { return $entKey["$t|$base"] }
        }
    }
    # Unknown principal (computer, foreign group, ...) -> keep as "Other"
    $disp = if ($bs -ge 0) { $k.Substring($bs + 1) } else { $k }
    return (Add-Entity 'O' $disp)
}

$dnToEntity = @{}   # lower DN -> entity index (groups and users)

foreach ($g in @(Get-ADGroup -Filter * -Properties Member | Select-Object Name, SamAccountName, DistinguishedName, Member)) {
    $gi = Add-Entity 'G' $g.Name
    Register-Alias $gi 'G' $g.SamAccountName
    if ($g.DistinguishedName) { $dnToEntity["$($g.DistinguishedName)".ToLower()] = $gi }
}

foreach ($u in @(Get-ADUser -Filter * | Select-Object Name, SamAccountName, DistinguishedName)) {
    $ui = Add-Entity 'U' $u.Name
    Register-Alias $ui 'U' $u.SamAccountName
    if ($u.DistinguishedName) { $dnToEntity["$($u.DistinguishedName)".ToLower()] = $ui }
}

Write-Host "  Groups: $(@($entities | Where-Object t -eq 'G').Count)   Users: $(@($entities | Where-Object t -eq 'U').Count)" -ForegroundColor DarkCyan

foreach ($g in @(Get-ADGroup -Filter * -Properties Member | Select-Object DistinguishedName, Member)) {
    $gi = $dnToEntity["$($g.DistinguishedName)".ToLower()]
    foreach ($m in @($g.Member)) {
        if (-not $m) { continue }
        $mk = "$m".ToLower()
        if (-not $dnToEntity.ContainsKey($mk)) {
            [void]$entities.Add([pscustomobject]@{ t = 'O'; n = (Get-DNDisplayName "$m") })
            $dnToEntity[$mk] = $entities.Count - 1
        }
        [void]$edges.Add( ,@($gi, $dnToEntity[$mk]) )
    }
}

# ---------------------------------------------------------------------------
# 4. ACL reading + parsing (cached per DN)
# ---------------------------------------------------------------------------
$classGuids = @{
    'bf967a8c-0de6-11d0-a255-00c04fd7d0dc' = 'user class'
    '312684f9-4194-11d0-a052-00a0c9223196' = 'group class'
    'bd162f71-cd80-4b3e-a9cd-f49478d39ecf' = 'computer class'
    'a86756cb-7bed-4fa2-94de-0830e57af84b' = 'contact class'
}

$aclCache  = @{}     # lower DN -> @{ perms=[object[]]; prot=bool }
$warnedAcl = $false
$aclFails  = 0

function Get-CachedPerms([string]$dn) {
    $k = "$dn".ToLower()
    if ($aclCache.ContainsKey($k)) { return $aclCache[$k] }

    $perms = @(); $prot = $false
    try {
        $acl = Get-Acl "LDAP://$dn" -ErrorAction Stop
        if ($null -eq $acl) { throw 'No security descriptor returned' }
        if ($acl -isnot [System.DirectoryServices.ActiveDirectorySecurity]) {
            Write-Warning "ACLs are not being returned as ActiveDirectorySecurity (requires Windows Server 2012+ / RSAT on Win8+). Aborting."
            $script:aclFails++ ; throw 'Unsupported ACL type'
        }
        $prot = [bool]$acl.IsProtected
        foreach ($r in @($acl.Access)) {
            try {
                if (-not $r) { continue }
                $idx = Resolve-PrincipalName ("$($r.IdentityReference)")
                if ($idx -lt 0) { continue }

                $deny   = ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)
                $rights = "$($r.ActiveDirectoryRights)"
                $f      = [int]$r.InheritanceFlags
                $ci     = if ([bool]($f -band 2)) { 1 } else { 0 }   # ContainerInherit bit -> child OUs
                $oi     = if ([bool]($f -band 1)) { 1 } else { 0 }   # ObjectInherit    bit -> child objects (users, ...)

                $ot = ''
                if ($r.ObjectType -ne [Guid]::Empty) {
                    $gg = "$($r.ObjectType)".ToLower()
                    if ($classGuids.ContainsKey($gg)) { $ot = $classGuids[$gg] } else { $ot = "guid:$($gg.Substring(0,8))" }
                }

                [void]$perms.Add([pscustomobject]@{ s=$idx; a=if($deny){'D'}else{'A'}; r=$rights; c=$ci; o=$oi; ot=$ot; i='' })
            } catch { Write-Verbose "ACE parse issue on $dn : $_" }
        }
    } catch {
        $script:aclFails++
        if (-not $script:warnedAcl) {
            Write-Warning "Could not read ACL for '$dn' ($_) - continuing; further failures will be counted silently."
            $script:warnedAcl = $true
        }
    }

    $aclCache[$k] = @{ perms = [object[]]$perms; prot = $prot }
    return $aclCache[$k]
}

# Fail fast if we cannot read the domain DACL at all (permissions problem)
try {
    $test = Get-CachedPerms $domDN
    if ($script:aclFails -gt 0) { throw "Unable to read security descriptors. Run as Domain Admin on a DC / with SeSecurityPrivilege." }
} catch [System.Exception] { throw $_.Message }

# ---------------------------------------------------------------------------
# 5. Effective permissions = own explicit ACEs + inherited from ancestors
#    (nearest grantor wins; walk stops at protected containers)
# ---------------------------------------------------------------------------
$effCache = @{}

function Get-EffPerms([string]$dn) {
    $k = "$dn".ToLower()
    if ($effCache.ContainsKey($k)) { return [object[]]$effCache[$k] }

    $list  = [System.Collections.Generic.List[object]]::new()
    $seen  = @{}
    $info  = Get-CachedPerms $dn

    foreach ($p in @($info.perms)) {
        $key = "$($p.s)|$($p.a)|$($p.r)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = 1
            [void]$list.Add([pscustomobject]@{ s=$p.s; a=$p.a; r=$p.r; c=$p.c; o=$p.o; ot=$p.ot; i='' })
        }
    }

    if (-not $ExplicitOnly -and -not $info.prot) {
        $cur = $dn
        while ($true) {
            $parDn = Get-ParentDN $cur
            if (-not $parDn) { break }
            $aInfo = Get-CachedPerms $parDn
            foreach ($p in @($aInfo.perms)) {
                if (-$p.c) { continue }   # ancestor ACE must carry ContainerInherit to reach descendant OUs
                $key = "$($p.s)|$($p.a)|$($p.r)"
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = 1
                    [void]$list.Add([pscustomobject]@{ s=$p.s; a=$p.a; r=$p.r; c=$p.c; o=$p.o; ot=$p.ot; i=(Get-DNDisplayName $parDn) })
                }
            }
            if ($aInfo.prot) { break }    # protected container: nothing above flows through it
            $cur = $parDn
        }
    }

    $effCache[$k] = [object[]]$list.ToArray()
    return [object[]]$effCache[$k]
}

# ---------------------------------------------------------------------------
# 6. Build the node tree (index 0 = domain root) and collect effective perms
# ---------------------------------------------------------------------------
Write-Host "Collecting effective permissions for $($ous.Count) OUs (reads every container DACL - may take a while)..." -ForegroundColor Cyan

$ouSorted     = $ous | Sort-Object @{ e = { $_.DN.Length } }, @{ e = { $_.DN } }   # parents always before children
$nodeIdByDn   = @{}
$nodes        = [System.Collections.Generic.List[object]]::new()

[void]$nodes.Add([pscustomobject]@{ n = $domain.Name; dn = $domDN; p = -1; d = 0; pr = @(Get-EffPerms $domDN) })
$nodeIdByDn[$domDNLc] = 0

$i = 0; $total = $ouSorted.Count
foreach ($ou in $ouSorted) {
    $i++
    Write-Progress -Activity 'Mapping OU permissions' -Status $ou.DN -PercentComplete ([int](100 * $i / [Math]::Max(1,$total)))

    # Nearest known ancestor (handles non-OU intermediate containers gracefully)
    $pp  = Get-ParentDN $ou.DN
    while ($pp -and -not $nodeIdByDn.ContainsKey("$pp".ToLower())) { $pp = Get-ParentDN $pp }
    $par = if ($pp) { $nodeIdByDn["$pp".ToLower()] } else { 0 }

    [void]$nodes.Add([pscustomobject]@{
        n  = $ou.Name
        dn = $ou.DN
        p  = $par
        d  = $nodes[$par].d + 1
        pr = @(Get-EffPerms $ou.DN)
    })
    $nodeIdByDn["$($ou.DN)".ToLower()] = $nodes.Count - 1
}
Write-Progress -Activity 'Mapping OU permissions' -Completed

$totalRows = 0; foreach ($nd in $nodes) { $totalRows += @($nd.pr).Count }
if ($script:aclFails -gt 0) { Write-Warning "$($script:aclFails) container(s) could not be read (see console above)." }

# ---------------------------------------------------------------------------
# 7. Serialize to JSON and inject into the HTML template
# ---------------------------------------------------------------------------
Write-Host "Generating HTML report..." -ForegroundColor Cyan

$payload = [pscustomobject]@{
    domain       = $domain.Name
    netbios      = $domain.NetBIOSName
    generated    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    explicitOnly = [bool]$ExplicitOnly
    entities     = @($entities)          # [{t,n}]  index == id
    edges        = @($edges)             # [[groupIdx, memberIdx], ...] direct membership only
    nodes        = @( $nodes | ForEach-Object {
            [pscustomobject]@{
                n  = $_.n
                dn = $_.dn
                p  = $_.p
                d  = $_.d
                pr = @($_.pr | ForEach-Object {
                        [pscustomobject]@{ s=$_.s; a=$_.a; r=$_.r; c=$_.c; o=$_.o; ot=$_.ot; i=$_.i }
                    })
            }
        })
}

$json = $payload | ConvertTo-Json -Depth 8 -Compress
$json = $json.Replace('"pr":null', '"pr":[]')     # belt & braces for empty arrays
$json = $json.Replace('</', '<\/')                # keep the <script> tag safe

$HTML_TEMPLATE = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AD OU Permission Bubble Map</title>
<style>
:root{--bg:#0b1220;--line:#243252;--txt:#dbe6ff;--dim:#8aa0c9;}
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,'Segoe UI',sans-serif;display:flex;flex-direction:column}
header{padding:10px 14px;border-bottom:1px solid var(--line);background:#0e1730;display:flex;flex-direction:column;gap:6px;z-index:5}
.hrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:650;white-space:nowrap}
h1 .dom{color:#7fb3ff}
select,input,button{background:#0d1830;color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:5px 9px;font:inherit;outline:none}
input[type=text]{width:210px}
label.chk{display:flex;gap:6px;align-items:center;color:var(--dim);font-size:13px}
#legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dim)}
.lg{display:inline-flex;gap:5px;align-items:center;cursor:default}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block;border:1px solid #ffffff33}
#stats{font-size:12px;color:var(--dim)}
main{flex:1;position:relative;overflow:hidden}
svg{position:absolute;inset:0;width:100%;height:100%;cursor:grab;display:block}
svg:active{cursor:grabbing}
.bub{stroke:#ffffff26;transition:fill .15s}
.bub:hover{stroke:#fff;stroke-width:1.4}
.bub.root{fill:transparent !important;stroke:#3d5a9e;stroke-dasharray:7 7}
.lbl{fill:#fff;opacity:.92;text-anchor:middle;pointer-events:none;font-weight:600;paint-order:stroke;stroke:#0b1220aa;stroke-width:2.5px}
.root-lbl{fill:#8fb0e8;font-weight:700}
.off{opacity:.09}
body.hideMode .off{display:none}
#tip{position:fixed;z-index:30;background:#0c1630f5;border:1px solid var(--line);border-radius:8px;padding:8px 11px;max-width:340px;font-size:12.5px;pointer-events:none;display:none}
#tip .dim{color:var(--dim)}
#panel{position:absolute;top:8px;right:8px;bottom:8px;width:min(460px,94vw);background:#0f1a33f2;border:1px solid var(--line);border-radius:10px;display:flex;flex-direction:column;transform:translateX(calc(100% + 24px));transition:transform .25s ease;z-index:20}
#panel.open{transform:none}
.ph{padding:10px 14px;border-bottom:1px solid var(--line);position:relative}
#pclose{position:absolute;top:8px;right:10px;background:none;border:none;color:var(--dim);font-size:20px;cursor:pointer;line-height:1}
#pTitle{margin:0 24px 2px 0;font-size:15px;word-break:break-all}
.small{font-size:11.5px}.dim{color:var(--dim)}
.pb{overflow:auto;padding:6px 14px;flex:1}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;vertical-align:top;padding:6px;border-bottom:1px solid #1c2a4a}
.badge{display:inline-block;padding:1px 8px;border-radius:9px;font-size:10.5px;border:1px solid var(--line);white-space:nowrap}
.b-G{color:#c4b5fd}.b-U{color:#7dd3fc}.b-O{color:#cbd5e1}
.deny{color:#ff6b81;font-weight:650}.allow{color:#7ee2a8;font-weight:650}
.chip{display:inline-block;background:#162343;border:1px solid var(--line);border-radius:9px;padding:0 8px;margin:1px 2px 1px 0;font-size:10.5px;color:var(--dim)}
#pnote{padding:8px 14px;border-top:1px solid var(--line);font-size:11px}
</style>
</head>
<body>
<header>
  <div class="hrow">
    <h1>🫧 AD OU Permission Bubble Map &nbsp;<span class="dom" id="domName"></span></h1>
    <label style="color:var(--dim);font-size:13px">Group filter
      <select id="grp"><option value="-1">All — no filter</option></select>
    </label>
    <input type="text" id="search" placeholder="Find OU by name / path…"/>
    <label class="chk"><input type="checkbox" id="hideDim"/> Hide non-matching OUs</label>
    <span style="flex:1"></span>
    <button id="zin" title="Zoom in">+</button>
    <button id="zout" title="Zoom out">−</button>
    <button id="fitBtn" title="Fit to screen">⌂ Fit</button>
  </div>
  <div class="hrow"><div id="legend"></div></div>
  <div id="stats"></div>
</header>
<main>
  <svg id="canvas"><g id="world"></g></svg>
  <div id="tip"></div>
  <aside id="panel">
    <div class="ph">
      <button id="pclose">×</button>
      <h2 id="pTitle" style="font-size:15px;margin:0 24px 2px 0"></h2>
      <div id="pPath" class="dim small"></div>
    </div>
    <div class="pb">
      <table><thead><tr><th>Principal</th><th>Type</th><th>Rights</th><th>Applies to / scope</th><th>Inheritance</th></tr></thead>
      <tbody id="pbody"></tbody></table>
    </div>
    <div id="pnote" class="dim"></div>
  </aside>
</main>

<script>
const DATA=__DATA__;
'use strict';
/* ---------------- data prep ---------------- */
const E = DATA.entities || [];
const nodes = DATA.nodes.map((n,i)=>{ n.id=i; n.pr=n.pr||[]; return n; });
const N = nodes.length;
const kids = Array.from({length:N},()=>[]);
nodes.forEach(n=>{ if(n.p>=0) kids[n.p].push(n.id); });

/* direct membership adjacency + transitive reach (memoized, cycle-safe) */
const adj={};
(DATA.edges||[]).forEach(([p,c])=>{ (adj[p]=adj[p]||[]).push(c); });
const reachCache=new Map();
function reach(i){
  let c=reachCache.get(i); if(c) return c;
  const out=new Set([i]), seen=new Set([i]), st=[i];
  while(st.length){
    const x=st.pop();
    for(const m of (adj[x]||[])){ if(!seen.has(m)){ seen.add(m); out.add(m); st.push(m); } }
  }
  reachCache.set(i,out); return out;
}

/* ---------------- privilege tiers / colours ---------------- */
function tierOf(r,a){
  if(a==='D') return 5;
  const s=String(r||'').toLowerCase(); let t=0;
  const rules=[[4,/genericall|full control|writedacl|replicate/],
               [3,/genericwrite|resetpassword|unlockmember|managedby|delete|createchild/],
               [2,/writeproperty|write/],
               [1,/read|control|list|self|extendedright|syncrepl/]];
  for(const [v,re] of rules) if(re.test(s)) t=Math.max(t,v);
  return t;
}
const COLORS=['#64748b','#3b82f6','#eab308','#f97316','#a855f7','#ef4444'];
const TIER_NAMES=['Minor / other','Read · Control','Write (properties)','Create/Delete/Mgmt','GenericAll · Full control','DENY'];

/* ---------------- bubble layout (circle packing) ---------------- */
(function radii(i){
  const n=nodes[i], ch=kids[i]||[];
  if(!ch.length){ n.r=Math.max(6, 5+Math.sqrt(n.pr.length)*3.4); return; }
  let maxC=0,sum=0;
  for(const c of ch){ radii(c); const r=nodes[c].r; sum+=r*r; if(r>maxC)maxC=r; }
  n.r=Math.max(maxC+9, Math.sqrt(sum/Math.PI)*1.28 + maxC*0.25);
})(0);

const GA=Math.PI*(3-Math.sqrt(5));
function place(i,cx,cy,R){
  const n=nodes[i]; n.x=cx; n.y=cy;
  const ch=(kids[i]||[]).slice().sort((a,b)=>nodes[b].r-nodes[a].r);
  if(!ch.length) return;
  let k=1e9;
  for(let j=0;j<ch.length;j++){
    const c=nodes[ch[j]];
    k=Math.min(k, Math.max(.5, R-3-c.r)/Math.sqrt(j+1));
  }
  ch.forEach((id,j)=>{
    const c=nodes[id];
    let d=(ch.length===1)?0:k*Math.sqrt(j+1);
    if(d+c.r>R-2) d=Math.max(0,R-2-c.r);      // allow slight boundary overlap rather than clipping subtrees
    const a=(j+1)*GA;
    c.x=cx+d*Math.cos(a); c.y=cy+d*Math.sin(a);
    place(id,c.x,c.y,c.r);
  });
}
place(0,0,0,nodes[0].r);

/* ---------------- render ---------------- */
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const world=document.getElementById('world');
let html='';
for(let i=0;i<N;i++){
  const n=nodes[i], r=Math.max(n.r,3).toFixed(1);
  html+=`<circle data-i="${i}" class="bub${i===0?' root':''} off" cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${r}"></circle>`;
  if(i!==0 && n.r>=26){
    const fs=Math.min(15,Math.max(7.5,n.r*0.3));
    let lab=n.n; const maxc=Math.floor(n.r/3.4);
    if(lab.length>maxc) lab=lab.slice(0,Math.max(3,maxc-1))+'…';
    html+=`<text data-i="${i}" class="lbl off" x="${n.x.toFixed(1)}" y="${(n.y+fs*0.35).toFixed(1)}" font-size="${fs.toFixed(1)}">${esc(lab)}</text>`;
  }
}
html+=`<text class="lbl root-lbl" x="0" y="${(-nodes[0].r*0.88).toFixed(0)}" font-size="24">Domain: ${esc(nodes[0].n)}</text>`;
world.innerHTML=html;

const circ=[...document.querySelectorAll('.bub')];
const lbls=new Array(N).fill(null);
document.querySelectorAll('text.lbl[data-i]').forEach(t=>{ const i=+t.dataset.i; if(i>=0&&i<N) lbls[i]=t; });

/* ---------------- paths / breadcrumbs ---------------- */
const pathStr=new Array(N);
function pathOf(i){
  if(pathStr[i]) return pathStr[i];
  const parts=[]; let j=i, guard=0;
  while(j>=0 && j<N && guard++<500){ parts.unshift(nodes[j].n); j=nodes[j].p; }
  return pathStr[i]=parts.join(' › ');
}

/* ---------------- filter state + refresh ---------------- */
let curG=-1, q='';
const sel=document.getElementById('grp'), searchEl=document.getElementById('search');
(function fillGroups(){
  const gs=E.map((e,i)=>[i,e]).filter(([i,e])=>e&&e.t==='G').sort((a,b)=>String(a[1].n).localeCompare(String(b[1].n)));
  for(const [i,e] of gs){ const o=document.createElement('option'); o.value=i; o.textContent=e.n; sel.appendChild(o); }
})();

function visiblePerms(n){
  if(curG<0) return n.pr;
  const out=[];
  for(const p of n.pr){
    if(p.s<0) continue;
    if(p.s===curG || reach(p.s).has(curG)) out.push(p);   // ACE subject is a group that (transitively) contains the selected group
  }
  return out;
}

const counts=[0,0,0,0,0,0];
function refresh(){
  for(let c=0;c<6;c++)counts[c]=0;
  let matched=0, rows=0;
  for(let i=1;i<N;i++){
    const n=nodes[i], vp=visiblePerms(n); rows+=vp.length;
    const nameOk=!q || n.n.toLowerCase().includes(q) || pathOf(i).toLowerCase().includes(q);
    let t=-1;
    if(vp.length && nameOk){ for(const p of vp){ const tt=tierOf(p.r,p.a); if(tt>t)t=tt; } matched++; counts[Math.max(0,t)]++; }
    circ[i].setAttribute('fill', COLORS[t>=0?t:0]);
    circ[i].classList.toggle('off', t<0);
    if(lbls[i]) lbls[i].classList.toggle('off', t<0);
  }
  document.querySelectorAll('#legend b[data-c]').forEach(el=>el.textContent=counts[+el.dataset.c]);
  let st=`${matched} of ${N-1} OUs show effective permissions` + (curG>=0?` for “${E[curG].n}”`:``) + ` · ${rows} permission rows`;
  if(curG>=0){
    const r=reach(curG); let u=0; r.forEach(x=>{ const e=E[x]; if(e&&e.t==='U')u++; });
    st+=` · ≈${u} nested users in group`;
  }
  document.getElementById('stats').textContent=st + `   ·   generated ${DATA.generated}`;
}

/* legend */
document.getElementById('legend').innerHTML=TIER_NAMES.map((nm,k)=>
  `<span class="lg" title="Bubbles coloured by their highest matching permission tier"><span class="dot" style="background:${COLORS[k]}"></span>${nm}&nbsp;<b data-c="${k}">0</b></span>`).join('');

/* ---------------- events: filter / search / hide ---------------- */
sel.addEventListener('change',()=>{ curG=+sel.value; refresh(); });
let deb=null;
searchEl.addEventListener('input',()=>{ clearTimeout(deb); deb=setTimeout(()=>{ q=searchEl.value.trim().toLowerCase(); refresh(); },150); });
document.getElementById('hideDim').addEventListener('change',e=>document.body.classList.toggle('hideMode',e.target.checked));

/* ---------------- zoom / pan ---------------- */
const svg=document.getElementById('canvas');
let vx=0,vy=0,vk=1;
function applyV(){ world.setAttribute('transform',`translate(${vx} ${vy}) scale(${vk})`); }
function fit(){ const R=nodes[0].r||1, w=svg.clientWidth, h=svg.clientHeight; vk=Math.min(w,h)/(2*R)*0.97; vx=w/2; vy=h/2; applyV(); }
function zoomAt(mx,my,f){ const nk=Math.min(12,Math.max(.03,vk*f)); f=nk/vk; vx=mx-(mx-vx)*f; vy=my-(my-vy)*f; vk=nk; applyV(); }
svg.addEventListener('wheel',e=>{ e.preventDefault(); zoomAt(e.clientX-svg.getBoundingClientRect().left, e.clientY-svg.getBoundingClientRect().top, Math.exp(-e.deltaY*0.0014)); },{passive:false});
document.getElementById('zin').onclick =()=>zoomAt(svg.clientWidth/2,svg.clientHeight/2,1.35);
document.getElementById('zout').onclick=()=>zoomAt(svg.clientWidth/2,svg.clientHeight/2,1/1.35);
document.getElementById('fitBtn').onclick=fit;

let drag=null,moved=0;
svg.addEventListener('pointerdown',e=>{ drag={x:e.clientX,y:e.clientY,vx,vy}; moved=0; try{svg.setPointerCapture(e.pointerId);}catch(_){} });
svg.addEventListener('pointermove',e=>{ if(!drag)return; const dx=e.clientX-drag.x,dy=e.clientY-drag.y; moved=Math.max(moved,Math.abs(dx)+Math.abs(dy)); vx=drag.vx+dx; vy=drag.vy+dy; applyV(); });
['pointerup','pointercancel'].forEach(t=>svg.addEventListener(t,()=>{drag=null;}));

/* ---------------- tooltip + detail panel ---------------- */
const tip=document.getElementById('tip'), panel=document.getElementById('panel');
svg.addEventListener('mousemove',e=>{
  if(drag && moved>4){ tip.style.display='none'; return; }
  const t=e.target.closest ? e.target.closest('.bub') : null;
  if(!t || !t.dataset.i){ tip.style.display='none'; return; }
  const n=nodes[+t.dataset.i];
  tip.innerHTML=`<b>${esc(n.n)}</b><br><span class="dim">${esc(pathOf(+t.dataset.i))}</span><br>${(n.pr||[]).length} permission rows — click for details`;
  tip.style.display='block';
  let x=e.clientX+14, y=e.clientY+12;
  const r=tip.getBoundingClientRect();
  if(x+r.width>innerWidth-8)  x=e.clientX-r.width-10;
  if(y+r.height>innerHeight-8)y=e.clientY-r.height-10;
  tip.style.left=x+'px'; tip.style.top=y+'px';
});
svg.addEventListener('mouseleave',()=>{ tip.style.display='none'; });

function memberLine(idx){
  const e=E[idx]; if(!e || e.t==='U') return '';
  const r=reach(idx); let u=0; r.forEach(x=>{ const t2=(E[x]||{}).t; if(t2==='U')u++; });
  return `<div class="dim small">${r.size-1} nested members · ≈${u} users</div>`;
}

svg.addEventListener('click',e=>{
  if(moved>5) return;
  const t=e.target.closest ? e.target.closest('.bub') : null;
  if(!t || !t.dataset.i) return;
  openPanel(+t.dataset.i);
});
document.getElementById('pclose').onclick=()=>panel.classList.remove('open');

function openPanel(i){
  const n=nodes[i];
  panel.classList.add('open');
  document.getElementById('pTitle').textContent=n.n;
  document.getElementById('pPath').textContent=pathOf(i)+(n.dn?`   ·   ${n.dn}`:'');
  const vp=visiblePerms(n);
  const rows=[...vp].sort((a,b)=>tierOf(b.r,b.a)-tierOf(a.r,a.a) || String(E[a.s]?.n||'').localeCompare(String(E[b.s]?.n||'')))
   .map(p=>{
      const e=E[p.s]||{t:'O',n:'#'+p.s};
      const scope=[]; if(p.c)scope.push('child OUs'); if(p.o)scope.push('child objects (users, groups…)'); if(!p.c&&!p.o)scope.push('this OU only'); if(p.ot)scope.push(esc(p.ot));
      return `<tr>
        <td>${esc(e.n)}${memberLine(p.s)}</td>
        <td><span class="badge b-${e.t}">${e.t==='G'?'Group':e.t==='U'?'User':'Other'}</span></td>
        <td class="${p.a==='D'?'deny':'allow'}">${p.a==='D'?'DENY':'Allow'}<br>${esc(p.r||'(none)')}</td>
        <td>${scope.map(s=>`<span class="chip">${s}</span>`).join('')}</td>
        <td>${p.i?`Inherited from<br><b>${esc(p.i)}</b>`:'Set on this OU'}</td></tr>`;
   }).join('');
  document.getElementById('pbody').innerHTML=rows||'<tr><td colspan="5" class="dim">No permissions under the current filter.</td></tr>';
  document.getElementById('pnote').textContent=(curG>=0?'Showing only rows effective for “'+E[curG].n+'”. ':(DATA.explicitOnly?'Explicit-only mode: inherited ACEs were not traced. ':''))+
   'Scope chips reflect the inheritance propagation flags stored on the object; “child objects” covers non-OU entries such as users &amp; groups (those rows are shown on their own OU but not propagated into child OUs).';
}

/* ---------------- init ---------------- */
document.getElementById('domName').textContent=DATA.domain+(DATA.netbios?`  (${DATA.netbios})`:``);
refresh();
fit();
</script>
</body>
</html>
'@

$out = $HTML_TEMPLATE.Replace('__DATA__', $json)
[System.IO.File]::WriteAllText($OutputFile, $out, [System.Text.UTF8Encoding]::new($false))

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
$sw.Stop()
Write-Host ''
Write-Host "Done in $($sw.Elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Green
Write-Host ("  OUs mapped ............ {0}" -f $ous.Count)
Write-Host ("  Groups / users ....... {0} / {1}" -f (@($entities | Where-Object t -eq 'G').Count), (@($entities | Where-Object t -eq 'U').Count))
Write-Host ("  Permission rows ...... {0}" -f $totalRows)
Write-Host ("  Output ............... {0} ({1:N1} KB)" -f $OutputFile, ((Get-Item $OutputFile).Length / 1KB))
Write-Host ''
Write-Host "Open the file in any modern browser. Filter by group name from the dropdown; use search + zoom for navigation." -ForegroundColor Cyan
