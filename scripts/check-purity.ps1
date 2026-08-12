# check-purity.ps1 — vérifie la règle §1 de CALQUE-ARCHITECTURE.md :
# « Le cœur est pur. Aucune entrée-sortie dans la logique d'analyse. »
#
# Équivalent Windows de scripts/check-purity.sh. Deux contrôles pour
# chacun des crates purs :
#   1. l'arbre de dépendances (cargo tree -e normal) ne contient aucun
#      crate d'entrée-sortie ou d'exécution asynchrone ;
#   2. le source ne contient aucun usage de std::net::{Tcp,Udp}*,
#      std::fs, std::process, std::time::SystemTime ni tokio::.
#      (Les TYPES purs comme std::net::IpAddr ou ipnet::IpNet sont
#      autorisés : la cible, ce sont les entrées-sorties.)
#
# Code de sortie 0 si tout est pur, 1 sinon.

$ErrorActionPreference = "Continue"

$PureCrates = @("calque-model", "calque-space", "calque-engine", "calque-policy", "calque-diff")

$ForbiddenDeps = '^(tokio|russh|reqwest|hyper|openssl|openssl-sys|native-tls|mio|socket2|async-std|smol|ssh2|libssh2-sys|curl|ureq) v'

$ForbiddenSrc = 'std::net::(Tcp|Udp)|std::fs\b|std::process\b|std::time::SystemTime|std::io::(stdin|stdout|stderr)|\btokio::'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$failed = $false

Write-Host "== Contrôle 1 : arbre de dépendances (cargo tree -e normal) =="
foreach ($crate in $PureCrates) {
    $tree = cargo tree -p $crate -e normal --prefix none 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERREUR : cargo tree a échoué pour $crate :"
        $tree | ForEach-Object { Write-Host "    $_" }
        $failed = $true
        continue
    }
    $bad = $tree | Select-String -Pattern $ForbiddenDeps | ForEach-Object { $_.Line } | Sort-Object -Unique
    if ($bad) {
        Write-Host "IMPURETÉ : $crate dépend de :"
        $bad | ForEach-Object { Write-Host "    $_" }
        $failed = $true
    } else {
        Write-Host "ok : $crate"
    }
}

Write-Host ""
Write-Host "== Contrôle 2 : motifs d'entrée-sortie dans le source =="
foreach ($crate in $PureCrates) {
    $src = Join-Path "crates" (Join-Path $crate "src")
    if (-not (Test-Path $src)) {
        Write-Host "ERREUR : $src introuvable"
        $failed = $true
        continue
    }
    $hits = Get-ChildItem -Path $src -Recurse -Filter *.rs |
        Select-String -Pattern $ForbiddenSrc
    if ($hits) {
        Write-Host "IMPURETÉ : motif d'entrée-sortie dans $src :"
        $hits | ForEach-Object { Write-Host ("    {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) }
        $failed = $true
    } else {
        Write-Host "ok : $src"
    }
}

Write-Host ""
if ($failed) {
    Write-Host "ÉCHEC : le cœur n'est pas pur (cf. CALQUE-ARCHITECTURE.md §1)."
    exit 1
}
Write-Host "Le cœur est pur."
exit 0
