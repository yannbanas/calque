#!/usr/bin/env bash
# check-purity.sh — vérifie la règle §1 de CALQUE-ARCHITECTURE.md :
# « Le cœur est pur. Aucune entrée-sortie dans la logique d'analyse. »
#
# Deux contrôles, pour chacun des crates purs :
#   1. l'arbre de dépendances (cargo tree -e normal) ne doit contenir
#      aucun crate d'entrée-sortie ou d'exécution asynchrone ;
#   2. le source ne doit contenir aucun usage de std::net::{Tcp,Udp}*,
#      std::fs, std::process, std::time::SystemTime ni tokio::.
#      (Les TYPES purs comme std::net::IpAddr ou ipnet::IpNet sont
#      autorisés : la cible, ce sont les entrées-sorties.)
#
# Sortie 0 si tout est pur, 1 sinon. Utilisé par l'intégration continue.

set -u

PURE_CRATES="calque-model calque-space calque-engine calque-policy calque-diff"

# Crates interdits dans l'arbre de dépendances normal d'un crate pur.
FORBIDDEN_DEPS='tokio|russh|reqwest|hyper|openssl|openssl-sys|native-tls|mio|socket2|async-std|smol|ssh2|libssh2-sys|curl|ureq'

# Motifs interdits dans le source (I/O, horloge murale, réseau, processus).
FORBIDDEN_SRC='std::net::(Tcp|Udp)|std::fs\b|std::process\b|std::time::SystemTime|std::io::(stdin|stdout|stderr)|\btokio::'

cd "$(dirname "$0")/.." || exit 1

fail=0

echo "== Contrôle 1 : arbre de dépendances (cargo tree -e normal) =="
for crate in $PURE_CRATES; do
    tree=$(cargo tree -p "$crate" -e normal --prefix none 2>&1)
    if [ $? -ne 0 ]; then
        echo "ERREUR : cargo tree a échoué pour $crate :"
        echo "$tree"
        fail=1
        continue
    fi
    bad=$(printf '%s\n' "$tree" | grep -E "^($FORBIDDEN_DEPS) v" | sort -u)
    if [ -n "$bad" ]; then
        echo "IMPURETÉ : $crate dépend de :"
        printf '%s\n' "$bad" | sed 's/^/    /'
        fail=1
    else
        echo "ok : $crate"
    fi
done

echo
echo "== Contrôle 2 : motifs d'entrée-sortie dans le source =="
for crate in $PURE_CRATES; do
    src="crates/$crate/src"
    if [ ! -d "$src" ]; then
        echo "ERREUR : $src introuvable"
        fail=1
        continue
    fi
    hits=$(grep -rEn "$FORBIDDEN_SRC" "$src" 2>/dev/null)
    if [ -n "$hits" ]; then
        echo "IMPURETÉ : motif d'entrée-sortie dans $src :"
        printf '%s\n' "$hits" | sed 's/^/    /'
        fail=1
    else
        echo "ok : $src"
    fi
done

echo
if [ "$fail" -ne 0 ]; then
    echo "ÉCHEC : le cœur n'est pas pur (cf. CALQUE-ARCHITECTURE.md §1)."
    exit 1
fi
echo "Le cœur est pur."
exit 0
