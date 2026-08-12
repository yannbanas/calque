# Performance — mesures et optimisations

Mesures faites le 2026-08-12 sur la machine de développement :
Intel Core i5-9300H (4 cœurs, 2,4 GHz), 16 Go, Windows 11, rustc 1.97.1,
profil `bench` (qui hérite de `[profile.release]` : `lto = "thin"`,
`codegen-units = 1`). Les benchs sont sous `crates/*/benches/` (criterion),
entièrement déterministes (aucune source d'aléa). Reproduire :

```sh
cargo bench -p calque-space -p calque-parse -p calque-vendors -p calque-engine
```

Précaution d'honnêteté : machine portable, autres processus actifs pendant
certaines campagnes — le bruit observé sur les gros cas atteint ±20 %
(vérifié en répétant les runs). Les ordres de grandeur et les pentes de
complexité, eux, sont stables. Les chiffres sont les médianes criterion.

## 1. Résultats — état actuel du code

### Import FortiGate (couches 1 + 2)

Configurations synthétiques réalistes générées dans les benchs
(interfaces, routes, adresses, groupes, services, politiques — toutes les
directives comprises par l'adaptateur, fidélité complète).

| Taille (lignes) | `fortigate::parse` (couche 1) | `import_str` (couches 1+2) |
|---|---|---|
| 1 200  | 0,55 ms | 0,77 ms |
| 10 716 | 4,6 ms  | 7,1 ms  |
| 52 436 | 25 ms   | 42 ms   |

Complexité observée : **linéaire** (~2,1 M lignes/s en couche 1,
~1,2–1,5 M lignes/s pour l'import complet).

> **Budget indicatif : une configuration de 11 000 lignes s'importe en
> ~8 ms.** L'import n'est pas et ne sera pas le goulot.

### Algèbre de pavés (`calque-space`)

Ensembles de n pavés « flux » (src /24, dst /24, tcp, un port) ;
« disjoints » = aucune paire ne se rencontre, « identiques » = les deux
opérandes sont le même ensemble.

| Opération | n = 10 | n = 100 | n = 1000 |
|---|---|---|---|
| `from_cubes` (normalisation)   | 26 µs | 1,8 ms | 152 ms |
| `union` disjoints              | 16 µs | 0,86 ms | 62 ms |
| `union` identiques             | 32 µs | 0,39 ms | 23 ms |
| `intersect` disjoints          | 3,3 µs | 0,14 ms | 15 ms |
| `intersect` identiques         | 10 µs | 0,39 ms | 31 ms |
| `subtract` disjoints           | 4,4 µs | 0,14 ms | 13 ms |
| `subtract` identiques          | 22 µs | 0,27 ms | 13 ms |

Complexité observée : **quadratique** en nombre de pavés (×100 pavés →
~×10 000 sur le temps). C'est structurel : chaque opération compare des
paires de pavés (fusion, disjonction). Les bornes du moteur symbolique
(`MAX_CUBES = 1024`, `MAX_UNION_CUBES = 2048`) plafonnent n, donc le pire
cas d'une opération unitaire reste de l'ordre de 10²–10³ ms, et les cas
réels (quelques dizaines de pavés) restent sous la milliseconde.

Fragmentation en chaîne (`full()` moins n flux successifs — le motif
« que reste-t-il après n règles ? ») :

| n soustractions | 4 | 8 | 16 | 32 | 64 |
|---|---|---|---|---|---|
| temps | 44 µs | 138 µs | 0,51 ms | 2,4 ms | 14 ms |

Croissance ~quadratique (le reste se fragmente, chaque soustraction
balaie plus de pavés). À 64 règles on est à 14 ms : acceptable, borné par
`MAX_CUBES` dans le moteur.

### Moteur (`calque-engine`)

| Requête | Taille | Temps |
|---|---|---|
| `trace_packet` (pire cas : seule la DERNIÈRE règle correspond) | 1 000 règles | 27 µs |
| | 5 000 règles | 120 µs |
| `reach_to` (réseau 2 équipements, politique 100 règles) | 100 règles | 4,6 ms |
| `dead_rules`, règles deux à deux disjointes | 1 000 règles | 13 ms |
| `dead_rules`, groupes réalistes (500 règles réellement mortes) | 1 000 règles | 15 ms |
| `dead_rules`, cas pathologique (union des masques → 999 pavés) | 50 / 100 / 200 / 1 000 | 0,9 / 2,8 / 11 / 228 ms |

- `trace_packet` est **linéaire** et négligeable : ~24 ns par règle
  balayée. Des milliers de requêtes concrètes par seconde sont possibles
  sans parallélisme.
- `dead_rules` est **quadratique** par construction (chaque règle est
  confrontée à toutes ses antérieures) : la pente mesurée sur le cas
  pathologique est ~n^1,9. À 1 000 règles mutuellement chevauchantes on
  paie ~0,2 s ; sur un profil réaliste (chevauchements locaux), ~15 ms.

> **Budget indicatif pour l'objectif « quelques milliers de règles » :**
> import ~10 ms, une trace concrète < 1 ms, `dead_rules` de quelques
> dizaines de ms (réaliste) à quelques secondes (politique entièrement
> chevauchante à 5 000 règles, extrapolation quadratique : ~5 s).

## 2. Optimisations réalisées (mesurées avant/après)

Le code d'origine était correct mais cubique sur les unions : la
normalisation relançait un balayage complet des paires après CHAQUE
fusion, et chaque test de fusion (`try_merge`) passait par des inclusions
CALCULÉES PAR SOUSTRACTION (allocantes) sur chaque dimension. Mesures
« avant » faites au même endroit, profil release par défaut (sans LTO —
l'effet du profil est isolé au §3 ; les gains ci-dessous sont donc du
code, pas du profil).

| Bench | Avant | Après | Gain |
|---|---|---|---|
| `from_cubes` n=100 | 187 ms | 1,8 ms | ×100 |
| `from_cubes` n=1000 | ~110 s (une seule exécution chronométrée) | 152 ms | ~×700 |
| `union` disjoints n=100 | 383 ms | 0,86 ms | ×450 |
| `intersect` disjoints n=1000 | 222 ms¹ | 15 ms | ×15 |
| fragmentation n=64 | 394 ms | 14 ms | ×28 |
| `dead_rules` disjointes n=1000 | 203 ms | 13 ms | ×16 |
| `dead_rules` groupes n=1000 | 270 ms | 15 ms | ×18 |
| `dead_rules` pathologique n=200 | 1,40 s | 11 ms | ×130 |
| `dead_rules` pathologique n=1000 | non mesurable (extrapolé > 30 s) | 228 ms | — |
| `reach_to` 100 règles | 10 ms | 4,6 ms | ×2 |

¹ mesuré à mi-parcours, après la première vague d'optimisations.

Ce qui a été changé (tout dans `calque-space`, plus une ligne dans
`calque-engine/src/dead.rs`) :

1. **Inclusions directes par dimension** (`prefix.rs`, `ports.rs`) :
   `contains_set` ne passe plus par une soustraction complète.
   - Préfixes : `b ⊆ ensemble` ⟺ un préfixe de la forme normalisée
     contient `b` (l'agrégation des frères au point fixe garantit qu'un
     bloc aligné entièrement couvert est représenté par un seul préfixe).
   - Ports : un intervalle inclus dans une union d'intervalles disjoints
     ET non adjacents tient nécessairement dans UN intervalle.
2. **Normalisation incrémentale** (`headerset.rs`) : insertion avec
   fusion en cascade (`insert_merged`) au lieu du re-balayage complet
   après chaque fusion — le point fixe est atteint en O(n²) au lieu de
   O(n³).
3. **`union` sans re-normalisation du membre gauche** : A étant déjà sans
   paire fusionnable, seuls les morceaux de B \ A sont insérés.
4. **`subtract` paresseux** : un pavé disjoint du soustracteur est déplacé
   sans copie ; si rien n'a été découpé, le résultat est `self` déjà
   normalisé (aucune re-normalisation).
5. **`is_disjoint` sans allocation** (`Cube`, `PrefixSet`, `PortRanges`,
   `HeaderSet`) : deux pavés sont disjoints dès qu'une dimension l'est.
   Utilisé comme pré-filtre dans `intersect` et dans le test n²/2 de
   `dead_rules` (qui construisait l'intersection pour la jeter).
6. **Chemin rapide de `HeaderSet::contains_set`** : si chaque pavé de
   `other` est contenu dans UN pavé de `self` (test suffisant, sans
   allocation), inutile de soustraire.

Filet de sécurité : les 64 tests engine + 46 tests space (proptests
compris) passent inchangés, et quatre NOUVELLES propriétés proptest
épinglent les chemins directs sur leurs définitions ensemblistes
(`contains_set` ≡ soustraction vide, `is_disjoint` ≡ intersection vide).

## 3. Effet du profil release (mesuré à code constant)

`[profile.release]` du Cargo.toml racine : `lto = "thin"`,
`codegen-units = 1`, `strip = "symbols"` (le profil `bench` en hérite).

| Bench (code identique) | Profil par défaut | thin-LTO + CU=1 |
|---|---|---|
| `import_str` 10 716 lignes | 23,9 ms | 7,1–7,9 ms (3 runs) |
| `fortigate::parse` 10 716 lignes | 15,3 ms | 4,6 ms |

Soit ~×3 sur l'import — l'inlining inter-crates (model/parse/vendors)
paie. `lto = "fat"` a été essayé : 10k identique (7,9 ms), 50k dans le
bruit de la machine (39–65 ms selon le run pour les deux variantes) ;
« thin » est retenu (compilation nettement plus rapide, gain
indiscernable). `cargo build --release -p calque-cli` vérifié après
réglage.

## 4. Ce qui n'a PAS été optimisé, et pourquoi

- **`trace_packet` / chemin concret** : 24 ns par règle, linéaire. Rien à
  faire.
- **Couche 1 (`calque-parse`)** et **couche 2 (`calque-vendors`)** :
  linéaires, ~8 ms pour 11 k lignes. Rien à faire (et leur `src/` est
  hors périmètre de ce chantier).
- **Le caractère quadratique de `dead_rules` et des opérations
  d'ensembles** : structurel (paires de règles, paires de pavés), borné
  par `MAX_CUBES`/`MAX_UNION_CUBES`, et à 228 ms pour le pire cas à
  1 000 règles il ne justifie pas de complexité supplémentaire
  (indexation spatiale, tri par dimension…). Un code simple et juste vaut
  mieux ; à revisiter seulement si les politiques réelles dépassent
  ~5 000 règles mutuellement chevauchantes.
- **Parallélisme (`rayon`)** : prévu par l'architecture (§9) « quand les
  requêtes se comptent en milliers » — pas avant.

## 5. Alertes hors périmètre (constatées, non touchées)

- `crates/calque-engine/src/engine.rs:71` (`owner_of_address`) et
  `engine.rs:96` (`locate_source`) balaient TOUTES les interfaces de tous
  les équipements à chaque appel, et `owner_of_address` est rappelé à
  chaque saut livré. Linéaire en taille du réseau, invisible aujourd'hui
  (< 1 µs sur 2 équipements) ; si le parc atteint des centaines
  d'équipements × des milliers de requêtes, construire un index
  adresse → interface une fois par `Network` serait la bonne réponse.
  (Fichiers dans le périmètre engine, mais l'optimisation n'est pas
  justifiée par les mesures actuelles — notée pour mémoire.)
- `crates/calque-engine/src/reach.rs:81` : `reach_to` lance une
  propagation symbolique COMPLÈTE par interface d'entrée. Sur un réseau
  de N équipements le coût est N × (coût d'une trace symbolique). C'est
  l'endroit naturel pour `rayon` (les propagations sont indépendantes).
- Rien de préoccupant vu dans les autres crates depuis les benchs ;
  `calque-diff`/`calque-cli` n'ont pas été mesurés (hors périmètre).

## 6. Reproduire une comparaison avant/après

Les baselines criterion `avant`, `apres` et `final` sont conservées dans
`target/criterion/` (non versionné). Pour une nouvelle campagne :

```sh
cargo bench -p calque-space -- --save-baseline ref
# ... modification ...
cargo bench -p calque-space -- --baseline ref
```
