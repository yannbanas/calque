# Journal des modifications

Ce fichier suit le format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).
En v0, l'API et la ligne de commande peuvent encore changer sans préavis
majeur.

## [Unreleased]

Rien pour l'instant.

## [0.2.0] — 2026-08-13

### Ajouté

- **Deux nouveaux constructeurs** : OPNsense/pfSense (config.xml, couche 1
  XML sécurisée sans résolution d'entités) et nftables (fichiers de règles
  et sortie `nft list ruleset`, chaînes de base et régulières via `Jump`,
  sets/defines résolus tard, `ct state` traité sans dégrader la fidélité).
- **Format export YAML FortiOS** : détection automatique et conversion
  vers le même arbre que le CLI (testé par égalité stricte des deux
  imports) — les exports d'outils de sauvegarde s'importent directement.
- **S7 — collecte et confrontation au réel** (feature Cargo `collect`,
  désactivée par défaut : l'analyse hors ligne ne compile pas la pile
  SSH) : `calque collect` (SSH lecture seule stricte avec liste blanche,
  voisins LLDP/CDP fusionnés dans la topologie) et
  `calque verify --against-reality` (§11.2).
- Objets adresse FortiGate `interface-subnet` modélisés (sous-réseau
  exporté ou déduit des adresses de l'interface).

### Corrigé

- **Import : sélection par adaptateur, plus jamais par constructeur** —
  deux adaptateurs peuvent servir le même constructeur (FortiGate CLI et
  export YAML) ; l'ancien dispatch envoyait le YAML vers l'adaptateur CLI
  et cassait aussi l'import Cisco/OPNsense/nftables via le binaire.
- **`calque scrub` : plus jamais d'anonymisation incomplète silencieuse**
  — avertissement explicite quand le format n'est pas reconnu ; secrets au
  format YAML (`password: [ENC, …]`, clés privées, certificats) caviardés ;
  collecte des noms sur l'export YAML.
- `calque model dead-rules` : une règle irrésoluble hors ligne (objet
  fqdn/geography, VIP…) est exclue avec diagnostic au lieu d'interrompre
  toute l'analyse (abstention sûre, jamais un faux positif).

### Sécurité

- quick-xml 0.37 → 0.41 (RUSTSEC-2026-0194, RUSTSEC-2026-0195).
- RUSTSEC-2023-0071 (`rsa` via russh, feature `collect` désactivée par
  défaut) : exception datée et justifiée dans `deny.toml`, aucun
  correctif amont disponible.

## [0.1.0] — 2026-08-12

Première version publiée. Les étapes S1 à S6 de
[CALQUE-ARCHITECTURE.md](CALQUE-ARCHITECTURE.md) sont livrées. L'outil
fonctionne de bout en bout sur le corpus, mais n'est pas encore éprouvé
sur des configurations de production.

### Ajouté

- **Analyse FortiGate et Cisco IOS** en deux couches : tokenizers par
  format (blocs FortiGate, indentation IOS) avec spans exacts
  (`calque-parse`), puis sémantique constructeur vers la représentation
  intermédiaire (`calque-vendors`). Toute directive non comprise produit
  un diagnostic, jamais une supposition.
- **Représentation intermédiaire** (`calque-model`) : équipements,
  interfaces, routes, règles, avec traçabilité `SourceSpan` (fichier +
  ligne) sur chaque élément et fidélité du modèle (`Complete` /
  `Partial`).
- **Algèbre d'espace d'en-têtes** (`calque-space`) : pavés 5D,
  union/intersection/soustraction normalisées, IPv4 et IPv6, validée par
  tests de propriétés (ADR 001 : pavés plutôt que diagrammes de décision
  binaires).
- **Moteur d'accessibilité** (`calque-engine`), concret et symbolique :
  localisation, filtres, NAT, routage par plus long préfixe, détection de
  boucles, traces justifiées règle par règle avec `shadowed_by`.
- **Commandes** : `calque import` (fichier ou répertoire, détection du
  constructeur), `calque model check` (fidélité du modèle),
  `calque model dead-rules` (règles masquées ou à l'ensemble vide,
  analyse prudente sans faux positif), `calque path --explain` (verdict
  concret tracé), `calque reach --to/--from` (mode symbolique agrégé,
  sortie texte ou JSON), `calque test` (suite de flux `flows.yaml`,
  sortie texte ou JUnit, code de sortie non nul en cas d'écart),
  `calque plan --candidate` (flux rompus, corrigés, et ouvertures que
  personne n'a demandées), `calque topology check` (liens inférés par
  sous-réseau + `topology.yaml`), `calque scrub` (anonymisation cohérente :
  relations de sous-réseau préservées, secrets caviardés, table de
  correspondance optionnelle via `--map`).
- **Validation** : tests de propriétés (`proptest`) sur l'algèbre,
  instantanés (`insta`) sur les analyseurs, corpus de configurations
  anonymisées avec réponses attendues, fuzzing hebdomadaire des
  analyseurs (`cargo-fuzz` : `parse_fortigate`, `parse_cisco_ios`,
  `import_fortigate`), vérification de pureté du cœur en CI,
  `cargo-deny`.
- **Image Docker** statique publiée sur GHCR à chaque commit sur `main`
  (`ghcr.io/yannbanas/calque`), sans shell, lecture/écriture limitées au
  répertoire monté sur `/work`.

### Limites connues

- Deux constructeurs seulement (FortiGate, Cisco IOS) ; pfSense/OPNsense,
  nftables et les suivants viendront un par un.
- Pas encore de collecte en ligne (S7 : SSH, LLDP) — l'entrée est
  toujours un fichier.
- L'anonymisation de `calque scrub` est structurelle, pas un chiffrement :
  relire le résultat avant diffusion reste obligatoire (§11.4).
- Pas éprouvé sur des configurations de production ; les retours de
  terrain sont bienvenus.

[Unreleased]: https://github.com/yannbanas/calque/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yannbanas/calque/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yannbanas/calque/releases/tag/v0.1.0
