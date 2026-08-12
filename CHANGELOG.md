# Journal des modifications

Ce fichier suit le format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).
En v0, l'API et la ligne de commande peuvent encore changer sans préavis
majeur.

## [Unreleased]

État actuel du développement v0 : les étapes S1 à S6 de
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
  sous-réseau + `topology.yaml`).
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

[Unreleased]: https://github.com/yannbanas/calque/commits/main
