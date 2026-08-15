# Journal des modifications

Ce fichier suit le format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).
En v0, l'API et la ligne de commande peuvent encore changer sans préavis
majeur.

## [Unreleased]

Rien pour l'instant.

## [0.6.1] — 2026-08-14

### Ajouté

- **Paquets Linux `.deb` et `.rpm`** (amd64 et arm64), produits par nfpm
  depuis `packaging/nfpm.yaml` et attachés à chaque release, en plus des
  archives multi-plateformes et de l'image Docker CLI (`ghcr.io/yannbanas/calque`).
- **Nomenclature logicielle (SBOM)** au format SPDX jointe à la release.

## [0.6.0] — 2026-08-14

### Modifié

- **Fidélité par CHEMIN, plus par équipement.** Un verdict `path`/`test`/
  `reach` n'est plus déclaré « non ferme » simplement parce que
  l'équipement a une lacune de modélisation quelque part : il l'est
  UNIQUEMENT si une lacune touche le CHEMIN DÉCISIF du paquet analysé.
  C'est le moteur pur qui trancherend `Verdict::Unknown` sur le chemin
  (objet externe non résolu, ou règle sur-approximée décisive). Sur une
  configuration réelle par ailleurs partielle, un `calque path` vers un
  serveur bien modélisé est désormais FERME (code 0) SANS `--allow-partial`.
- **Jamais de faux « autorisé » (§6.3).** Les règles dont la correspondance
  est SUR-APPROXIMÉE dans le modèle — restriction par identité
  (`groups`/`users`/`fsso-groups`), `internet-service`, négation
  (`*-negate`), `nat46/64`, planification temporelle non-`always` — sont
  marquées (`Rule::approximation`). Si une telle règle peut décider sur le
  chemin (décisive, ou antérieure non exclue par zone), le verdict reste
  NON FERME avec la cause précise (« règle N sur-approximée, raison »), au
  lieu de risquer un ferme erroné.
- `calque test --allow-partial` : le drapeau ne contourne plus une fidélité
  globale ; il force l'évaluation sur la partie modélisée (règles
  approximées traitées sur leur correspondance modèle, objets externes non
  résolus = « ne matchent pas »), avec avertissement. Inutile pour tout
  chemin sans lacune décisive.

## [0.5.0] — 2026-08-14

### Ajouté

- **ICMP par type et code.** Les services ICMP/ICMPv6 avec `set icmptype`
  / `set icmpcode` sont modélisés : le type et le code sont portés par les
  dimensions de ports de l'algèbre (convention `ConcretePacket` :
  `dport` = type, `sport` = code), sans nouvelle dimension. Les questions
  d'accessibilité ICMP deviennent possibles : `calque path 10.0.0.1 ->
  10.0.0.2:8/icmp` interroge un echo request (ping), et `reach`/`test`
  acceptent les protocoles `icmp`/`icmp6`.

## [0.4.0] — 2026-08-14

### Modifié

- **Fidélité : le bruit cosmétique ne dégrade plus le modèle.** Les
  directives sans effet possible sur l'accessibilité (identifiants `uuid`,
  messages de remplacement, profils de sécurité UTM attachés aux
  politiques, réglages d'administration/GUI, options de débit/supervision
  d'interface, redondances déjà captées comme `src-addr-type`…) sont
  désormais RECONNUES et classées hors modèle (note Info), au lieu d'être
  comptées comme « non comprises ». Sur une configuration de collectivité
  réelle, les diagnostics passent de ~540 à ~45 — tous légitimes — et
  `model check` redevient lisible et actionnable. Ce n'est pas « deviner »
  (§6.3) : la liste est explicite et prudente ; toute clé qui POURRAIT
  peser sur le filtrage (restriction par identité `groups`/`users`,
  `internet-service`, négation `*-negate`, `nat46/64`, VRF non-défaut par
  route…) reste diagnostiquée, jamais avalée en silence.
- Le VRF d'une interface (`set vrf`) est modélisé (cloisonnement de
  routage) ; `set vrf 0` sur une route est le VRF racine (sans effet).

### Ajouté

- **Modélisation FortiGate étendue** — `firewall vip`/`vipgrp` (objets
  adresse + DNAT exact porté par les règles, éclatement traçable des
  règles multi-VIP), routes par objet (`set dstaddr`), `system sdwan`
  (zone des membres + une route candidate par WAN), sélecteurs IPsec
  phase2 (filtre de sortie du tunnel). Les tunnels, publications et sortie
  Internet d'une configuration réelle deviennent analysables.
- **Sortie de périmètre modélisé** — un flux qui quitte le modèle (Internet
  via WAN, site distant via tunnel) reçoit un verdict FERME (« autorisé,
  sort du périmètre modélisé via wan2 ») au lieu d'« indéterminé », dès
  lors que la destination n'appartient à aucun réseau du modèle et que
  l'interface de sortie n'a aucun lien. Un vrai trou de topologie interne
  reste indéterminé.
- **Routage ECMP par branches** — plusieurs routes optimales (SD-WAN
  multi-WAN) sont toutes évaluées : verdict ferme si elles s'accordent,
  sinon indéterminé avec le détail par branche (« wan1 : autorisé ;
  wan2 : refusé par la règle X »). Concret et symbolique.
- **`calque test --allow-partial`** — rend les verdicts sur la partie
  modélisée même quand le modèle est partiel (le cas d'une configuration
  réelle), avec un avertissement ; sans le drapeau, le refus de verdict
  ferme (§6.3) reste le défaut.

## [0.3.0] — 2026-08-13

La jonction bibliothèque : tout le chemin « texte de configuration →
modèle → verdict » devient une API publique sans I/O, consommable par un
programme tiers (Constat épingle cette version en dépendance git).
Décision documentée dans [ADR 002](docs/adr/002-jonction-bibliotheque.md).
La ligne de commande reste fonctionnellement identique.

### Ajouté

- **`calque_vendors::detect_and_import(raw: &str, label: &str)`** :
  détection automatique du constructeur par score de confiance + import,
  sur du texte fourni par l'appelant (aucune lecture de fichier). Erreurs
  structurées (`DetectImportError` : scores de détection, diagnostics) —
  jamais de supposition sous le seuil ou à égalité (§6.3). La CLI lit le
  fichier elle-même et réutilise cette fonction.
- **`calque_engine::prepare_for_engine`** : la préparation du modèle
  pour le moteur (évaluation des politiques à couple de zones au point
  de sortie — sémantique forward FortiGate) remonte du binaire dans le
  moteur, en API publique documentée, idempotente.
- **`calque_policy::{evaluate_flow, evaluate_flows, flow_packet}`** :
  l'évaluation des flux déclarés (la brique de `calque test`) remonte
  dans `calque-policy`, qui gagne sa dépendance prévue vers
  `calque-engine`. Le refus de verdict ferme sur un chemin traversant un
  import partiel (§6.3) vit dans la bibliothèque — la fidélité par
  équipement est un paramètre, l'honnêteté ne se contourne pas. La
  rustdoc de `evaluate_flow` montre le chemin complet :
  `detect_and_import` → `Network` (+ `prepare_for_engine` +
  `infer_links_from_subnets`) → `evaluate_flow` → `FlowResult`.
- **`--format json` sur `calque path` et `calque test`** : la trace
  complète structurée pour `path` (les avertissements texte restent au
  mode texte, les codes de sortie sont inchangés), les résultats de flux
  avec décompte (`tests`/`failures`) pour `test`.
- Libellés français des étapes et issues de trace dans `calque-engine`
  (`Stage::label`, `Outcome::label`, `Display`) : la justification d'un
  verdict est identique des deux côtés de la jonction.

### Modifié

- `FlowResult`/`FlowStatus` vivent désormais dans `calque-policy` (crate
  pur, au plus près de `evaluate_flow` qui les produit) ;
  `calque-report` les ré-exporte — les consommateurs existants compilent
  sans changement. En contrepartie, `calque-report` dépend de
  `calque-policy` (et transitivement du moteur).
- `calque test` prépare le modèle une fois pour toute la suite au lieu
  d'une fois par flux — sorties et codes de sortie inchangés.

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

[Unreleased]: https://github.com/yannbanas/calque/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/yannbanas/calque/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/yannbanas/calque/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/yannbanas/calque/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/yannbanas/calque/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yannbanas/calque/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yannbanas/calque/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yannbanas/calque/releases/tag/v0.1.0
