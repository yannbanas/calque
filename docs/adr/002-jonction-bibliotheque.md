# ADR 002 — Les briques d'évaluation sortent du binaire : jonction bibliothèque

- **Date** : 2026-08-13
- **Statut** : accepté

## Contexte

Constat (l'outil jumeau d'horodatage de faits) doit consommer Calque en
bibliothèque : il fournit des configurations réseau historiques signées,
Calque évalue l'accessibilité, et le verdict redevient un fait horodaté
chez Constat. Or les briques nécessaires vivaient dans `calque-cli`, un
crate binaire non réutilisable :

- la préparation du modèle pour le moteur (`prepare_for_engine`,
  sémantique forward FortiGate) était dans `backend.rs` ;
- la détection automatique du constructeur par score de confiance était
  soudée à la lecture du fichier (`import_config(&Path)`) ;
- l'évaluation d'un flux déclaré (`run_flow`) et la construction du
  paquet représentatif (`flow_packet`) étaient dans `commands.rs`, et le
  type de résultat (`FlowResult`) vivait dans `calque-report`.

Alternatives considérées : exposer `calque-cli` comme bibliothèque
(refusé : cela entraînerait clap, miette et l'I/O du projet `.calque/`
chez tout consommateur) ; créer un crate « façade » supplémentaire
(refusé : onze crates suffisent, chaque brique a déjà un crate naturel).

## Décision

Chaque brique remonte dans le crate du cœur qui lui correspond, en API
publique, sans I/O :

- `calque_engine::prepare_for_engine(&Network) -> Network` — la
  préparation est une transformation de modèle, elle appartient au
  moteur. Idempotente ; la CLI la ré-exporte (`backend::prepare_for_engine`).
- `calque_vendors::detect_and_import(raw: &str, label: &str)
  -> Result<DetectedImport, DetectImportError>` — la sélection par score
  parmi `all_adapters()` appartient à la couche constructeur. Le texte
  arrive de l'appelant ; la CLI lit le fichier elle-même (bornes de
  taille comprises) et habille les erreurs structurées en messages
  miette portant le chemin.
- `calque_policy::{evaluate_flow, evaluate_flows, flow_packet}` — un
  flux déclaré est un test : son évaluation appartient à `calque-policy`
  (qui gagne sa dépendance, prévue de longue date, vers `calque-engine`).
  Les types `FlowResult`/`FlowStatus` déménagent de `calque-report` vers
  `calque-policy`, dans CE sens : `calque-policy` est un crate pur
  vérifié par la CI, et une dépendance policy → report inverserait la
  direction rendu ← données. `calque-report` les ré-exporte pour
  compatibilité et garde tous les rendus.

L'évaluation reçoit la fidélité par équipement
(`&BTreeMap<DeviceId, Fidelity>`) : le refus de verdict ferme sur un
chemin traversant un import partiel (§6.3) reste dans la bibliothèque,
pas dans la CLI — un consommateur ne peut pas l'oublier.

## Conséquences

- Le chemin complet « texte de configuration → modèle → verdict » se
  parcourt sans binaire : `detect_and_import` → `Network`
  (+ `prepare_for_engine`, `infer_links_from_subnets`) → `evaluate_flow`
  → `FlowResult`. C'est le contrat que Constat épingle (dépendance git,
  v0.3.0).
- La CLI reste fonctionnellement identique (mêmes sorties, mêmes codes
  de sortie — les tests de bout en bout le vérifient) ; `calque test`
  prépare désormais le modèle une fois pour toute la suite au lieu d'une
  fois par flux.
- Les libellés français des étapes et issues de trace
  (`Stage::label`, `Outcome::label`) vivent dans `calque-engine` pour
  que la justification (`FlowResult::detail`) soit identique des deux
  côtés de la jonction.
- Coût assumé : `calque-report` dépend désormais de `calque-policy`
  (donc, transitivement, du moteur) — le découplage « rendus sans
  moteur » de la phase de construction parallèle n'a plus lieu d'être.
- L'API d'évaluation demande un modèle PRÉPARÉ ; l'oublier ne produit
  jamais un verdict faux — le moteur refuse honnêtement (`Unknown`,
  diagnostic `EgressZoneUnknownAtIngress`).
