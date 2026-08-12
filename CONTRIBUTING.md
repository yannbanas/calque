# Contribuer à Calque

Merci de votre intérêt. Ce document explique comment construire le projet,
ce qu'une contribution doit respecter, et comment elle est examinée. Les
interactions dans le projet sont régies par le
[code de conduite](CODE_OF_CONDUCT.md) ; les problèmes de sécurité suivent
[SECURITY.md](SECURITY.md), pas le suivi d'incidents public.

Avant toute contribution de fond, lire
[CALQUE-ARCHITECTURE.md](CALQUE-ARCHITECTURE.md) — en particulier la
section 13, « Les principes à ne pas trahir ». Une PR qui contredit ces
principes sera refusée, quelle que soit sa qualité technique.

## Construire et tester

Prérequis : [Rust stable](https://rustup.rs). Le dépôt est un workspace
Cargo ; tout se joue à la racine.

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

L'intégration continue (`.github/workflows/ci.yml`) exécute exactement ces
commandes, plus la vérification de pureté et `cargo-deny`. Une PR dont un
de ces jobs échoue n'est pas relue.

### La vérification de pureté

Les crates du cœur (`calque-model`, `calque-space`, `calque-engine`,
`calque-policy`, `calque-diff`) ne dépendent ni de `tokio`, ni du réseau,
ni du système de fichiers, ni de l'horloge. Cette règle est vérifiée par
un script, à lancer avant de pousser si vous touchez à ces crates :

```bash
bash scripts/check-purity.sh          # Linux, macOS, Git Bash
```

```powershell
powershell -File scripts/check-purity.ps1   # Windows
```

### Tests de propriétés (proptest)

L'algèbre d'espace d'en-têtes (`calque-space`) est couverte par des tests
de propriétés (lois des ensembles, cohérence symbolique/concret). Ils font
partie de `cargo test --workspace`. Pour un passage plus exhaustif en
local :

```bash
PROPTEST_CASES=10000 cargo test -p calque-space
```

Si `proptest` trouve un contre-exemple, il écrit une graine dans un
fichier `proptest-regressions/` : ce fichier fait partie de la correction
et doit être commité avec elle.

### Tests d'instantanés (insta)

Les analyseurs (`calque-parse`) sont couverts par des instantanés `insta`
(`crates/calque-parse/src/snapshots/`). Quand une modification change une
sortie d'analyse :

```bash
cargo install cargo-insta      # une fois
cargo insta review             # examiner chaque différence, une par une
```

Un instantané modifié est un changement de comportement : la PR doit dire
pourquoi la nouvelle sortie est la bonne. N'utilisez pas `cargo insta
accept` en aveugle.

### Fuzzing

Les analyseurs traitent des entrées non fiables ; tout panic, débordement
ou blocage est un bug, même sur entrée absurde. Les cibles vivent dans
`fuzz/` (espace de travail séparé) et tournent chaque semaine en CI
(`.github/workflows/fuzz.yml`). En local :

```bash
cargo install cargo-fuzz       # nécessite la toolchain nightly
cargo +nightly fuzz run parse_fortigate    # ou parse_cisco_ios, import_fortigate
```

Un crash reproduit se rejoue avec
`cargo +nightly fuzz run <cible> fuzz/artifacts/<cible>/crash-…`.

## Ce qu'une PR doit respecter

Ces règles ne sont pas des préférences de style ; elles sont ce qui rend
la sortie de l'outil digne de confiance.

1. **Le cœur reste pur.** Aucune entrée-sortie, aucune horloge, aucun
   réseau dans les crates d'analyse. Pas de nouvelle dépendance dans un
   crate pur sans discussion préalable — la CI le vérifie, mais la
   question se règle avant, dans l'issue.
2. **Ne jamais deviner.** Une directive non comprise produit un
   diagnostic (`Diagnostic`, fidélité `Partial`), jamais une supposition
   silencieuse. Si votre analyseur rencontre une construction qu'il ne
   sait pas traiter, il le dit ; il n'invente pas un comportement
   « probable ». Un verdict faux est pire qu'une absence de verdict.
3. **L'ordre des règles est sémantique.** Une politique de filtrage est
   une liste ordonnée : la première règle qui correspond décide. Aucune
   transformation (tri, déduplication, normalisation) ne doit réordonner
   les règles ou changer le résultat d'une évaluation.
4. **`SourceSpan` partout.** Chaque élément de la représentation
   intermédiaire porte son fichier et sa ligne d'origine. La trace est le
   produit : une règle sans span rend un verdict injustifiable et ne
   passera pas la relecture.
5. **Le projet est en français.** Documentation, commentaires, messages
   d'erreur, sorties de l'outil, messages de commit : en français, sobre
   et précis. Les identifiants de code suivent l'usage Rust (anglais).

## Le processus

- **Issue d'abord pour les gros changements** : nouveau constructeur,
  modification du moteur ou de l'algèbre, nouvelle commande, nouvelle
  dépendance d'un crate pur. Décrire le problème et l'approche envisagée
  avant d'écrire le code — cela évite de refuser une PR sur laquelle vous
  avez passé du temps. Les corrections de bugs et les petites
  améliorations peuvent arriver directement en PR.
- **ADR pour les décisions d'architecture.** Toute décision qui engage la
  structure du projet (représentation des données, frontière entre
  couches, choix d'algorithme central) est documentée et datée dans
  [docs/adr/](docs/adr/), suivant le
  [gabarit](docs/adr/000-template.md). L'ADR fait partie de la PR qui
  applique la décision.
- Les PR sont relues sur le fond : justesse, respect des règles
  ci-dessus, tests qui prouvent le comportement. Une PR courte et
  focalisée est relue vite ; une PR qui mélange trois sujets attendra.

## Contribuer une configuration au corpus

Le corpus (`corpus/`) est ce qui protège le projet des erreurs de
sémantique constructeur — c'est une des contributions les plus utiles.
Lire impérativement [corpus/README.md](corpus/README.md) avant quoi que
ce soit. L'essentiel :

- **L'anonymisation est obligatoire, sans exception.** Jamais de
  configuration réelle non anonymisée, même partiellement, même « juste
  un extrait ». `calque scrub` aide à l'anonymisation ; la relecture
  manuelle du résultat reste obligatoire (commentaires et descriptions
  compris).
- **Autorisation écrite** du propriétaire si la configuration n'est pas
  la vôtre.
- Chaque cas du corpus est accompagné d'un `flows.yaml` décrivant les
  réponses attendues — c'est ce qui en fait un test et pas un simple
  échantillon.

Toute contribution qui ne respecte pas ces règles est refusée et purgée
de l'historique.

## Style de commit

- En français, comme le reste du projet.
- Une ligne de titre courte (au plus ~72 caractères) qui dit ce que le
  commit fait, par exemple :
  `Analyse des groupes d'adresses FortiGate (addrgrp)`.
- Un corps quand le pourquoi n'est pas évident — c'est le pourquoi qui
  intéresse le lecteur dans deux ans, le quoi se lit dans le diff.
- Un commit = un changement cohérent. Les instantanés `insta` et les
  fichiers `proptest-regressions/` modifiés font partie du commit qui les
  justifie.
