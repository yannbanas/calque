# Fuzzing des analyseurs

Concrétise l'exigence §11.3 de l'architecture : les configurations sont
des entrées **non fiables**, potentiellement issues d'un équipement
compromis. **Tout panic est un bug, même sur entrée absurde** — y compris
débordement arithmétique, indexation hors bornes, récursion infinie ou
blocage. `Ok` comme `Err` sont des sorties acceptables ; une interruption
du processus ne l'est jamais.

## Cibles

| Cible | Ce qu'elle exerce |
|---|---|
| `parse_fortigate` | couche 1 : `calque_parse::fortigate::parse` |
| `parse_cisco_ios` | couche 1 : `calque_parse::cisco_ios::parse` |
| `import_fortigate` | couches 1+2 : `FortigateAdapter::import_str` (tokenizer **et** conversion sémantique en IR — la cible la plus profonde) |

Chaque cible accepte des octets arbitraires : l'UTF-8 valide passe tel
quel, le reste passe par `String::from_utf8_lossy` pour couvrir quand
même les séquences invalides.

## Lancer localement

Nécessite le toolchain **nightly** et `cargo-fuzz` :

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Depuis la racine du dépôt :

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run parse_fortigate -- -max_total_time=120 -timeout=10
```

### Windows (MSVC) — limitation connue

`cargo fuzz build` échoue en liaison sous MSVC x64 si le composant
« C++ AddressSanitizer » de Visual Studio n'est pas installé (symboles
`clang_rt.asan*` et sancov manquants, y compris avec `-s none`).
Solutions : installer ce composant via Visual Studio Installer, ou
fuzzer dans un conteneur Linux **à base de glibc** (Debian : `rust:slim`
+ nightly + `cargo install cargo-fuzz`, puis `-s none` si ASan n'est pas
disponible — les panics et les débordements restent détectés,
`debug-assertions` étant actifs).

**Piège vérifié** : ne PAS fuzzer sous Alpine/musl. Les intercepteurs de
libFuzzer (`FuzzerInterceptors.cpp`, `memmem`/`strcmp`…) reposent sur
`dlsym(RTLD_NEXT, …)`, qui échoue silencieusement sous musl : le mutateur
appelle alors un pointeur nul et produit de FAUX crashs SIGSEGV avec un
artefact vide (`crash-da39a3…`, SHA-1 de l'entrée vide), sans aucun bug
dans le code fuzzé.

La CI (`.github/workflows/fuzz.yml`) fuzze sous `ubuntu-latest` (glibc)
chaque semaine, à chaque poussée touchant les analyseurs, et à la
demande.

## Reproduire un crash

libFuzzer écrit l'entrée fautive dans `fuzz/artifacts/<cible>/crash-…`
(en CI : téléchargeable comme artefact `artefacts-fuzz-<cible>`). Pour
rejouer :

```sh
cargo +nightly fuzz run parse_fortigate fuzz/artifacts/parse_fortigate/crash-...
```

Puis minimiser avant d'archiver :

```sh
cargo +nightly fuzz tmin parse_fortigate fuzz/artifacts/parse_fortigate/crash-...
```

Chaque crash minimisé est archivé dans `fuzz/regressions/` avec une
explication dans son README — c'est le dossier des bugs connus en
attente de correction, et le corpus de non-régression une fois corrigés.

## Corpus

`fuzz/corpus/<cible>/` amorce chaque cible avec les fixtures de
`corpus/` (racine du dépôt) et des cas dégénérés écrits à la main
(bloc non fermé, guillemets non fermés, imbrication profonde, ligne
géante, valeurs sémantiques absurdes). libFuzzer y ajoute au fil de
l'eau les entrées qui découvrent de la couverture nouvelle.
