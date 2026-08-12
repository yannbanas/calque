<!-- Décrire ce que fait la PR et pourquoi. Lier l'issue le cas échéant
     (« Closes #12 »). Pour les gros changements, une issue préalable est
     attendue — voir CONTRIBUTING.md. -->

## Liste de contrôle

- [ ] `cargo test --workspace` est vert
- [ ] `cargo fmt --all --check` et `cargo clippy --workspace --all-targets -- -D warnings` passent
- [ ] Si un crate pur est touché (`calque-model`, `calque-space`, `calque-engine`, `calque-policy`, `calque-diff`) : `scripts/check-purity.sh` (ou `.ps1`) passe, aucune dépendance impure ajoutée
- [ ] Si la PR acte une décision d'architecture : un ADR daté est inclus (`docs/adr/`, gabarit `000-template.md`)
- [ ] Si des instantanés `insta` changent : la PR explique pourquoi la nouvelle sortie est la bonne
- [ ] **Aucune configuration réelle non anonymisée** — ni dans le code, ni dans les tests, ni dans la description (voir `corpus/README.md`)
