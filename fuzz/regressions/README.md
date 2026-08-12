# Crashs archivés

Dossier des entrées fautives **minimisées** (`cargo fuzz tmin`) trouvées
par le fuzzing, en attente de correction puis conservées comme corpus de
non-régression. Chaque cas est documenté ici : cible, symptôme (panic,
débordement, blocage), et référence de la correction une fois faite.

Vide pour l'instant : aucune campagne n'a encore trouvé de crash réel
(voir le README parent — les `crash-da39a3…` vides obtenus sous
Alpine/musl sont un faux positif d'environnement, pas des bugs).

Pour rejouer un cas :

```sh
cargo +nightly fuzz run <cible> fuzz/regressions/<fichier>
```
