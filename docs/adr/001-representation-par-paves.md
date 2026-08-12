# ADR 001 — Représentation des espaces d'en-têtes par ensembles de pavés

- **Date** : 2026-08-11
- **Statut** : accepté

## Contexte

Le moteur d'analyse de Calque doit manipuler des ensembles de paquets :
« tous les paquets de 10.0.10.0/24 vers 10.0.20.5, TCP, port 445 ». Il
faut pouvoir les intersecter (règle ∩ trafic restant), les unir, les
soustraire (ce qui n'a pas encore été capturé par les règles
précédentes), et en extraire un exemple concret.

Deux familles de représentations existent :

1. **Ensembles de pavés** (hyperrectangles) : une règle de pare-feu
   réelle est un pavé dans un espace à cinq dimensions (source,
   destination, protocole, port source, port destination). Une politique
   est une liste ordonnée de pavés. L'algèbre (union, intersection,
   différence, normalisation) est implémentable en quelques centaines de
   lignes ; le seul point délicat est la soustraction, qui peut produire
   jusqu'à une dizaine de pavés et impose une normalisation après chaque
   opération.

2. **Diagrammes de décision binaires** (BDD), voire un solveur SMT
   (Z3) : plus généraux, plus compacts sur d'énormes ensembles de règles
   très chevauchantes, mais opaques — impossible d'afficher un BDD et de
   le lire — et coûteux en complexité de mise en œuvre dès le départ.

Sur les tailles réelles visées (quelques milliers de règles), les pavés
sont rapides, et surtout **inspectables** : on peut afficher le résultat
d'un calcul et le vérifier à l'œil, ce qui compte pour un outil dont la
sortie sert de preuve. Les BDD ne paient que sur des cas que Calque ne
vise pas en v1.

## Décision

Nous représentons les espaces d'en-têtes par des **ensembles normalisés
de pavés disjoints** (`HeaderSet { cubes: Vec<Cube> }` dans
`calque-space`), avec normalisation après chaque opération (fusion des
pavés adjacents, suppression des vides).

Toute la manipulation passe par le trait `HeaderSpace` (`full`, `empty`,
`is_empty`, `intersect`, `union`, `subtract`, `contains`, `sample`).
Le moteur (`calque-engine`) ne connaît que ce trait, jamais la structure
interne.

L'algèbre est vérifiée par tests de propriétés (`proptest`) : lois des
ensembles, cohérence entre le chemin symbolique et le chemin concret.

## Conséquences

- **Ce que ça rend facile** : implémentation courte et auditée ;
  résultats affichables et lisibles ; `sample()` fournit un paquet
  concret pour chaque violation, donc des diagnostics actionnables ;
  performances largement suffisantes pour les configurations du terrain.
- **Ce que ça coûte** : la soustraction fragmente (`A \ B` peut produire
  jusqu'à dix pavés) — la normalisation est le vrai travail algorithmique
  du projet ; sur d'énormes politiques très chevauchantes, la
  représentation peut grossir plus vite qu'un BDD.
- **Porte de sortie** : si un jour les tailles réelles l'exigent, une
  seconde implémentation du trait `HeaderSpace` adossée à
  `biodivine-lib-bdd` pourra être ajoutée en **v2**, sans toucher au
  moteur ni aux analyseurs. C'est une optimisation derrière un trait,
  pas une fondation : elle ne sera écrite que si un cas réel la justifie.
