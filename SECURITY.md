# Politique de sécurité

Calque lit des configurations d'équipements réseau et rend des verdicts
d'accessibilité dont la sortie sert de preuve. Ce statut particulier
élargit ce que le projet considère comme une vulnérabilité.

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique.** Utiliser le signalement privé de
vulnérabilité de GitHub :

> <https://github.com/yannbanas/calque/security/advisories/new>

(onglet *Security* du dépôt → *Report a vulnerability*). Si ce canal est
indisponible, écrire à yannbanas@gmail.com avec « [sécurité calque] » en
objet.

Un signalement utile contient : la version ou le commit concerné, une
entrée qui reproduit le problème (configuration **anonymisée** — jamais
de configuration réelle, voir [corpus/README.md](corpus/README.md)), et
ce que vous avez observé face à ce qui aurait dû se produire.

## Périmètre

Sont traités comme des vulnérabilités :

- **Un verdict faux.** Un flux déclaré « refusé » alors que l'équipement
  le laisserait passer (ou l'inverse), une règle morte déclarée à tort,
  une trace qui désigne la mauvaise règle. La sortie de Calque sert de
  preuve dans des décisions de segmentation réseau : un verdict faux est
  une vulnérabilité au même titre qu'une corruption mémoire, pas un
  simple bug fonctionnel. (Exception : un verdict explicitement rendu
  comme non ferme — modèle `Partial`, code de sortie 3 — est le
  comportement prévu.)
- **Panic, blocage ou épuisement de ressources sur configuration
  hostile.** Les fichiers analysés sont des entrées non fiables,
  potentiellement issues d'un équipement compromis. Tout panic,
  débordement, boucle infinie ou consommation mémoire déraisonnable
  déclenché par un fichier d'entrée est une vulnérabilité (déni de
  service), même si l'entrée est absurde.
- Toute écriture hors du projet `.calque/` ou du répertoire de travail,
  ou tout accès réseau : Calque est en lecture seule, toujours ; un
  comportement contraire est une vulnérabilité par définition.

Ne relèvent pas de cette politique (issue publique normale) : les
directives non comprises correctement **diagnostiquées** par
`calque model check`, les messages d'erreur maladroits, les problèmes de
performance sans caractère d'épuisement.

## Versions supportées

| Version | Supportée |
|---|---|
| `main` | oui |
| tout le reste | non |

Le projet est en v0 : seule la tête de `main` reçoit des correctifs. Les
versions étiquetées ne sont pas maintenues rétroactivement tant qu'une
1.0 n'existe pas.

## Délais

- Accusé de réception : sous 7 jours.
- Premier diagnostic (confirmé / non reproduit / hors périmètre) : sous
  14 jours.
- Correction : selon la gravité, en visant le raisonnable ; le correctif
  d'un verdict faux confirmé est prioritaire sur tout le reste. Le
  projet est maintenu bénévolement — ces délais sont un engagement de
  bonne foi, pas un contrat de service.

Merci de laisser un délai raisonnable de correction avant toute
divulgation publique ; la coordination se fait dans l'advisory GitHub.

## Remerciements

Les personnes qui signalent une vulnérabilité de façon responsable sont
créditées dans l'advisory publié et dans le [CHANGELOG](CHANGELOG.md),
sauf demande contraire de leur part.
