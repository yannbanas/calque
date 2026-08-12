# Corpus de configurations

Ce dossier contient des configurations d'équipements réseau **anonymisées**
et les réponses attendues du modèle, utilisées comme tests de référence
(CALQUE-ARCHITECTURE.md §11.1).

## La règle absolue (§11.4)

> **Aucune configuration professionnelle non anonymisée dans un dépôt,
> même privé. Et une autorisation écrite avant toute utilisation d'une
> configuration qui n'est pas la tienne.**

Une configuration de pare-feu contient le plan d'adressage, les noms de
serveurs et parfois des secrets (clés pré-partagées, condensats de mots
de passe, communautés SNMP). Publier cela, même par accident, même dans
un dépôt privé, est une faute. Il n'y a pas d'exception.

## Contribuer une configuration au corpus

1. **Obtenir l'autorisation écrite** du propriétaire de la configuration
   si elle n'est pas la vôtre. La conserver. Pas d'autorisation écrite,
   pas de contribution.
2. **Anonymiser avec `calque scrub`** :

   ```bash
   calque scrub fw-01.conf > fw-01-anon.conf
   ```

   `scrub` remplace de façon cohérente les adresses, les noms d'hôtes et
   les identifiants en préservant la structure — le comportement du
   modèle reste donc testable.
3. **Relire le résultat à la main.** L'outil aide, la responsabilité
   reste humaine : vérifier qu'aucun nom, aucune adresse publique,
   aucun secret ne subsiste (commentaires et descriptions compris).
4. **Utiliser un adressage fictif** : plages privées banalisées
   (10.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) et noms
   génériques (`fw-01`, `srv-fichiers`, `vlan-invite`).
5. **Joindre les réponses attendues** : pour chaque configuration, un
   fichier de flux (`flows.yaml`) décrivant ce que le modèle doit
   répondre. C'est ce qui fait d'une configuration un cas de test et
   pas un simple échantillon.

## Organisation

```
corpus/
├── fortigate/
│   ├── <cas>/
│   │   ├── config.conf      # configuration anonymisée
│   │   └── flows.yaml       # réponses attendues
├── cisco_ios/
└── ...
```

Toute contribution qui ne respecte pas ces règles sera refusée et
purgée de l'historique.
