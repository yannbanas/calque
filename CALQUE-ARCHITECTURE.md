# Calque — architecture de développement

> **Ce que c'est** : un outil en ligne de commande qui lit les configurations d'équipements réseau, en construit un modèle, et répond à « qui peut joindre quoi » et « qu'est-ce qui casse si j'applique ce changement ».
> **Licence** : Apache-2.0
> **Langage** : Rust
> **Statut** : spécification de développement, v1

---

## 1. La règle qui structure tout le projet

> **Le cœur est pur. Aucune entrée-sortie dans la logique d'analyse.**

Les crates `calque-model`, `calque-space`, `calque-engine`, `calque-policy` et `calque-diff` ne dépendent ni de `tokio`, ni de `std::net`, ni du système de fichiers, ni de l'horloge. Ils prennent des données en entrée et rendent des données en sortie.

Trois bénéfices, et ils sont énormes :

1. **Testable exhaustivement** — on peut lancer des dizaines de milliers de cas en quelques secondes.
2. **Reproductible** — deux exécutions sur les mêmes données donnent le même verdict, ce qui est indispensable pour un outil dont la sortie sert de preuve.
3. **Rapide** — pas de coût réseau dans la boucle chaude.

Un test d'intégration continue vérifie l'arbre de dépendances et échoue si une impureté entre dans le cœur.

---

## 2. L'erreur à ne pas commettre au démarrage

La tentation naturelle est de sortir immédiatement l'artillerie lourde : Z3, diagrammes de décision binaires, exécution symbolique.

**C'est prématuré, et probablement inutile.**

Regarde à quoi ressemble une règle de pare-feu réelle :

```
source      10.0.10.0/24
destination 10.0.20.5/32
protocole   tcp
port        445
action      accept
```

C'est un **pavé** dans un espace à cinq dimensions. Pas une formule logique arbitraire — un rectangle. Et une politique complète, c'est une liste ordonnée de pavés.

Or l'algèbre des ensembles de pavés (union, intersection, différence, normalisation) est :

- implémentable en quelques centaines de lignes ;
- rapide sur les tailles réelles (quelques milliers de règles) ;
- **inspectable** — on peut afficher le résultat et le lire, ce qui est impossible avec un diagramme de décision binaire ;
- suffisante pour la quasi-totalité des configurations du terrain.

Les diagrammes de décision binaires ne paient que sur d'énormes ensembles de règles très chevauchantes. C'est une optimisation de version 2, derrière un trait, pas une fondation.

> **Décision : représentation par ensembles de pavés dès le départ, derrière un trait `HeaderSpace` qui laisse la porte ouverte.**

---

## 3. La représentation intermédiaire — le cœur du projet

Si elle est juste, ajouter un constructeur devient un week-end. Si elle est fausse, chaque constructeur devient un cas particulier et le projet meurt sous son propre poids.

### 3.1 Ce qu'un équipement réseau fait, abstraitement

Peu importe le constructeur, un paquet qui traverse un équipement subit toujours la même séquence :

```
entrée → filtre d'entrée → traduction de destination → décision de routage
       → filtre de sortie → traduction de source → sortie
```

Les constructeurs diffèrent sur le vocabulaire et sur l'endroit où ils accrochent les filtres. Pas sur cette séquence.

### 3.2 Les types

```rust
// calque-model — aucune dépendance au-delà de serde et ipnet

pub struct Network {
    pub devices: BTreeMap<DeviceId, Device>,
    pub links:   Vec<Link>,            // topologie physique
}

pub struct Device {
    pub id:         DeviceId,
    pub vendor:     Vendor,
    pub interfaces: BTreeMap<IfaceId, Interface>,
    pub zones:      BTreeMap<ZoneId, Vec<IfaceId>>,
    pub vrfs:       BTreeMap<VrfId, Vrf>,
    pub objects:    ObjectStore,       // groupes d'adresses et de services
    pub pipeline:   Pipeline,          // où sont accrochés les filtres
}

pub struct Interface {
    pub id:       IfaceId,
    pub addrs:    Vec<IpNet>,
    pub vlan:     Option<VlanId>,
    pub zone:     Option<ZoneId>,
    pub vrf:      VrfId,
    pub state:    AdminState,          // ne pas modéliser ce qui est éteint
    pub members:  Vec<IfaceId>,        // agrégats, bridges
}

pub struct Vrf {
    pub routes: Vec<Route>,            // triées par longueur de préfixe
}

pub struct Route {
    pub prefix:   IpNet,
    pub next_hop: NextHop,             // Ip | Interface | Drop
    pub metric:   u32,
    pub origin:   RouteOrigin,         // Static | Connected | Dynamic
}

/// Une règle de filtrage : un pavé + une action.
pub struct Rule {
    pub id:     RuleId,                // identifiant chez le constructeur
    pub matches: HeaderSet,            // le pavé
    pub from:   Option<ZoneId>,
    pub to:     Option<ZoneId>,
    pub action: Action,                // Accept | Deny | Nat(..) | Jump(..)
    pub source: SourceSpan,            // fichier + ligne, pour la traçabilité
}

pub struct Policy {
    pub id:    PolicyId,
    pub rules: Vec<Rule>,              // ORDRE SIGNIFICATIF, première correspondance
    pub default_action: Action,
}
```

### 3.3 Trois choix à ne pas rater

**`SourceSpan` sur chaque règle.** Le fichier et la ligne d'origine. C'est ce qui permet de répondre « refusé par la règle 34, fichier `fw-01.conf` ligne 812 » plutôt que « refusé ». **C'est le produit.** Un verdict sans justification n'a aucune valeur.

**L'ordre des règles est sémantique.** Un `Vec`, jamais un ensemble. La première correspondance gagne, et c'est la source d'erreur la plus fréquente en réseau.

**Les objets sont résolus tard.** Les configurations sont pleines de groupes d'adresses et de services. On garde la référence dans la représentation intermédiaire et on résout à l'évaluation. Sinon on perd la capacité de dire « à cause du groupe `SRV-INTERNES` qui a changé ».

---

## 4. L'algèbre d'espace d'en-têtes

### 4.1 Le trait

```rust
// calque-space — pur, testé par propriétés

pub trait HeaderSpace: Clone + Eq {
    fn full() -> Self;
    fn empty() -> Self;
    fn is_empty(&self) -> bool;
    fn intersect(&self, other: &Self) -> Self;
    fn union(&self, other: &Self) -> Self;
    fn subtract(&self, other: &Self) -> Self;
    fn contains(&self, pkt: &ConcretePacket) -> bool;
    fn sample(&self) -> Option<ConcretePacket>;   // un exemple concret
}
```

`sample()` est important : quand une invariante est violée, l'outil doit sortir **un paquet précis** qui viole, pas une abstraction. « Le flux 10.0.99.4 → 10.0.1.10:22 passe alors qu'il ne devrait pas » est actionnable ; « il existe un chevauchement » ne l'est pas.

### 4.2 Les cinq dimensions

```rust
pub struct HeaderSet {
    src:   PrefixSet,      // ensemble de préfixes IP
    dst:   PrefixSet,
    proto: ProtoSet,       // ensemble d'entiers 0..255
    sport: PortRanges,     // ensemble d'intervalles 0..65535
    dport: PortRanges,
}
```

Les dimensions sont indépendantes, donc une intersection est simplement l'intersection composante par composante. C'est ce qui rend l'implémentation si peu coûteuse.

Le seul point délicat est la **soustraction**, qui ne reste pas un pavé unique : `A \ B` peut produire jusqu'à dix pavés. D'où la structure réelle :

```rust
pub struct HeaderSet {
    cubes: Vec<Cube>,      // union normalisée de pavés disjoints
}
```

Avec une normalisation après chaque opération (fusion des pavés adjacents, suppression des vides). C'est là qu'est le vrai travail algorithmique du projet, et c'est borné : deux ou trois jours.

### 4.3 Tests par propriétés

Cette algèbre doit obéir aux lois des ensembles, et `proptest` peut le vérifier sur des dizaines de milliers de cas générés :

```rust
proptest! {
    #[test]
    fn union_contient_les_operandes(a: HeaderSet, b: HeaderSet) {
        let u = a.union(&b);
        prop_assert!(u.contains_set(&a) && u.contains_set(&b));
    }

    #[test]
    fn soustraction_puis_intersection_est_vide(a: HeaderSet, b: HeaderSet) {
        prop_assert!(a.subtract(&b).intersect(&b).is_empty());
    }

    #[test]
    fn coherence_avec_le_concret(a: HeaderSet, p: ConcretePacket) {
        // le chemin symbolique et le chemin concret doivent s'accorder
        prop_assert_eq!(a.contains(&p), a.cubes.iter().any(|c| c.contains(&p)));
    }
}
```

Si ces propriétés tiennent, le reste du moteur repose sur du solide.

---

## 5. Le moteur d'accessibilité

### 5.1 L'algorithme concret

```
localiser la source (quel équipement/interface possède ce préfixe ?)
boucle :
    filtre d'entrée         → si refusé, ARRÊT avec la règle responsable
    traduction destination  → l'en-tête peut être réécrit
    recherche de route      → plus long préfixe correspondant dans le VRF
                              si aucune route, ARRÊT « pas de route »
    filtre de sortie        → si refusé, ARRÊT avec la règle responsable
    traduction source       → l'en-tête peut être réécrit
    traverser le lien       → équipement suivant
    si déjà visité          → ARRÊT « boucle de routage »
    si destination atteinte → ARRÊT « autorisé »
```

### 5.2 La trace est le produit

```rust
pub struct Trace {
    pub verdict: Verdict,              // Allowed | Denied | NoRoute | Loop | Unknown
    pub hops:    Vec<Hop>,
}

pub struct Hop {
    pub device:     DeviceId,
    pub in_iface:   IfaceId,
    pub out_iface:  Option<IfaceId>,
    pub header_in:  ConcretePacket,
    pub header_out: ConcretePacket,    // après traduction d'adresse
    pub decisions:  Vec<Decision>,
}

pub struct Decision {
    pub stage:  Stage,                 // IngressFilter | Route | EgressFilter | Nat
    pub rule:   Option<RuleId>,
    pub source: Option<SourceSpan>,    // fichier + ligne
    pub outcome: Outcome,
    pub shadowed_by: Vec<RuleId>,      // règles antérieures qui masquent
}
```

Le champ `shadowed_by` mérite une mention spéciale : il répond à la question qui fait perdre le plus de temps aux administrateurs — « j'ai bien ajouté la règle d'autorisation, pourquoi ça ne passe pas ». Réponse : parce que la règle 12 plus haut refuse déjà. Aucun équipement ne dit ça spontanément.

### 5.3 Le mode symbolique, plus tard

Même moteur, en propageant un `HeaderSet` au lieu d'un `ConcretePacket`. La sortie devient un arbre plutôt qu'un chemin, puisqu'un ensemble peut se scinder à un embranchement de routage.

C'est ce qui permet `calque reach --to vlan-supervision` : « voici tout ce qui peut atteindre ce VLAN ». Version 6 de la feuille de route, pas version 1.

---

## 6. Les analyseurs — deux couches, jamais une

Erreur classique : écrire un analyseur monolithique par constructeur, qui passe du texte brut à la sémantique en une fois. Ingérable.

```
texte de configuration
        │
        ▼  couche 1 : par FORMAT (Fortinet, IOS, XML, JSON)
   arbre de configuration générique
        │
        ▼  couche 2 : par CONSTRUCTEUR (sémantique)
   représentation intermédiaire
```

### 6.1 Couche 1 — l'arbre générique

```rust
pub struct ConfigNode {
    pub keyword: String,
    pub args:    Vec<String>,
    pub children: Vec<ConfigNode>,
    pub span:    SourceSpan,
}
```

Une configuration FortiGate est un arbre par blocs :

```
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set action accept
    next
end
```

Une configuration Cisco IOS est un arbre par indentation. Deux tokenizers d'environ deux cents lignes chacun, réutilisables pour toute la gamme du constructeur.

### 6.2 Couche 2 — le sens

C'est là que vit la connaissance du constructeur : où sont accrochés les filtres, comment se nomment les zones, quel est le comportement par défaut, comment fonctionne la traduction d'adresse.

```rust
pub trait VendorAdapter {
    fn vendor(&self) -> Vendor;
    fn detect(&self, raw: &str) -> Confidence;      // reconnaissance automatique
    fn to_ir(&self, tree: &ConfigNode) -> Result<Device, Vec<Diagnostic>>;
}
```

### 6.3 Le principe qui protège le projet

> **Ne jamais deviner. En cas de directive non comprise, produire un diagnostic et marquer le résultat comme incomplet.**

```rust
pub enum Fidelity {
    Complete,
    Partial { unsupported: Vec<Diagnostic> },
}
```

Une réponse « autorisé » issue d'un modèle qui a silencieusement ignoré trois directives est **pire que pas de réponse** : elle donne confiance à tort. Toute sortie de `Calque` porte son niveau de fidélité, et l'outil refuse de rendre un verdict ferme sur un modèle partiel touchant le chemin analysé.

C'est la décision de conception la plus importante du projet après la pureté du cœur.

### 6.4 Ordre des constructeurs

1. **FortiGate** — très répandu dans les PME et collectivités françaises, format régulier et facile à analyser
2. **Cisco IOS / IOS-XE**
3. **pfSense / OPNsense** — configuration en XML, donc analyseur presque gratuit
4. **Linux nftables** — utile pour les tests et pour les hôtes
5. HPE/Aruba, UniFi

> Un constructeur parfaitement traité vaut mieux que six approximatifs.

---

## 7. La topologie — le problème caché

Comment `Calque` sait-il que le port 3 de l'équipement A est câblé au port 12 de l'équipement B ? Rien dans les configurations ne le dit.

Trois sources, par ordre de fiabilité :

1. **Voisinage LLDP / CDP** — la table de voisinage de chaque équipement. La meilleure source, mais nécessite une collecte en ligne.
2. **Fichier de topologie déclaré** — l'humain écrit les liens. Fiable, fastidieux.
3. **Inférence par sous-réseau** — deux interfaces dans le même sous-réseau sont probablement reliées. Rapide, faux dès qu'il y a des commutateurs intermédiaires.

**Version 1** : inférence par sous-réseau, plus fichier `topology.yaml` pour corriger et compléter. `calque topology check` signale les incohérences et les liens ambigus.

---

## 8. Découpage en crates

```
calque/
├── Cargo.toml                  # workspace
├── deny.toml                   # licences autorisées
├── LICENSE                     # Apache-2.0
│
├── crates/
│   ├── calque-model/           # PUR — la représentation intermédiaire
│   ├── calque-space/           # PUR — algèbre de pavés
│   ├── calque-engine/          # PUR — accessibilité, traces
│   ├── calque-policy/          # PUR — tests de flux, invariants
│   ├── calque-diff/            # PUR — comparaison de deux modèles
│   │
│   ├── calque-parse/           # couche 1 — tokenizers par format
│   ├── calque-vendors/         # couche 2 — un module par constructeur
│   │   ├── fortigate/
│   │   ├── cisco_ios/
│   │   ├── opnsense/
│   │   └── nftables/
│   │
│   ├── calque-collect/         # IMPUR — SSH/API. Fonctionnalité optionnelle
│   ├── calque-scrub/           # anonymisation des configurations
│   ├── calque-report/          # sorties : texte, JSON, JUnit, HTML
│   └── calque-cli/             # le binaire
│
├── corpus/                     # configurations anonymisées + réponses attendues
├── fuzz/                       # cibles cargo-fuzz sur les analyseurs
└── docs/adr/                   # décisions d'architecture datées
```

**Règle de dépendance** : `calque-cli` peut tout voir. Les crates purs ne voient que d'autres crates purs. `calque-collect` est derrière une fonctionnalité Cargo désactivée par défaut — quelqu'un qui veut analyser des fichiers hors ligne ne doit pas compiler une pile SSH.

---

## 9. Dépendances

| Besoin | Crate | Note |
|---|---|---|
| Arithmétique de préfixes IP | `ipnet` | indispensable, ne pas réécrire |
| CLI | `clap` (derive) | standard |
| Sérialisation | `serde`, `serde_yaml`, `serde_json` | — |
| Analyse syntaxique | `nom` ou à la main | les configurations réseau sont linéaires, `pest` est superflu |
| Erreurs lisibles | `miette` | affiche l'extrait de configuration fautif avec un curseur. Énorme gain perçu |
| Tests par propriétés | `proptest` | pour l'algèbre |
| Tests par instantanés | `insta` | idéal pour les analyseurs : on fige la sortie et on voit les régressions |
| Fuzzing | `cargo-fuzz` | les configurations sont des entrées non fiables |
| Graphe | `petgraph` | topologie, détection de cycles |
| Parallélisme | `rayon` | quand les requêtes se comptent en milliers |
| Collecte SSH | `russh` | optionnel, isolé |
| Diagrammes binaires | `biodivine-lib-bdd` | **version 2 seulement**, derrière le trait |

Peu de dépendances, toutes matures. C'est un projet maintenable seul sur la durée.

---

## 10. Interface en ligne de commande

```bash
# Importer
calque import fw-01.conf --as fw-01
calque import --dir ./configs/          # détection automatique du constructeur

# Vérifier le modèle
calque model check                       # fidélité, directives non gérées
calque topology check                    # liens ambigus ou manquants

# Interroger
calque path 10.0.10.5 '->' 10.0.20.10:445/tcp
calque path --explain                    # trace complète, règle par règle
calque reach --to vlan-supervision       # symbolique, version ultérieure

# Tester (la commande qui vend, n° 1)
calque test                              # exécute flows.yaml
calque test --format junit               # pour l'intégration continue

# Prévisualiser (la commande qui vend, n° 2)
calque plan --candidate fw-01-nouveau.conf

# Hygiène
calque scrub fw-01.conf > fw-01-anon.conf
calque verify --against-reality --from 10.0.10.5
```

### 10.1 Le fichier de flux

C'est la suite de tests du réseau. Format volontairement minimal :

```yaml
flows:
  - name: la comptabilité accède au serveur de fichiers
    from: 10.0.10.0/24
    to:   10.0.20.5
    port: 445/tcp
    expect: allow

  - name: le wifi invité est isolé de l'administration
    from: vlan-invite
    to:   vlan-admin
    port: any
    expect: deny

  - name: la supervision joint tous les commutateurs
    from: 10.0.99.10
    to:   groupe:commutateurs
    port: 22/tcp
    expect: allow
```

`calque test` renvoie un code de sortie non nul si un flux ne se comporte pas comme déclaré. Cela suffit à le brancher dans une chaîne d'intégration continue, un crochet Git ou une tâche planifiée.

### 10.2 Ce que produit `calque plan`

```
$ calque plan --candidate fw-01-nouveau.conf

3 flux changent de comportement :

  ROMPU   la comptabilité accède au serveur de fichiers
          10.0.10.0/24 → 10.0.20.5:445/tcp
          avant : autorisé par la politique 12
          après : refusé par la politique 8 (nouvelle)
          cause : la politique 8 est insérée avant la 12 et couvre
                  10.0.0.0/16 en refus

  CORRIGÉ le wifi invité est isolé de l'administration
  NOUVEAU 10.0.30.0/24 → 10.0.20.0/24:* devient joignable
          (n'était couvert par aucun flux déclaré)

2 flux inchangés.
```

La ligne `NOUVEAU` est précieuse : elle signale une ouverture d'accès **que personne n'avait demandée**. C'est exactement le type d'erreur qui crée une brèche de segmentation.

---

## 11. Validation — comment savoir que le modèle est juste

Cette section décide de la crédibilité de l'outil. Un modèle faux est pire qu'aucun modèle.

### 11.1 Quatre niveaux

| Niveau | Outil | Ce qu'il attrape |
|---|---|---|
| Propriétés | `proptest` sur `calque-space` | erreurs d'algèbre |
| Instantanés | `insta` sur les analyseurs | régressions silencieuses d'analyse |
| Corpus de référence | configurations réelles anonymisées + réponses attendues | erreurs de sémantique constructeur |
| **Confrontation au réel** | voir ci-dessous | tout le reste |

### 11.2 La confrontation au réel — la fonctionnalité qui crée la confiance

```bash
calque verify --against-reality --from 10.0.10.5
```

L'outil calcule les réponses sur son modèle, puis fait réellement tester ces flux depuis un hôte du réseau (`nmap`, `hping`, ou une simple connexion TCP), et compare.

Toute divergence est un bogue du modèle, avec le cas de test tout prêt.

C'est aussi le meilleur argument commercial existant. Face à « comment savoir si votre modèle dit vrai ? », la réponse est une commande qui le démontre sur le réseau du client.

### 11.3 Fuzzing

Les configurations sont des entrées non maîtrisées, potentiellement issues d'un équipement compromis. `cargo-fuzz` sur chaque analyseur, dès qu'il existe. Aucun `panic!`, aucun `unwrap()` sur une entrée externe.

### 11.4 Anonymisation obligatoire

Une configuration de pare-feu contient le plan d'adressage, les noms de serveurs et parfois des secrets. `calque scrub` remplace de façon cohérente les adresses, les noms d'hôtes et les identifiants, en préservant la structure — donc le comportement du modèle reste testable.

**Règle absolue** : aucune configuration professionnelle non anonymisée dans un dépôt, même privé. Et une autorisation écrite avant toute utilisation d'une configuration qui n'est pas la tienne.

---

## 12. Feuille de route

Chaque étape a un critère de sortie vérifiable.

### S1 — Analyse et modèle (2 à 3 semaines)
Tokenizer FortiGate, représentation intermédiaire, adaptateur, `calque import`, `calque model check`, diagnostics avec `miette`.

> **Sortie** : importer une vraie configuration FortiGate, afficher interfaces, zones, routes et politiques, et lister honnêtement ce qui n'a pas été compris.

### S2 — Moteur concret et trace (2 à 3 semaines)
Algèbre de pavés, recherche de route, évaluation ordonnée des politiques, `calque path --explain`.

> **Sortie** : sur un réseau à trois équipements, répondre correctement à vingt questions d'accessibilité vérifiées à la main, avec la règle exacte qui décide à chaque fois.

### S3 — Tests de flux (1 à 2 semaines)
`flows.yaml`, `calque test`, codes de sortie, sortie JUnit.

> **Sortie** : la suite de flux tourne dans une chaîne d'intégration continue et échoue quand on introduit volontairement une régression de segmentation.

### S4 — La prévisualisation (2 semaines)
`calque plan`, comparaison des résultats entre configuration courante et candidate, détection des ouvertures non déclarées.

> **Sortie** : la démonstration de trente secondes qui fait réagir un administrateur. **C'est ici que le projet devient montrable.**

### S5 — Deuxième constructeur (2 à 3 semaines)
Cisco IOS. C'est le test de qualité de la représentation intermédiaire : si ça prend plus de trois semaines, la représentation est mauvaise et il faut la corriger maintenant.

### S6 — Mode symbolique (4 à 6 semaines)
Propagation d'ensembles, `calque reach`, détection de règles masquées et de règles mortes.

### S7 — Collecte et topologie (3 semaines)
`calque-collect` via SSH, voisinage LLDP, découverte automatique.

**Séquence à respecter** : `plan` avant le symbolique. La fonctionnalité qui vend arrive à la semaine dix, pas à la semaine trente.

---

## 13. Les principes à ne pas trahir

1. **Lecture seule, toujours.** `Calque` ne pousse jamais une configuration. C'est simultanément l'argument de vente, la limitation de responsabilité et la réduction de surface d'attaque.
2. **Le cœur est pur.** Aucune entrée-sortie dans l'analyse. Vérifié par l'intégration continue.
3. **Ne jamais deviner.** Une directive non comprise produit un diagnostic, jamais une supposition. La fidélité du modèle est toujours affichée.
4. **La trace est le produit.** Un verdict sans la règle qui l'a produit ne vaut rien.
5. **Un constructeur parfait vaut mieux que six approximatifs.**
6. **Jamais de configuration réelle non anonymisée dans un dépôt.**

---

## 14. Premier commit

Le workspace, `deny.toml`, `LICENSE`, l'ADR 001 daté qui acte la représentation par pavés plutôt que par diagrammes de décision binaires, et `calque-model` avec les types de la section 3.

Puis une seule configuration FortiGate anonymisée dans `corpus/`, et le tokenizer qui la lit.
