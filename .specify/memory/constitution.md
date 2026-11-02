<!--
Sync Impact Report
- Version change: 1.0.0 → 1.0.1 (PATCH: licence TODO resolved, no principle change)
- Previous: (template, unversioned) → 1.0.0
- Modified principles: all template placeholders replaced (initial adoption)
  - [PRINCIPLE_1..5] → I. Binaire autonome et hors ligne
                       II. Natif d'abord, import sans exécution
                       III. Chaîne de preuve
                       IV. Reproductibilité déterministe
                       V. Traitement en flux
                       VI. Tests d'abord et validation par oracle
                       VII. Licences permissives uniquement
                       VIII. Détection déterministe et prudente
                       IX. Windows-first
- Added sections: Contraintes techniques et de sécurité; Workflow de développement et qualité
- Removed sections: none
- Templates requiring updates: none (plan/spec/tasks templates read the constitution at runtime;
  their "Constitution Check" gate applies these principles unchanged) ✅
- Resolved 2026-11-02: licence Apache-2.0 (fichier LICENSE) ; nom du projet DFIRFlow.
- Deferred TODOs: none
-->

# DFIRFlow Constitution

## Core Principles

### I. Binaire autonome et hors ligne

- DFIRFlow MUST être livré sous forme d'un binaire Go unique, compilé statiquement, sans runtime
  externe à l'exécution (.NET, Python, Node, Docker, CGO non requis).
- Le binaire MUST fonctionner entièrement hors ligne : aucun téléchargement, appel réseau ni
  télémétrie pendant une analyse.
- Toute fonctionnalité MUST être utilisable en CLI headless et scriptable ; aucune dépendance à une
  interface graphique.

Justification : exigences E1–E3 (`docs/etude-existant.md` §2) — déploiement sur poste compromis,
serveur headless et environnement air-gap.

### II. Natif d'abord, import sans exécution

- Les artefacts du cœur (EVTX, Registre, $MFT, $UsnJrnl, Prefetch) MUST être décodés nativement
  en Go (`internal/parser/`).
- Les sorties d'outils tiers (KAPE, DFIR ORC, EZ Tools, Hayabusa, Plaso, Volatility) MAY être lues
  par des importers (`internal/importer/`) ; DFIRFlow MUST NOT lancer, embarquer ou orchestrer un
  outil tiers.
- Parsers et importers MUST produire le même modèle pivot `normalizer.Event` ; le reste du pipeline
  MUST NOT dépendre de l'origine d'un événement.

Justification : décision « hybride native d'abord » (`docs/etude-existant.md` §6–7) ; l'approche
orchestrateur est écartée car elle viole le principe I.

### III. Chaîne de preuve

- Les preuves sources MUST être traitées en lecture seule ; aucune commande ne modifie un fichier
  sous `evidence/`.
- Chaque preuve MUST être hachée en SHA-256 à son entrée dans le dossier de cas et inscrite au
  manifeste ; une commande de vérification MUST pouvoir détecter toute altération.
- Chaque `Event` MUST renseigner `SourceFile`, `SourceHash`, `RecordID` et `Ingest`
  (`native` ou `import:<outil>@<version>`) ; une détection MUST pouvoir être reliée à l'artefact
  source haché.
- Chaque investigation MUST être isolée dans son propre dossier de cas (`case.json` + arborescence
  dédiée) ; les opérations importantes MUST être journalisées dans le cas.

Justification : exigence E8 et valeur probatoire des résultats.

### IV. Reproductibilité déterministe

- Même entrée + même version + mêmes règles MUST produire la même sortie (hors horodatages
  d'exécution explicitement identifiés comme tels).
- Tous les horodatages d'événements MUST être stockés en UTC avec leur `TimestampType`.
- Les sorties MUST avoir un ordre stable (tri défini, pas d'ordre d'itération de map ou de
  goroutines exposé).
- La version de l'outil et des règles MUST être enregistrée dans le cas et les rapports.

Justification : exigence E9 — contre-expertise et usage en situation de crise.

### V. Traitement en flux

- Les parsers et importers MUST traiter les artefacts en flux et MUST NOT charger un artefact
  entier en mémoire.
- Une erreur sur un enregistrement corrompu MUST être signalée et MUST NOT interrompre le
  traitement des enregistrements suivants, sauf corruption rendant le reste illisible.
- La consommation mémoire MUST rester bornée indépendamment de la taille de l'artefact ; elle est
  mesurée par les benchmarks.

Justification : artefacts de plusieurs Go (EVTX, $MFT, $J) ; risque de saturation identifié au SWOT.

### VI. Tests d'abord et validation par oracle (NON-NEGOTIABLE)

- Tout code de logique MUST être accompagné de tests écrits avant ou avec l'implémentation ; la CI
  MUST rester verte (`gofmt`, `go vet`, `go test -race`).
- Tout parser MUST disposer de tests oracle comparant ses sorties, champ par champ, à l'outil de
  référence (EvtxECmd/Hayabusa, MFTECmd, RECmd, PECmd) sur des fixtures versionnées.
- Toute règle de détection MUST avoir au moins un cas positif et un cas négatif.
- Tout bug corrigé MUST donner lieu à un test de non-régression.
- Les fixtures MUST être synthétiques ou issues d'un laboratoire dédié, jamais de données réelles
  de personnes ou d'organisations.

Justification : risque principal « écart de précision avec les outils de référence »
(`docs/etude-existant.md` §8).

### VII. Licences permissives uniquement

- Seules des dépendances sous licence permissive (Apache-2.0, MIT, BSD) MAY être intégrées au
  binaire ; du code copyleft (GPL, AGPL, LGPL) MUST NOT être copié ou lié.
- Les outils copyleft (Chainsaw, Hayabusa, Velociraptor) MAY servir d'inspiration et d'oracle de
  test ; leurs règles MAY être réutilisées selon la licence propre à ces règles.
- Les versions des dépendances MUST être figées (`go.mod` / `go.sum`) et leur licence vérifiée
  avant ajout.
- DFIRFlow est distribué sous licence Apache-2.0 (fichier `LICENSE`) ; toute dépendance MUST être
  compatible avec cette licence.

Justification : exigence E10 — distribution libre du binaire.

### VIII. Détection déterministe et prudente

- La détection et la corrélation MUST reposer exclusivement sur des règles déterministes,
  déclaratives et versionnées (YAML compatible Sigma pour les règles mono-événement) ; aucun
  modèle de ML.
- Chaque règle MUST porter un identifiant, une sévérité et, lorsque pertinent, une technique
  MITRE ATT&CK.
- Les règles MUST s'appuyer sur des champs structurés (`EventData`, champs de `Event`) et non sur
  des messages EVTX résolus.
- DFIRFlow MUST NOT présenter une détection comme une preuve de compromission ; les rapports
  MUST exposer la confiance et les limites connues.

Justification : `docs/MoSCoW.md` (Won't Have : IA/ML) et cahier des charges §44.

### IX. Windows-first

- Les artefacts analysés MUST être des artefacts Windows ; l'analyse d'artefacts Linux/macOS est
  hors périmètre v1.
- Le binaire MUST fonctionner sur une station d'analyse Windows x64 et Linux x64 ; d'autres
  cibles de compilation MAY être produites sans être garanties.
- Les fonctionnalités nécessitant une API Windows (collecte live, VSS, lecture NTFS brute) MUST
  être isolées derrière des build tags et MUST NOT casser la compilation Linux.

Justification : exigence E4 et périmètre MoSCoW.

## Contraintes techniques et de sécurité

- Langage : Go (version déclarée dans `go.mod`) ; stockage embarqué : SQLite via une
  implémentation compatible avec le principe I ; formats de sortie : JSON, JSONL, SQLite, HTML.
- Le modèle pivot `normalizer.Event` est un contrat partagé : toute modification MUST être
  spécifiée, rétro-compatible pour les exports ou annoncée comme rupture, et documentée.
- Les entrées (artefacts, CSV/JSON tiers, règles) sont des données non fiables : les parsers MUST
  valider tailles et offsets et MUST NOT paniquer sur une entrée malformée.
- Les scénarios d'attaque MUST être exécutés uniquement en laboratoire isolé, contrôlé et
  documenté.
- Les documents de référence sont `docs/etude-existant.md` (décisions d'architecture, prioritaire
  en cas de conflit), `docs/Archi.md`, `docs/MoSCoW.md` et `docs/benchmark.md`.

## Workflow de développement et qualité

- Toute fonctionnalité MUST passer par le cycle Spec Kit : `/speckit-specify` →
  `/speckit-clarify` → `/speckit-plan` → `/speckit-tasks` → `/speckit-implement` ; la spec vit
  dans `specs/<NNN>-<nom>/`.
- Chaque plan MUST passer la « Constitution Check » ; toute dérogation MUST être justifiée dans la
  section *Complexity Tracking* du plan.
- Une fonctionnalité est terminée lorsque ses critères d'acceptation sont couverts par des tests,
  que la CI est verte et que la documentation impactée est à jour.
- Commits au format Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`…).
- Toute revue de code MUST vérifier la conformité aux principes I à IX.

## Governance

- Cette constitution prévaut sur les autres pratiques et documents du projet ; en cas de conflit
  entre un document de `docs/` et la constitution, la constitution s'applique et le document est
  corrigé.
- Amendement : proposition écrite via `/speckit-constitution`, validée par les deux membres du
  binôme, avec Sync Impact Report et mise à jour des specs ou plans impactés.
- Versionnement sémantique : MAJOR pour la suppression ou redéfinition incompatible d'un principe,
  MINOR pour l'ajout ou l'extension matérielle d'un principe ou d'une section, PATCH pour les
  clarifications et corrections de forme.
- Revue de conformité à chaque plan (`/speckit-plan`), à chaque analyse (`/speckit-analyze`) et
  avant chaque release.

**Version**: 1.0.1 | **Ratified**: 2026-11-02 | **Last Amended**: 2026-11-02
