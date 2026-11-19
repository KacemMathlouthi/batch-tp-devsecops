#import "/docs/template.typ": *

#let (shot, todo-shot) = shots("/tp2/compte-rendu/screenshots/")

#show: conf.with(
  tp: "TP2",
  short-title: "Sécurité dans le pipeline CI/CD",
  title: [Intégration de la sécurité dans un pipeline CI/CD],
  subtitle: [Chaque modification passe par des tests, une analyse du code, une analyse des dépendances et une attaque automatisée de l'application déployée. Une seule faille grave suffit à bloquer la fusion et la publication.],
  image-ref: "ghcr.io/kacemmathlouthi/batch-tp-devsecops",
)

// ═══════════════════════════════════════════
//  PRÉSENTATION
// ═══════════════════════════════════════════
= Présentation générale

== Objectif

- Automatiser les contrôles du TP1 : ils ne dépendent plus de la discipline d'un développeur mais s'exécutent à chaque #emph[push] et chaque #emph[pull request].
- Faire du pipeline un garde-fou : un résultat critique ou élevé fait échouer le pipeline, empêche la fusion et la publication de l'image.
- Ajouter une analyse dynamique (DAST) : attaquer l'application réellement déployée, pas seulement lire son code.
- Démontrer le blocage avec une pull request volontairement vulnérable, puis le passage avec sa correction.

== Point de départ

- L'application du TP1 : service de notes FastAPI, corrigé (0 alerte Bandit, 0 vulnérabilité Snyk), 10 tests.
- Le dépôt public #cmd[KacemMathlouthi/batch-tp-devsecops], branche #cmd[main].

== Stack technique

#deflist(
  [CI/CD],  [GitHub Actions, runners #cmd[ubuntu-latest]],
  [SAST],   [Bandit (#cmd[ghcr.io/pycqa/bandit/bandit])],
  [SCA],    [Snyk CLI (#cmd[snyk/snyk:python-3.12]), jeton en secret GitHub],
  [DAST],   [OWASP ZAP 2.17 (#cmd[ghcr.io/zaproxy/zaproxy:stable]), scan d'API guidé par OpenAPI],
  [Registre], [GitHub Container Registry (#cmd[ghcr.io])],
)

// ═══════════════════════════════════════════
//  ÉTAPE 1, PIPELINE DE BASE
// ═══════════════════════════════════════════
= Étape 1 : pipeline de base

== Le fichier #cmd[.github/workflows/ci.yml]

- Déclenché sur chaque #emph[push] vers #cmd[main] et chaque #emph[pull request] qui la cible.
- Un seul job, trois étapes utiles : installer les dépendances depuis le #cmd[uv.lock], lancer les tests, construire l'image.
- #cmd[permissions: contents: read] : le jeton fourni au workflow ne peut que lire le dépôt (moindre privilège).

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    name: build and test
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: app
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with: { version: "0.7.20", python-version: "3.12" }
      - name: install dependencies (uv.lock)
        run: uv sync --frozen
      - name: unit tests
        run: uv run pytest -v
      - name: build image
        run: docker build -t tp-devsecops:${{ github.sha }} .
```

== Premier passage

#shot("01-ci-base-run.png",
  [Run \#1 : le job #cmd[build and test] passe en 32 s],
)

#shot("02-ci-base-log.png",
  [Journal du run consulté avec #cmd[gh run view --log] : les 10 tests passent sur le runner (Python 3.12.11), puis l'image est construite],
)

#info-box([Ce que garantit ce pipeline], [
  - Le code compile, les dépendances s'installent depuis le lockfile, les tests passent, l'image se construit.
  - Rien sur la sécurité : un #cmd[shell=True] ou une dépendance vulnérable passerait sans bruit. Les tests de sécurité du TP1 ne couvrent que les failles déjà connues.
])
