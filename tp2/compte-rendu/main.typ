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

// ═══════════════════════════════════════════
//  ÉTAPE 2, SAST ET SCA
// ═══════════════════════════════════════════
= Étape 2 : SAST et SCA dans le pipeline

== Architecture du pipeline

#figure(
  image("diagrams/pipeline.svg", width: 100%),
  caption: [Les jobs du workflow #cmd[ci] ; point rouge : porte de sécurité],
)

- Quatre jobs indépendants, un par contrôle : un échec désigne immédiatement le contrôle en cause.
- SAST et SCA tournent en parallèle du build : ils n'ont besoin que du code source.
- Le DAST attend le build : il lui faut une application qui démarre.
- #cmd[publish] dépend des quatre (#cmd[needs]) : l'image n'atteint le registre que si tout est vert.

== Règle de blocage

Chaque outil tourne deux fois : un rapport complet archivé (jamais bloquant) et une porte (#emph[gate]) qui ne retient que le seuil choisi.

#htable(
  columns: (auto, 1fr, auto),
  header: ([Contrôle], [Porte], [Bloque si]),
  [SAST], [#cmd[bandit ... --severity-level high]], [une alerte #emph[High]],
  [SCA],  [#cmd[snyk test --severity-threshold=high]], [une vulnérabilité #emph[High] ou #emph[Critical]],
  [DAST], [#cmd[jq] sur le rapport JSON de ZAP], [une alerte de risque #emph[High]],
)

- Les sévérités inférieures restent visibles dans les rapports (artefacts du run) sans bloquer : un seuil trop bas rendrait le pipeline rouge en permanence et pousserait à l'ignorer.

```yaml
  sast:
    steps:
      - name: full report (all severities, never fails)
        run: docker run ... bandit -r /src -x /src/.venv,/src/tests -f json -o /out/bandit.json --exit-zero
      - name: security gate (fails on High)
        run: docker run ... bandit -r /src -x /src/.venv,/src/tests --severity-level high

  sca:
    steps:
      - name: security gate (fails on High or Critical)
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        run: docker run --rm -e SNYK_TOKEN ... snyk/snyk:python-3.12 snyk test --severity-threshold=high
```

== Secret Snyk

- Jeton enregistré comme secret du dépôt (#cmd[gh secret set SNYK_TOKEN]), jamais dans le code.
- Transmis au conteneur par #cmd[-e SNYK_TOKEN] sans valeur : Docker le lit dans l'environnement du job.
- GitHub masque sa valeur dans les journaux (#cmd[SNYK_TOKEN: \*\*\*]).

// ═══════════════════════════════════════════
//  ÉTAPE 3, DAST
// ═══════════════════════════════════════════
= Étape 3 : analyse dynamique (DAST)

== Environnement éphémère

- Créé dans le runner pour la durée du job, détruit à la fin (#cmd[if: always()]) : rien ne survit au run.
- Réseau Docker dédié #cmd[dast] : l'application n'est pas exposée sur l'hôte, seul ZAP la joint.
- Secrets jetables générés à chaque run (#cmd[openssl rand]) : aucun secret réel n'est utilisé pour l'attaque.
- Attente active sur #cmd[/healthz] avant le scan.

```yaml
      - name: deploy ephemeral environment
        run: |
          docker build -t tp-devsecops:${{ github.sha }} app
          docker network create dast
          docker run -d --name target --network dast \
            -e ADMIN_PASSWORD="$(openssl rand -hex 16)" -e SECRET_KEY="$(openssl rand -hex 32)" \
            tp-devsecops:${{ github.sha }}
```

== OWASP ZAP

- #cmd[zap-api-scan.py] : scan d'API guidé par la description OpenAPI que FastAPI publie sur #cmd[/openapi.json]. ZAP connaît ainsi toutes les routes et tous les paramètres, sans exploration aveugle.
- Scan passif (en-têtes, fuites d'information) puis actif : ZAP envoie de vraies charges (injection SQL, injection de commande, XSS…) sur chaque paramètre.
- #cmd[-I] : ZAP ne décide pas lui-même de l'échec ; la porte #cmd[jq] applique notre règle (risque #emph[High]).

```yaml
      - name: security gate (fails on High risk)
        run: |
          high=$(jq '[.site[].alerts[] | select(.riskcode == "3")] | length' reports/zap.json)
          echo "High risk alerts: $high"
          if [ "$high" -gt 0 ]; then
            jq -r '... | "::error title=ZAP High::\(.alert) on \(.instances[0].uri)"' reports/zap.json
            exit 1
          fi
```

== Calibrage

Avant d'activer la règle, ZAP a été lancé localement contre les deux versions de l'application du TP1.

#htable(
  columns: (1fr, auto, auto),
  header: ([Image], [Alertes #emph[High]], [Porte]),
  [#cmd[v1] (vulnérable)], [2 : injection SQL (#cmd[/search]), injection de commande (#cmd[/ping])], [bloque],
  [#cmd[v3] (corrigée)], [0], [passe],
)

- Restent sur #cmd[v3] des alertes #emph[Medium] et #emph[Low] : en-têtes de sécurité absents (CSP, anti-#emph[clickjacking], #cmd[X-Content-Type-Options]). Signalées, non bloquantes.

== Pipeline complet sur #cmd[main]

#shot("03-ci-secure-green.png",
  [Run \#3 : les quatre contrôles passent, l'image est publiée],
)

#shot("05-gate-sast-sca-pass.png",
  [Portes SAST et SCA : aucune alerte #emph[High], 0 vulnérabilité sur 18 dépendances],
)

#shot("04-gate-dast-pass.png",
  [Porte DAST : alertes #emph[Medium] et inférieures listées, 0 alerte #emph[High]],
)

== Protection de la branche #cmd[main]

- Un pipeline rouge n'empêche rien à lui seul : il faut rendre les contrôles obligatoires.
- Règle de protection : les quatre jobs sont des #emph[required status checks] ; #cmd[strict] impose qu'ils aient tourné sur une branche à jour de #cmd[main].

```bash
gh api -X PUT repos/KacemMathlouthi/batch-tp-devsecops/branches/main/protection --input protect.json
# "contexts": ["build and test", "sast (bandit)", "sca (snyk)", "dast (zap)"], "strict": true
```

// ═══════════════════════════════════════════
//  ÉTAPE 4, VALIDATION
// ═══════════════════════════════════════════
#demo-page(1)

= Démo 1 : une pull request vulnérable est bloquée

== La modification

- Nouvelle fonctionnalité réaliste : lister les notes d'un utilisateur, #cmd[GET /notes/by-owner?owner=].
- Écrite volontairement de façon non sûre : requête SQL construite par f-string, propriétaire réinjecté dans le HTML sans échappement.
- Un test fonctionnel accompagne la route : il passe, la fonctionnalité « marche ».

```python
@app.get("/notes/by-owner", response_class=HTMLResponse)
def notes_by_owner(owner: str = "admin"):
    with db() as conn:
        rows = conn.execute(f"SELECT id, title FROM notes WHERE owner = '{owner}'").fetchall()
    items = "".join(f"<li>{r['title']}</li>" for r in rows)
    return f"<h2>Notes de {owner}</h2><ul>{items}</ul>"
```

- Branche #cmd[feat/notes-by-owner], pull request \#1 vers #cmd[main].

== Résultat

#shot("06-pr1-run.png",
  [Le run de la PR \#1 : seul le DAST échoue ; #cmd[publish image] n'est pas exécuté],
)

#shot("08-pr1-gate-dast-fail.png",
  [La porte DAST : ZAP a injecté une apostrophe dans #cmd[owner] et provoqué une erreur SQL ; 1 alerte #emph[High], le job échoue],
)

#shot("09-pr1-gate-sast.png",
  [Le SAST a bien vu la requête dynamique (B608), mais en sévérité #emph[Medium] : sous le seuil, la porte passe],
)

#shot("07-pr1-checks.png",
  [Vue de la PR : 3 contrôles réussis, 1 en échec ; GitHub refuse la fusion (#cmd[mergeStateStatus: BLOCKED])],
)

#success-box([
  - La fusion est refusée : la faille n'atteint pas #cmd[main], l'image n'est pas publiée.
  - Le DAST a arrêté ce que le SAST laissait passer : le SAST signale un #emph[motif] suspect, le DAST #emph[prouve] l'exploitation.
])

#info-box([Pourquoi Bandit laisse passer], [
  - B608 repère une chaîne SQL construite dynamiquement, sans savoir si la variable vient de l'utilisateur : d'où une sévérité et une confiance #emph[Medium].
  - Abaisser la porte SAST à #emph[Medium] l'aurait bloquée aussi, au prix de faux positifs ; la défense en profondeur (SAST + DAST) évite ce compromis.
])

#demo-page(2)

= Démo 2 : la correction passe

== Correction

- Nouvelle branche #cmd[fix/notes-by-owner], partie de la branche vulnérable, nouvelle pull request \#2.
- Le propriétaire devient un paramètre lié de la requête ; il est échappé, comme les titres, dans le HTML.
- Deux tests de non-régression rejouent les charges d'injection SQL et de XSS.

```python
        rows = conn.execute("SELECT id, title FROM notes WHERE owner = ?", (owner,)).fetchall()
    items = "".join(f"<li>{html.escape(r['title'])}</li>" for r in rows)
    return f"<h2>Notes de {html.escape(owner)}</h2><ul>{items}</ul>"
```

```python
def test_notes_by_owner_injection_is_inert(client):
    body = client.get("/notes/by-owner", params={"owner": "' OR '1'='1"}).text
    assert "Bienvenue" not in body
```

== Résultat

#shot("10-pr2-run.png",
  [Le run de la PR \#2 : les quatre contrôles passent ; #cmd[publish] reste ignoré, il ne tourne que sur #cmd[main]],
)

#shot("12-pr2-gate-dast-pass.png",
  [Porte DAST : plus d'injection SQL, 0 alerte #emph[High]],
)

#shot("11-pr2-checks.png",
  [Tous les contrôles réussis : la PR devient fusionnable (#cmd[mergeStateStatus: CLEAN])],
)

#success-box([
  - Même fonctionnalité, mêmes tests fonctionnels : seule la manière d'écrire la requête a changé.
  - Le pipeline passe, la fusion est autorisée.
  - Bandit ne signale plus rien, pas même le B608 #emph[Medium].
])

== Fusion et publication

- PR \#1 fermée (« bloquée par la porte DAST, remplacée par \#2 »), PR \#2 fusionnée dans #cmd[main].
- Le #emph[push] de la fusion relance tout le pipeline ; cette fois #cmd[publish image] s'exécute.

#shot("13-main-merge-run.png",
  [Run \#6 sur #cmd[main] : les quatre contrôles passent, l'image est publiée],
)

#shot("14-publish-log.png",
  [L'image est poussée sur #cmd[ghcr.io], étiquetée par le SHA du commit et #cmd[latest]],
)

- L'étiquette SHA relie chaque image publiée au commit exact qui a passé les contrôles.

// ═══════════════════════════════════════════
//  CONCLUSION
// ═══════════════════════════════════════════
= Conclusion

== Bilan

#htable(
  columns: (auto, auto, auto, auto, auto, auto),
  header: ([Run], [Tests], [SAST], [SCA], [DAST], [Résultat]),
  [\#3 #cmd[main]], [✓], [✓], [✓], [✓ 0 High], [image publiée],
  [\#4 PR \#1], [✓], [✓ (1 Medium)], [✓], [✗ injection SQL], [fusion bloquée],
  [\#5 PR \#2], [✓], [✓], [✓], [✓ 0 High], [fusionnable],
  [\#6 #cmd[main]], [✓], [✓], [✓], [✓ 0 High], [image publiée],
)

#deflist(
  [Automatisation], [les contrôles du TP1 tournent à chaque modification, sans intervention],
  [Garde-fou], [une alerte #emph[High] bloque la fusion (protection de branche) et la publication (#cmd[needs])],
  [Défense en profondeur], [le DAST a arrêté une injection que le SAST jugeait seulement #emph[Medium]],
  [Traçabilité], [rapports complets en artefacts, image étiquetée par commit],
)

== Limites et pistes

- *Contournement administrateur* : #cmd[enforce_admins] est désactivé pour pouvoir pousser ce rapport directement ; en équipe, il faut l'activer pour que personne ne puisse fusionner sans contrôles.
- *Couverture du DAST* : ZAP n'a signalé ni le XSS de #cmd[/notes/by-owner], ni celui de #cmd[/hello] dans l'image #cmd[v1] du TP1. Aucun outil ne voit tout ; les tests de non-régression ferment les failles connues.
- *Alertes non bloquantes* : les en-têtes de sécurité manquants (CSP, anti-#emph[clickjacking]) restent signalés en #emph[Medium] ; un middleware qui les ajoute, ou un reverse proxy, les traiterait.
- *Seuils* : bloquer sur #emph[High] est un compromis ; le resserrer à #emph[Medium] demanderait de traiter ou d'accepter explicitement chaque alerte (fichier de règles ZAP, #cmd[.snyk], #cmd[\# nosec]).
- *Image* : le pipeline publie encore l'image naïve du TP1 (#cmd[python:3.12] complet, #cmd[root]) ; son durcissement est l'objet du TP3.

#info-box([Dépôt], [
  - GitHub : #link("https://github.com/KacemMathlouthi/batch-tp-devsecops")[github.com/KacemMathlouthi/batch-tp-devsecops]
  - Workflow : #cmd[.github/workflows/ci.yml]
  - Pull requests : #link("https://github.com/KacemMathlouthi/batch-tp-devsecops/pull/1")[\#1 (bloquée)], #link("https://github.com/KacemMathlouthi/batch-tp-devsecops/pull/2")[\#2 (fusionnée)]
])
