#import "/docs/template.typ": *

#let (shot, todo-shot) = shots("/tp1/compte-rendu/screenshots/")

#show: conf.with(
  tp: "TP1",
  short-title: "SAST et SCA",
  title: [Analyse statique (SAST) et sécurité des dépendances (SCA)],
  subtitle: [Trouver les failles dans le code et dans ses dépendances avant le déploiement, les corriger, puis prouver par un nouveau scan qu'elles ont disparu.],
  image-ref: "tp-devsecops:v1 → v2",
)

// ═══════════════════════════════════════════
//  PRÉSENTATION
// ═══════════════════════════════════════════
= Présentation générale

== Objectif

- Appliquer le #emph[shift-left] : déplacer les contrôles de sécurité au plus tôt dans le cycle, sur le code source et ses dépendances, avant toute mise en production.
- SAST : analyser le code sans l'exécuter pour repérer les motifs dangereux.
- SCA : inventorier les bibliothèques tierces et les confronter aux bases de vulnérabilités connues (CVE).
- Corriger, puis prouver la correction par un second scan.

#deflist(
  [SAST], [Bandit, image officielle #cmd[ghcr.io/pycqa/bandit/bandit], lancé via Docker],
  [SCA],  [OWASP Dependency-Check, image #cmd[owasp/dependency-check], lancé via Docker],
  [Preuve], [scan avant / après, exploitation réelle avant / après, tests de non-régression],
)

== Application

- Service de notes #cmd[FastAPI] (Python 3.12, #cmd[uv]), repris de l'application du TP de DevOps avancé.
- Étendu avec une base SQLite, une authentification et quelques routes typiques d'une API.
- Ces routes contiennent volontairement des erreurs classiques : le code part d'un état réaliste « non audité ».

#htable(
  columns: (auto, 1fr),
  header: ([Route], [Rôle]),
  [#cmd[GET /]], [liste des notes (template Jinja2)],
  [#cmd[GET /search?q=]], [recherche de notes par titre],
  [#cmd[GET /hello?name=]], [page de bienvenue],
  [#cmd[POST /login]], [authentification, renvoie un jeton],
  [#cmd[GET /ping?host=]], [test de connectivité réseau],
  [#cmd[POST /import]], [import de notes au format YAML],
  [#cmd[GET /healthz]], [sonde de santé],
)

== Stack technique

#deflist(
  [Langage],     [Python 3.12, FastAPI 0.109, Jinja2, SQLite],
  [Dépendances], [#cmd[uv] : #cmd[pyproject.toml] + #cmd[uv.lock] (versions figées)],
  [Conteneur],   [Docker Desktop (backend WSL 2)],
  [Tests],       [#cmd[pytest] + #cmd[TestClient]],
  [Dépôt],       [GitHub #cmd[KacemMathlouthi/batch-tp-devsecops], branche #cmd[main]],
)

== Organisation du dépôt

```
tp-devsecops/
├── app/                  # code, tests, Dockerfile, pyproject.toml, uv.lock
├── tp1/
│   ├── reports/          # rapports Bandit et Dependency-Check (HTML, JSON)
│   └── compte-rendu/     # ce rapport
├── tp2/  tp3/            # TP suivants
└── docs/                 # gabarit Typst partagé, polices
```

// ═══════════════════════════════════════════
//  ÉTAPE 1, ENVIRONNEMENT
// ═══════════════════════════════════════════
= Étape 1 : mise en place de l'environnement

== Dockerfile

- Première version volontairement naïve : image complète #cmd[python:3.12], exécution en #cmd[root], tout le contexte copié.
- Elle sert de point de départ ; son durcissement est l'objet du TP3.
- Dépendances installées par #cmd[uv sync --frozen] : le #cmd[uv.lock] est la seule source des versions, la même que celle scannée par la SCA.

```dockerfile
FROM python:3.12

COPY --from=ghcr.io/astral-sh/uv:0.7.20 /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

== Build et exécution

#shot("01-docker-build.png",
  [Build sans cache : 5 étapes, l'installation des dépendances par #cmd[uv sync --frozen] prend 1 s],
)

#shot("02-docker-run.png",
  [Conteneur #cmd[notes] démarré sur le port 8000 ; l'image pèse 1,69 Go],
)

#shot("03-app-home.png",
  [L'application servie par le conteneur],
)

== Les failles sont exploitables

Avant tout scan, trois attaques simples contre le conteneur #cmd[v1] montrent que les problèmes ne sont pas théoriques.

#shot("04-exploit-sqli.png",
  [Injection SQL sur #cmd[/search] : un #cmd[UNION] extrait le hash MD5 du mot de passe #cmd[admin] et la note privée],
)

#shot("05-exploit-cmdi.png",
  [Injection de commande sur #cmd[/ping] : #cmd[id] s'exécute, en #cmd[root], dans le conteneur],
)

#shot("06-exploit-xss.png",
  [XSS réfléchi sur #cmd[/hello] : le script est renvoyé tel quel au navigateur],
)

#warn-box([
  - Le hash #cmd[0192023a…] est le MD5 non salé de #cmd[admin123] : il se retrouve en clair dans n'importe quelle table de hashs précalculés.
  - L'injection de commande tourne en #cmd[uid=0] : l'image naïve aggrave l'impact de la faille applicative.
])

// ═══════════════════════════════════════════
//  ÉTAPE 2, SAST
// ═══════════════════════════════════════════
= Étape 2 : analyse statique (SAST)

== Bandit

- Analyseur statique de référence pour Python (PyCQA) : parcourt l'AST de chaque fichier et applique des règles (#cmd[Bxxx]) associées à une CWE.
- Lancé depuis son image officielle, sans rien installer localement.
- #cmd[.venv] et #cmd[tests] exclus : seul le code applicatif est audité.

```bash
docker run --rm -v "$PWD/app":/src ghcr.io/pycqa/bandit/bandit \
  -r /src -x /src/.venv,/src/tests
# rapports archivés : -f html -o tp1/reports/bandit-before.html, -f json
```

== Résultat initial

#shot("07-bandit-before.png",
  [Lancement du scan ; première alerte (B404)],
)

#shot("08-bandit-before-findings.png",
  [Trois des alertes : injection SQL (B608), MD5 (B324), #cmd[shell=True] (B602)],
)

#shot("09-bandit-before-summary.png",
  [Bilan : 11 problèmes sur 74 lignes, 4 #emph[High], 4 #emph[Medium], 3 #emph[Low]],
)

#htable(
  columns: (auto, auto, auto, 1fr, auto),
  header: ([Règle], [Sévérité], [Ligne], [Problème], [CWE]),
  [B701], sev("High"),   [22],  [Jinja2 sans #cmd[autoescape] → XSS], [79],
  [B324], sev("High"),   [32],  [MD5 pour les mots de passe], [327],
  [B324], sev("High"),   [72],  [MD5 pour le jeton de session], [327],
  [B602], sev("High"),   [78],  [#cmd[subprocess] avec #cmd[shell=True] → injection de commande], [78],
  [B608], sev("Medium"), [55],  [requête SQL construite par f-string → injection SQL], [89],
  [B506], sev("Medium"), [84],  [#cmd[yaml.load] non sûr → exécution de code], [502],
  [B108], sev("Medium"), [15],  [base de données dans #cmd[/tmp]], [377],
  [B104], sev("Medium"), [104], [écoute sur #cmd[0.0.0.0] codée en dur], [605],
  [B105], sev("Low"),    [18],  [#cmd[SECRET_KEY] en clair dans le code], [259],
  [B105], sev("Low"),    [19],  [#cmd[ADMIN_PASSWORD] en clair dans le code], [259],
  [B404], sev("Low"),    [5],   [import de #cmd[subprocess] (information)], [78],
)

#info-box([Ce que Bandit ne voit pas], [
  - Le XSS de #cmd[/hello] (f-string renvoyée en #cmd[HTMLResponse]) n'est signalé par aucune règle : Bandit raisonne par motifs, pas par flux de données.
  - Il a été trouvé par la revue manuelle et la démonstration ; un outil à analyse de teinte (Semgrep, SonarQube) l'aurait détecté.
])

== Corrections

Toutes les alertes sont corrigées dans un seul commit (#cmd[fix(app): remediate Bandit SAST findings]). Les quatre plus graves en détail :

=== Injection SQL (B608)

- La valeur de l'utilisateur devient un #emph[paramètre] lié par le pilote SQLite : elle ne peut plus modifier la structure de la requête.

```python
# avant
conn.execute(f"SELECT ... FROM notes WHERE title LIKE '%{q}%'")
# après
conn.execute("SELECT ... FROM notes WHERE title LIKE ?", (f"%{q}%",))
```

=== Injection de commande (B602, B607)

- Plus de shell : la commande est une liste d'arguments, les métacaractères (#cmd[;], #cmd[|], #cmd[\$()]) perdent leur sens.
- Validation stricte en amont : l'hôte doit être une adresse IP, sinon #cmd[400].
- Chemin absolu de #cmd[ping] résolu au démarrage (B607).

```python
# avant
subprocess.run(f"ping -c 1 {host}", shell=True, ...)
# après
ip = str(ipaddress.ip_address(host))          # ValueError → HTTP 400
subprocess.run([PING_BIN, "-c", "1", ip], ..., check=False)
```

=== Désérialisation YAML (B506)

- #cmd[yaml.Loader] instancie n'importe quel objet Python (#cmd[!!python/object/apply:os.system]).
- #cmd[yaml.safe_load] ne construit que des types simples ; une charge malveillante lève une erreur, convertie en #cmd[400].

=== XSS (B701 + #cmd[/hello])

- #cmd[select_autoescape(["html"])] sur l'environnement Jinja2 : toute variable du template est échappée.
- #cmd[html.escape(name)] sur la route #cmd[/hello], hors template.

=== Autres corrections

#deflist(
  [MD5 (B324)],       [mots de passe : PBKDF2-SHA256, sel aléatoire de 16 octets, 600 000 itérations, comparaison en temps constant ; jeton : HMAC-SHA256],
  [Secrets (B105)],   [#cmd[SECRET_KEY] et #cmd[ADMIN_PASSWORD] lus dans l'environnement ; sans mot de passe fourni, aucun compte admin n'est créé],
  [#cmd[/tmp] (B108)], [base dans #cmd[app/data/], ignorée par Git et Docker],
  [#cmd[0.0.0.0] (B104)], [le bloc #cmd[uvicorn.run] disparaît ; l'adresse d'écoute est un choix de déploiement, portée par le #cmd[CMD] du conteneur],
)

#info-box([Deux exceptions documentées (#cmd[\# nosec])], [
  - #cmd[B404] (import de #cmd[subprocess]) et #cmd[B603] (appel sans shell) sont des avertissements de principe : le module est nécessaire et n'est appelé qu'avec une liste d'arguments validée.
  - Chaque exception porte l'identifiant exact de la règle (#cmd[\# nosec B404]) et un commentaire justificatif ; Bandit les compte dans son rapport (« skipped … 2 »), elles restent donc visibles en revue.
])

== Tests de non-régression

- Un test par faille corrigée, rejouant la charge utilisée lors de l'exploitation.
- Si une modification future réintroduit la faille, la suite échoue (base du pipeline du TP2).

```python
def test_search_sql_injection_is_inert(client):
    payload = "%' UNION SELECT id, username, password, 'leak' FROM users --"
    assert client.get("/search", params={"q": payload}).json() == []
```

#shot("13-pytest.png",
  [5 tests fonctionnels + 5 tests de sécurité, tous au vert],
)

== Résultat après correction

#shot("10-bandit-after.png",
  [#emph[No issues identified] : 0 #emph[High], 0 #emph[Medium], 0 #emph[Low] ; les 2 exceptions justifiées sont comptées],
)

- Image reconstruite en #cmd[v2] ; les secrets sont passés par l'environnement (#cmd[-e ADMIN_PASSWORD] sans valeur : Docker reprend celle du shell, elle n'apparaît ni dans la commande ni dans l'historique).

#shot("11-docker-run-v2.png",
  [Build et lancement de l'image corrigée],
)

#shot("12-exploits-after.png",
  [Les mêmes attaques contre l'image #cmd[v2] : résultat vide, #cmd[400], HTML échappé, YAML refusé],
)

#success-box([
  - 11 alertes Bandit → 0, dont les 4 #emph[High].
  - Les quatre exploitations de l'étape 1 échouent sur l'image #cmd[v2].
  - Fonctionnalités intactes : les 5 tests fonctionnels passent toujours.
])
