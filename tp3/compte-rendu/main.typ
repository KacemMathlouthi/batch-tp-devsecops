#import "/docs/template.typ": *

#let (shot, todo-shot) = shots("/tp3/compte-rendu/screenshots/")

#show: conf.with(
  tp: "TP3",
  short-title: "Conteneurs et runtime",
  title: [Sécurité des conteneurs et surveillance au runtime],
  subtitle: [Une image minimale qui n'embarque que ce que l'application exécute, des secrets fournis par Kubernetes et jamais par le code, et un agent qui détecte ce qu'un attaquant ferait une fois à l'intérieur.],
  image-ref: "tp-devsecops:naive → hardened",
)

// ═══════════════════════════════════════════
//  PRÉSENTATION
// ═══════════════════════════════════════════
= Présentation générale

== Objectif

- Durcir l'image Docker : partir du rapport Trivy, réduire la surface d'attaque, supprimer les privilèges inutiles.
- Sortir les secrets du code et des images : les fournir à l'exécution par Kubernetes.
- Détecter un comportement malveillant pendant l'exécution avec Falco : un shell ouvert dans un conteneur de production.

== Point de départ

- L'application des TP1 et TP2 : API de notes FastAPI, code et dépendances corrigés, publiée par le pipeline CI/CD.
- Son Dockerfile est resté celui du TP1, volontairement naïf : image #cmd[python:3.12] complète, exécution en #cmd[root].
- Les secrets (#cmd[ADMIN_PASSWORD], #cmd[SECRET_KEY]) sont déjà lus dans l'environnement (TP1) ; reste à les fournir proprement.

== Stack technique

#deflist(
  [Scanner],     [Trivy 0.76 (#cmd[aquasec/trivy]) : vulnérabilités de l'image, mauvaises configurations du Dockerfile],
  [Image de base], [Chainguard #cmd[python] (Wolfi), #emph[distroless]],
  [Cluster],     [minikube (driver Docker, WSL 2), profil dédié #cmd[devsecops]],
  [Secrets],     [Kubernetes Secrets],
  [Runtime],     [Falco, sonde eBPF moderne],
)

// ═══════════════════════════════════════════
//  ÉTAPE 1, IMAGE
// ═══════════════════════════════════════════
= Étape 1 : sécurité de l'image Docker

== L'image actuelle

```dockerfile
FROM python:3.12

COPY --from=ghcr.io/astral-sh/uv:0.7.20 /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#shot("01-naive-image.png",
  [1,68 Go, exécutée en #cmd[root] (aucune instruction #cmd[USER])],
)

== Scan Trivy

- #cmd[trivy image] inventorie les paquets du système (Debian) et les paquets Python de l'image, puis les confronte aux bases de vulnérabilités.
- Lancé depuis son image officielle, avec le socket Docker pour lire l'image locale et un volume pour mettre sa base en cache.

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
  aquasec/trivy image tp-devsecops:naive
```

#shot("02-trivy-naive-summary.png",
  [2 786 vulnérabilités : 2 780 dans les paquets Debian (16 #emph[Critical], 491 #emph[High]), 6 dans #cmd[pip]],
)

#shot("03-trivy-naive-critical.png",
  [Les 16 vulnérabilités critiques (#cmd[--severity CRITICAL])],
)

== Analyse

#htable(
  columns: (auto, 1fr, auto),
  header: ([Composant], [Constat], [Utile à l'app ?]),
  [Clients MariaDB], [6 critiques (injection SQL, exécution de code) ; aucun correctif publié], [non],
  [OpenEXR, libxml2], [6 critiques (lecture de fichiers forgés)], [non],
  [#cmd[openssh-client]], [1 critique (#emph[use-after-free])], [non],
  [#cmd[linux-libc-dev]], [en-têtes du noyau pour compiler], [non],
  [#cmd[pip] 25.0.1], [6 vulnérabilités #emph[Medium]/#emph[Low]], [non (#cmd[uv])],
)

- L'image #cmd[python:3.12] est bâtie sur #cmd[buildpack-deps] : compilateurs, en-têtes, bibliothèques d'images et de bases de données, pour pouvoir compiler n'importe quel paquet. L'application n'en utilise aucun.
- La plupart des failles critiques sont #emph[affected] sans version corrigée : aucun #cmd[apt upgrade] ne les supprime. Le seul remède est de ne pas embarquer ces paquets.
- Le code et les dépendances de l'application, corrigés au TP1, sont propres : tout le risque vient de l'image de base.

#shot("04-trivy-config-naive.png",
  [#cmd[trivy config] sur le Dockerfile : exécution en #cmd[root] (#emph[High]), pas de #cmd[HEALTHCHECK] (#emph[Low])],
)

== Choix de l'image de base

#htable(
  columns: (1fr, auto, auto, auto),
  header: ([Image], [Taille], [Python], [Vulnérabilités]),
  [#cmd[python:3.12] (actuelle)], [1,68 Go], [3.12], [2 786 (16 C, 491 H)],
  [#cmd[python:3.12-slim]], [180 Mo], [3.12], [235 (48 H)],
  [#cmd[cgr.dev/chainguard/python]], [106 Mo], [3.15], [0],
)

- Chainguard publie des images #emph[distroless] bâties sur Wolfi : uniquement l'interpréteur et ses bibliothèques, sans shell ni gestionnaire de paquets, utilisateur non-root (#cmd[65532]) par défaut, reconstruites chaque jour.
- Python 3.15 au lieu de 3.12 : l'application et ses 13 tests passent sans modification (#cmd[requires-python = ">=3.12"]).
- La variante #cmd[-dev] (avec shell, #cmd[pip], #cmd[uv]) sert uniquement à l'étape de construction.

== Nouveau Dockerfile

```dockerfile
# ── Build stage: has a shell, pip and uv; never shipped ─────────────────────
FROM cgr.dev/chainguard/python:latest-dev@sha256:88d87152...095f AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
USER root
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
 && mkdir -p /app/data && chown 65532:65532 /app/data

# ── Runtime stage: distroless, no shell, no package manager ─────────────────
FROM cgr.dev/chainguard/python:latest@sha256:d914788e...ea8a
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DB_PATH=/app/data/notes.db
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=build --chown=65532:65532 /app/data /app/data
COPY main.py ./
COPY templates ./templates
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

== Changements et justification

#htable(
  columns: (auto, 1fr),
  header: ([Changement], [Pourquoi]),
  [Image #emph[distroless]], [plus de compilateurs, de bibliothèques ni de clients inutiles : les 2 780 vulnérabilités système disparaissent avec les paquets],
  [Construction multi-étapes], [#cmd[uv], #cmd[pip] et le shell restent dans l'étape #cmd[build] ; seuls le #cmd[.venv] et le code sont copiés dans l'image finale],
  [Dépendances seules, depuis le lockfile], [#cmd[COPY pyproject.toml uv.lock] puis #cmd[uv sync --frozen --no-dev] : versions figées, pas d'outils de test ; couche mise en cache tant que le lockfile ne change pas],
  [Copie ciblée], [#cmd[main.py] et #cmd[templates/] seulement, au lieu de #cmd[COPY . .] : ni tests, ni fichiers locaux, ni secrets oubliés dans le contexte],
  [#cmd[USER 65532]], [une faille d'exécution de code ne donne plus #cmd[root] dans le conteneur],
  [Code en lecture seule], [code et #cmd[.venv] appartiennent à #cmd[root] : l'utilisateur de l'application ne peut pas les modifier ; seul #cmd[/app/data] lui appartient],
  [Images épinglées par #emph[digest]], [#cmd[\@sha256:…] : une construction reproduit exactement la même base, une image de base altérée ne passerait pas inaperçue],
  [#cmd[HEALTHCHECK]], [Docker sait si l'application répond (sans #cmd[curl], absent de l'image : Python suffit)],
  [#cmd[ENTRYPOINT] direct], [#cmd[python -m uvicorn] au lieu de #cmd[uv run] : un processus de moins, plus d'outil de gestion de paquets au runtime],
)

#shot("05-build-hardened.png",
  [Construction en deux étapes ; seules les étapes #cmd[stage-1] composent l'image finale],
)

== Résultat

#shot("06-images-compare.png",
  [1,68 Go → 135 Mo ; #cmd[root] → #cmd[65532]],
)

#shot("07-trivy-hardened.png",
  [Trivy sur l'image durcie : 0 vulnérabilité, système (Wolfi) et paquets Python],
)

#shot("08-trivy-config-hardened.png",
  [#cmd[trivy config] : plus aucune mauvaise configuration],
)

#shot("09-hardened-run.png",
  [L'application répond, le conteneur est #emph[healthy] et non-root ; il n'y a plus de shell, ni même de commande #cmd[id], à exécuter],
)

#info-box([Effet de bord : #cmd[/ping]], [
  - La route #cmd[/ping] appelait le binaire #cmd[ping] du système ; il n'existe plus dans l'image et la route répond #cmd[503].
  - C'est le principe même : une fonctionnalité qui exécute des commandes système n'a plus de commandes à exécuter. Si elle était nécessaire, elle serait réécrite en Python (socket ICMP) plutôt que de réintroduire un binaire.
])

#success-box([
  - 2 786 vulnérabilités (16 #emph[Critical], 491 #emph[High]) → 0.
  - Taille divisée par 12, exécution non-root, aucun shell dans l'image.
  - Mêmes fonctionnalités, mêmes tests.
])
