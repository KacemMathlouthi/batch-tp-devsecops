# tp-devsecops

DevSecOps labs, 2026–2027. One small FastAPI notes service (`app/`) that is scanned, fixed, piped and hardened across three TPs.

| Folder | Contents |
|---|---|
| `app/` | FastAPI app, tests, hardened Dockerfile (distroless, non-root) |
| `tp1/` | SAST (Bandit) and SCA (OWASP Dependency-Check): scans and report |
| `tp2/` | Security gates in GitHub Actions: SAST, SCA, DAST (OWASP ZAP) |
| `.github/workflows/ci.yml` | CI/CD: tests, Bandit, Snyk, ZAP, Trivy gates, publish to GHCR |
| `k8s/` | restricted namespace, deployment with secrets from a Kubernetes Secret, Falco custom rule |
| `tp3/` | Container hardening (Trivy), Kubernetes Secrets, runtime detection with Falco |
| `docs/` | shared report template and fonts |

Each `tpN/compte-rendu/` holds the report (Typst source and PDF, in French).

Build a report:

```bash
typst compile --root . --font-path docs/fonts tp1/compte-rendu/main.typ
```
