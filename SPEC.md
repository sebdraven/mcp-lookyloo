# mcp-lookyloo — Spécification

Serveur MCP en Go exposant **toute** l'API REST de Lookyloo, avec CLI, CI/CD GitHub Actions, binaires multi-plateformes et specs Quint.

Document destiné à l'agent qui implémente le projet de bout en bout (code, tests, CI, specs Quint, PR).

---

## 0. Légende

| Terme | Définition |
|---|---|
| **Opération** | Un couple (méthode HTTP, chemin) du swagger Lookyloo. |
| **Tool** | Un outil MCP exposé par le serveur. Un tool peut couvrir plusieurs opérations (variantes GET/POST ou chemin/query du même endpoint). |
| **Capture** | Une exécution de Lookyloo sur une URL ou un document, identifiée par un UUID. |
| **Artefact** | Fichier binaire produit par une capture : screenshot PNG, ZIP de données, ZIP d'export. |
| **Niveau R** (read) | Tool sans effet de bord sur l'instance ni sur un tiers. |
| **Niveau S** (submit) | Tool qui fait travailler l'instance (nouvelle capture, modules tiers) sans effet hors de l'instance. |
| **Niveau P** (push) | Tool qui provoque un effet **hors** de l'instance : envoi d'email, push MISP, import de capture. |
| **Niveau A** (admin) | Tool d'administration de l'instance, dont certains destructifs. |
| **Fixture** | Réponse JSON/binaire réelle enregistrée depuis l'instance de référence, rejouée par `httptest` en CI. |
| **Instance de référence** | `http://citizen-lab:5100`, Lookyloo **1.27.0**. |

---

## 1. Source de vérité de l'API

- Swagger 2.0 de l'instance : `http://citizen-lab:5100/swagger.json` (titre « Lookyloo API », version `1.27.0`).
- L'agent récupère ce fichier et le versionne dans `api/lookyloo-swagger-1.27.0.json`. Toute évolution de l'API passe par la mise à jour de ce fichier dans une PR dédiée.
- Le swagger ne décrit **pas** la plupart des corps de réponse (seulement `"200": Success`). Les types Go des réponses se calent sur les **fixtures réelles**, pas sur des suppositions. Quand une forme n'est pas connue, le tool renvoie le JSON brut (`json.RawMessage`) tel quel.
- Point non documenté dans le swagger : le corps de `POST /json/upload`. L'agent lit le code de Lookyloo (`website/web/genericapi.py`, dépôt `Lookyloo/lookyloo`, tag correspondant à 1.27.0) pour en déduire le format, et le cite en commentaire de PR. Pas de devinette.
- Sécurité : header `Authorization: <token>` (`securityDefinitions.apikey`).

---

## 2. Couverture : 43 opérations → 35 tools

Préfixe des tools : `lk_`. Tous les paramètres reprennent les noms du swagger.

### 2.1 Captures — lecture (niveau R)

| Tool | Opération(s) | Paramètres |
|---|---|---|
| `lk_capture_info` | `GET /json/{capture_uuid}/info` | `capture_uuid` |
| `lk_capture_status` | `GET /json/{capture_uuid}/status` | `capture_uuid`, `with_error` (bool) |
| `lk_capture_stats` | `GET /json/{capture_uuid}/stats` | `capture_uuid` |
| `lk_capture_redirects` | `GET /json/{capture_uuid}/redirects` | `capture_uuid` |
| `lk_capture_urls` | `GET /json/{capture_uuid}/urls` | `capture_uuid`, `limit`, `offset` (pagination côté serveur MCP) |
| `lk_capture_hostnames` | `GET /json/{capture_uuid}/hostnames` | `capture_uuid`, `limit`, `offset` |
| `lk_capture_hashes` | `GET /json/{capture_uuid}/hashes` | `capture_uuid`, `algorithm` (défaut `sha512`), `hashes_only` (défaut `true`), `limit`, `offset` |
| `lk_capture_cookies` | `GET /json/{capture_uuid}/cookies` | `capture_uuid` |
| `lk_capture_comparables` | `GET /json/{capture_uuid}/comparables` | `capture_uuid`, `fields` (→ header `X-Fields`, masque) |
| `lk_capture_modules` | `GET /json/{capture_uuid}/modules` | `capture_uuid` |
| `lk_capture_misp_export` | `GET /json/{capture_uuid}/misp_export` | `capture_uuid` |

### 2.2 Artefacts binaires (niveau R)

| Tool | Opération | Sortie |
|---|---|---|
| `lk_capture_screenshot` | `GET /bin/{capture_uuid}/screenshot` (`image/png`) | Contenu image MCP **et**, si `out_dir` fourni, fichier `<uuid>.png` |
| `lk_capture_data` | `GET /bin/{capture_uuid}/data` (`application/zip`) | Fichier `<uuid>-data.zip` dans `out_dir` |
| `lk_capture_export` | `GET /bin/{capture_uuid}/export` (`application/zip`) | Fichier `<uuid>-export.zip` dans `out_dir` |

Règles :
- Les ZIP ne passent **jamais** dans la réponse MCP : écrits sur disque, la réponse donne `path`, `size`, `sha256` **complet**.
- `out_dir` : paramètre du tool, sinon flag `-out`, sinon erreur explicite (pas de `/tmp` implicite).
- Le contenu des ZIP n'est pas décompressé (données potentiellement malveillantes).

### 2.3 Recherche et pivots (niveau R)

| Tool | Opération(s) | Paramètres |
|---|---|---|
| `lk_url_info` | `POST /json/url_info` (`URLInfoFields`) | `url`*, `limit` (défaut 20), `cached_captures_only` (défaut `true`) |
| `lk_hostname_info` | `POST /json/hostname_info` (`HostnameInfoFields`) | `hostname`*, `limit`, `cached_captures_only` |
| `lk_hash_info` | `GET /json/hash_info/{h}` | `h`* (SHA512 complet, 128 hex — validé avant l'appel) |
| `lk_tld_captures` | `GET /json/tlds` | `tld`, `oldest_capture`, `most_recent_capture`, `urls_only` |
| `lk_categories` | `GET /json/categories`, `GET /json/categories/{category}` | `category` (optionnel ; absent = liste des catégories) |
| `lk_recent_captures` | `GET /json/recent_captures`, `GET /json/recent_captures/{timestamp}` | `timestamp` (optionnel) |
| `lk_compare_captures` | `POST /json/compare_captures` (`CompareCapturesFields`) | `capture_left`*, `capture_right`*, `ressources_ignore_domains[]`, `ressources_ignore_regexes[]` |
| `lk_takedown_info` | `POST /json/takedown` (`TakedownFields`) | `capture_uuid`*, `filter` (bool) |

### 2.4 Instance (niveau R)

| Tool | Opération | Note |
|---|---|---|
| `lk_devices` | `GET /json/devices` | Valeurs valides pour `device_name` de `lk_submit` |
| `lk_instance_stats` | `GET /json/stats` | |
| `lk_user_config` | `GET /json/get_user_config` | Authentifié |

### 2.5 Soumission (niveau S — actif par défaut, désactivable par `-read-only`)

| Tool | Opération(s) | Paramètres |
|---|---|---|
| `lk_submit` | `POST /submit` (`SubmitFieldsPost`) — le `GET /submit` n'est pas utilisé | `url` **ou** `document_path` (fichier local lu et encodé en base64 par le serveur) **ou** `document` (base64) + `document_name` ; `listing` (**défaut `false`**), `allow_tracking`, `java_script_enabled`, `user_agent`, `browser_name` (`chromium`/`firefox`/`webkit`), `device_name`, `referer`, `headers`, `proxy`, `cookies`, `auto_report{email,comment}` ; `wait` (bool), `wait_timeout` (défaut 120 s) |
| `lk_trigger_modules` | `POST /json/{capture_uuid}/trigger_modules` (`TriggerModulesFields`) | `capture_uuid`*, `force` |

Points imposés :
- **`listing` vaut `false` par défaut** côté MCP (le défaut Lookyloo est `1`) : une capture CTI ne s'affiche pas sur l'index public sauf demande explicite.
- `/submit` répond en `text/text` : l'UUID, éventuellement entre guillemets JSON. Le client gère les deux formes et valide le format UUID.
- `wait=true` : poll de `lk_capture_status` jusqu'à état terminal ou timeout, puis renvoie `capture_uuid`, état final, et `lk_capture_info`. Machine d'états en §5.1.
- `proxy` peut contenir des identifiants : jamais loggé, jamais renvoyé dans la réponse.
- Exactement une source parmi `url` / `document` / `document_path`, sinon erreur avant appel.

### 2.6 Effets externes (niveau P — inactif sauf flag `-allow-push`)

| Tool | Opération(s) | Effet externe |
|---|---|---|
| `lk_capture_report` | `POST /json/{capture_uuid}/report` | Envoi d'un email à l'équipe d'investigation de l'instance |
| `lk_misp_push` | `POST /json/{capture_uuid}/misp_push`, `POST /json/{capture_uuid}/misp_push/{instance_name}` (`MISPPushFields`) — variantes GET non utilisées | Création d'événement MISP |
| `lk_upload_capture` | `POST /json/upload` | Import d'une capture venant d'une autre instance (format : cf. §1) |

### 2.7 Administration (niveau A — inactif sauf flag `-allow-admin`, authentifié)

| Tool | Opération | Destructif |
|---|---|---|
| `lk_admin_hide` | `POST /admin/{capture_uuid}/hide` | non (réversible côté instance) |
| `lk_admin_rebuild` | `POST /admin/{capture_uuid}/rebuild` | non |
| `lk_admin_remove` | `POST /admin/{capture_uuid}/remove` | **oui** |
| `lk_admin_rebuild_cache` | `POST /admin/rebuild_all_cache` | non, mais long |
| `lk_admin_rebuild_all` | `POST /admin/rebuild_all` | non, mais **très** long (avertissement du swagger) |

### 2.8 Exclusion volontaire

`GET`/`POST /json/get_token` n'est **pas** exposé comme tool : des identifiants ne transitent pas par le LLM. L'obtention du token est gérée par le client (§3). C'est la seule opération du swagger non exposée en tool ; elle est néanmoins couverte par le client et testée.

### 2.9 Annotations MCP

Chaque tool porte ses `ToolAnnotations` : `readOnlyHint=true` pour R ; `destructiveHint=true` pour `lk_admin_remove` ; `openWorldHint=true` pour S et P. Un test CI vérifie que les 35 tools sont enregistrés avec les bons flags et qu'aucun tool P/A n'est enregistré sans son flag.

---

## 3. Configuration et authentification

| Élément | Source (par ordre de priorité) |
|---|---|
| URL de l'instance | flag `-url`, puis `LOOKYLOO_URL`, défaut `http://citizen-lab:5100` |
| Token API | `LOOKYLOO_API_KEY`, puis trousseau macOS service `lookyloo` (`security find-generic-password -s lookyloo -w`), puis obtention via `POST /json/get_token` avec `LOOKYLOO_USERNAME` / `LOOKYLOO_PASSWORD` |
| Répertoire d'artefacts | paramètre du tool, puis flag `-out` |

- Même structure que `internal/urlscan/key.go` de `mcp-urlscanio`.
- Le token n'est requis que pour les opérations marquées `security: apikey` (`get_user_config`, `misp_push`, admin). Les tools R/S fonctionnent sans token. Un tool authentifié sans token renvoie une erreur explicite qui liste les trois sources.
- Le token et le mot de passe ne sont jamais loggés, y compris en mode debug.

---

## 4. Architecture

```
mcp-lookyloo/
├── api/lookyloo-swagger-1.27.0.json
├── cmd/mcp-lookyloo/main.go
├── internal/
│   ├── lookyloo/          client HTTP, un fichier par groupe (capture.go, search.go, artefacts.go, submit.go, push.go, admin.go, auth.go)
│   │   └── testdata/      fixtures enregistrées depuis citizen-lab
│   └── mcptools/          enregistrement des tools, gating par niveau
├── spec/                  specs Quint (.qnt), une par feature à état
├── .github/workflows/     ci.yml, release.yml, zizmor.yml
├── SPEC.md
└── README.md
```

- Module : `github.com/sebdraven/mcp-lookyloo`, **Go 1.27**, SDK `github.com/modelcontextprotocol/go-sdk` v1.7.0 (aligné sur `mcp-urlscanio`).
- Dépendances : bibliothèque standard + SDK MCP. Pas de client généré depuis le swagger.
- Client : `http.Client` avec timeout (défaut 60 s, artefacts 300 s), `User-Agent: mcp-lookyloo/<version>`, erreurs HTTP enrichies (statut + 512 premiers octets du corps).
- Transports : stdio par défaut ; `-http <addr>` en streamable HTTP, sans authentification, à binder sur `127.0.0.1` (même choix que `mcp-urlscanio`).
- CLI one-shot (sans démarrer MCP), sortie JSON indentée sur stdout :
  - `-version`
  - `-submit <url>` (+ `-wait`) → UUID et état
  - `-info <uuid>`
  - `-url-info <url>`
- Flags de gating : `-read-only` (retire S), `-allow-push` (ajoute P), `-allow-admin` (ajoute A).

---

## 5. Specs Quint

Pratique : une spec Quint par feature à état, écrite **avant** le code de la feature, dans `spec/`. Quint tourne **en local sur le Mac** (pas en CI). Avant chaque PR, l'agent lance `quint typecheck` et `quint test` / `quint run` sur les specs touchées et colle la sortie dans la description de PR.

### 5.1 `spec/capture_lifecycle.qnt` — soumission et attente

États Lookyloo d'une capture : à relever sur l'instance et dans le code de `lacuscore` (`CaptureStatus`) avant d'écrire la spec — valeurs attendues `-1` UNKNOWN, `0` QUEUED, `1` DONE, `2` ONGOING, **à confirmer, pas à supposer**.

Modèle : `Submitted → {Queued, Ongoing, Done, Unknown}`, poll borné par `wait_timeout`.

Invariants :
- `lk_submit` avec `wait` termine toujours : état `Done`, `Unknown`, ou `TimedOut` (jamais de boucle infinie).
- On ne renvoie jamais `Done` sans qu'un poll ait effectivement observé `Done`.
- Un `Unknown` persistant N polls consécutifs (N=3) arrête l'attente avec une erreur explicite.
- Le nombre de requêtes de poll est borné par `wait_timeout / poll_interval + 1`.

### 5.2 `spec/tool_gating.qnt` — niveaux de permission

Invariants :
- Aucun tool de niveau P n'est enregistré si `allow_push = false`.
- Aucun tool de niveau A n'est enregistré si `allow_admin = false`.
- `read_only = true` ⇒ seuls les tools R sont enregistrés, quels que soient les autres flags.
- L'ensemble des tools enregistrés est monotone en fonction des flags.

### 5.3 `spec/auth.qnt` — résolution du token

Invariants :
- L'ordre de priorité env → trousseau → get_token est respecté.
- `get_token` n'est appelé que si aucune source précédente n'a fourni de token, et au plus une fois par processus (token mis en cache).
- Un appel authentifié sans token aboutit à une erreur, jamais à un appel HTTP sans header.

La correspondance spec ↔ code est assurée par des tests Go qui reprennent les mêmes scénarios (traces nommées comme les `run` Quint).

---

## 6. Tests (exécutés **uniquement** en CI)

- **Unitaires** avec `httptest.Server` rejouant les fixtures de `internal/lookyloo/testdata/`. Chaque tool a au moins : un cas nominal, un cas 404/UUID inconnu, un cas paramètre invalide (validé avant tout appel HTTP).
- **Enregistrement des fixtures** : l'agent les capture depuis `http://citizen-lab:5100` (requêtes de lecture uniquement + une soumission de test avec `listing=0` sur une URL inoffensive), puis les nettoie (aucun token, aucun cookie de session réel). Les fixtures binaires (PNG, ZIP) sont réduites au minimum valide.
- **Tests de contrat** : un test vérifie que chaque `operationId` du swagger versionné est soit mappé à un tool, soit listé dans l'exclusion §2.8. Une opération ajoutée au swagger sans mapping fait échouer la CI.
- **Tests de gating** : liste exacte des tools par combinaison de flags (miroir de §5.2).
- **Intégration** contre une vraie instance : `//go:build integration`, lancée seulement si `LOOKYLOO_URL` est défini, **non lancée en CI** par défaut.
- `-race` et couverture comme dans `mcp-urlscanio`.

---

## 7. CI/CD (GitHub Actions)

Reprendre `mcp-urlscanio` à l'identique pour la forme : actions épinglées par SHA, `permissions: contents: read` par défaut, `persist-credentials: false`, `concurrency`, audit `zizmor`.

### 7.1 `ci.yml` (push sur `main`, PR)

Jobs : `test` (gofmt, `go vet`, `go test -race` + couverture dans le step summary), `staticcheck`, `build` (build + `-version`), plus le test de contrat swagger (§6).

### 7.2 `release.yml` (tag `v*`)

Cross-compilation depuis `ubuntu-latest`, `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w -X main.version=${TAG}"`, une matrice :

| GOOS | GOARCH | Artefact |
|---|---|---|
| linux | arm64 | `mcp-lookyloo-linux-arm64` |
| linux | amd64 | `mcp-lookyloo-linux-amd64` |
| windows | amd64 | `mcp-lookyloo-windows-amd64.exe` |
| darwin | arm64 | `mcp-lookyloo-darwin-arm64` |

- Une ligne `darwin/arm64` en plus de la demande, pour le Mac (convention des autres serveurs MCP).
- `checksums-<suffix>.txt` en SHA256 complet par binaire, publiés avec `gh release upload --clobber`.
- Si une action JavaScript est nécessaire : runtime **Node 24**. Jamais `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`.

### 7.3 `zizmor.yml`

Copie de celui de `mcp-urlscanio`.

---

## 8. Mode de travail de l'agent

1. **Jamais sur `main`.** Une branche par PR, aux noms du §9. Si l'agent est déjà sur une branche de travail dédiée à ce lot, il y reste.
2. **Aucun build ni test Go en local** (`go build`, `go test`, `go vet`, `gofmt`, `docker build`) : la CI fait tout. Seul Quint tourne en local.
3. Spec Quint de la feature d'abord (si elle a un état), puis code, puis tests, puis PR.
4. L'agent commite, pousse, ouvre la PR, suit la CI et corrige jusqu'au vert. **Il ne merge pas** : le user valide et merge.
5. Description de PR : opérations couvertes, sortie Quint, ce qui reste ouvert. Commentaires de code minimalistes : le raisonnement va dans la PR, pas dans les fichiers.
6. Hashes toujours complets (SHA256 des artefacts, SHA512 de `hash_info`), dans le code, les tests, les logs et les PR.

---

## 9. Découpage en PR

| # | Branche | Contenu |
|---|---|---|
| 1 | `feat/skeleton-client-auth` | go.mod, `main.go`, client HTTP, résolution du token + `spec/auth.qnt`, swagger versionné, `ci.yml`, `zizmor.yml` |
| 2 | `feat/capture-read-tools` | §2.1 + §2.4, fixtures, tests |
| 3 | `feat/search-tools` | §2.3, validation SHA512, pagination |
| 4 | `feat/artefacts` | §2.2, écriture disque, SHA256 complet |
| 5 | `feat/submit-wait` | §2.5 + `spec/capture_lifecycle.qnt`, `listing=false` par défaut |
| 6 | `feat/gating-push-admin` | §2.6, §2.7, flags + `spec/tool_gating.qnt`, annotations §2.9 |
| 7 | `feat/contract-test` | test swagger ↔ tools (§6) |
| 8 | `feat/release` | `release.yml` (§7.2), README (installation, config Claude Desktop/Code, liste des tools par niveau) |

Critère de fin : les 43 opérations du swagger sont couvertes (35 tools + exclusion `get_token` documentée), test de contrat vert, release `v0.1.0` publiée avec les 4 binaires et leurs checksums.
