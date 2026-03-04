# vul-anime-rest-api

> [!CAUTION]
> **Do not deploy this.** Seriously. Please.

A FastAPI app for anime recommendations. Small in-memory dataset (7 titles), JWT auth, AES/RSA crypto endpoints, S3 integration, and a collection of intentionally broken endpoints for every major vuln class.

Runs on Python 3.x. Interactive docs at `/docs` once running.

```bash
pip install -r requirements.txt
uvicorn main:app --reload
# → http://localhost:8000
```

Default accounts: `admin / admin123` (premium), `user / user123`.

---

## API Endpoints

### Anime

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/anime/all` | — | List all anime |
| GET | `/anime/{id}` | — | Get by ID |
| GET | `/anime/search?title=` | — | Title search |
| POST | `/anime/recommend` | — | Filter by genre, rating, episodes, year |
| POST | `/anime/rate` | — | Submit score + comment |
| POST | `/anime/create` | — | Add new entry |
| POST | `/anime/random` | — | Random pick |
| GET | `/anime/secure/{id}` | JWT | Fetch with optional AES decrypt |
| POST | `/anime/secure/create` | JWT | Create with encrypted description |

### Auth & User

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/token` | — | Get JWT (username + password in body) |
| POST | `/auth/login_with_redirect` | — | Login with post-auth redirect |
| GET | `/auth/logout?redirect=` | — | Logout with redirect |
| GET | `/user/profile` | JWT | Current user info |
| POST | `/api/user/preferences/save` | — | Serialize and save preferences |
| POST | `/api/user/preferences/load` | — | Restore saved preferences |

### Crypto

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/crypto/encrypt` | — | AES-256 encrypt |
| POST | `/crypto/decrypt` | — | AES-256 decrypt |
| POST | `/crypto/sign` | — | RSA sign JSON |
| POST | `/crypto/verify` | — | RSA verify signature |

### AWS S3 (premium only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/aws/s3/upload` | JWT | Upload JSON blob |
| POST | `/aws/s3/download` | JWT | Download by key |
| GET | `/aws/s3/list` | JWT | List objects |
| DELETE | `/aws/s3/delete?key=` | JWT | Delete object |

### Admin & Utils

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/config_info` | JWT (premium) | Show application config |
| GET | `/admin/database_config` | JWT (premium) | Show JDBC config |
| POST | `/utils/search_files` | — | Search files by pattern |
| POST | `/utils/fetch_url` | — | Fetch a URL server-side |
| GET | `/utils/fetch_image?url=` | — | Fetch image metadata from URL |
