## Lite Recon

- **Languages**: Python 3.11
- **Framework**: Flask 2.2.2 + Connexion 2.14.2 (OpenAPI-driven), SQLAlchemy 2.0.2, PyJWT 2.6.0
- **Entry points**: `app.py` (main), `api_views/users.py` (user routes), `api_views/books.py` (book routes), `api_views/main.py` (index/db init), `openapi_specs/openapi3.yml` (route definitions)
- **Auth**: JWT with HS256 (PyJWT), secret key hardcoded as `'random'` in `config.py:13`
- **Deployment**: Docker (Dockerfile present, multi-stage Alpine build), GitHub Actions (`docker-image.yml`)
- **Excluded from scan**: `openapi_specs/`, `.github/`, `database/` (empty init + SQLite db file)
