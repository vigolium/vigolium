# Code Anatomy: Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

Generated: 2026-03-30T00:00:00Z
Files read: 11

---

## Functions

### `get_google_auth_url(next_path)` — `redash/handlers/authentication.py:23`
- **Returns**: URL string from `url_for` (google_oauth authorize endpoint)
- **Params**: next_path: unknown — next redirect target
- **Calls**: `url_for()` (`redash/handlers/authentication.py:25`, `:27`)
- **Side effects**: none

### `render_token_login_page(template, org_slug, token, invite)` — `redash/handlers/authentication.py:31`
- **Returns**: `(render_template(...), status_code)` or `redirect(...)`
- **Params**:
  - template: unknown — template name
  - org_slug: unknown — org slug for routing/templates
  - token: unknown — signed invite/reset token
  - invite: unknown — whether token is for invitation
- **Calls**: `validate_token()` (`redash/authentication/account.py:39`), `models.User.get_by_id_and_org()` (`redash/handlers/authentication.py:36`), `render_template()` (`:54`, `:63`, `:95`), `flash()` (`:75`, `:78`, `:81`), `user.hash_password()` (`:86`), `login_user()` (`:88`), `models.db.session.add()` (`:87`), `models.db.session.commit()` (`:89`), `redirect()` (`:90`), `url_for()` (`:90`, `:92`), `get_google_auth_url()` (`:92`)
- **Side effects**: DB write (user password, invitation state), session login, flash messages

### `invite(token, org_slug=None)` — `redash/handlers/authentication.py:109`
- **Returns**: value from `render_token_login_page(...)`
- **Params**:
  - token: unknown — invite token
  - org_slug: unknown — org slug
- **Calls**: `render_token_login_page()` (`redash/handlers/authentication.py:111`)
- **Side effects**: none

### `reset(token, org_slug=None)` — `redash/handlers/authentication.py:114`
- **Returns**: value from `render_token_login_page(...)`
- **Params**:
  - token: unknown — reset token
  - org_slug: unknown — org slug
- **Calls**: `render_token_login_page()` (`redash/handlers/authentication.py:116`)
- **Side effects**: none

### `verify(token, org_slug=None)` — `redash/handlers/authentication.py:119`
- **Returns**: `(render_template(...), 400)` on failure, or `render_template("verify.html", ...)` on success
- **Params**:
  - token: unknown — verification token
  - org_slug: unknown — org slug
- **Calls**: `validate_token()` (`redash/authentication/account.py:39`), `models.User.get_by_id_and_org()` (`redash/handlers/authentication.py:124`), `render_template()` (`:128`, `:142`), `models.db.session.add()` (`:136`), `models.db.session.commit()` (`:137`), `url_for()` (`:140`)
- **Side effects**: DB write (email verified)

### `forgot_password(org_slug=None)` — `redash/handlers/authentication.py:145`
- **Returns**: `render_template("forgot.html", submitted=...)`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `current_org.get_setting()` (`:148`), `abort()` (`:149`), `models.User.get_by_email_and_org()` (`:157`), `send_user_disabled_email()` (`redash/authentication/account.py:73`), `send_password_reset_email()` (`redash/authentication/account.py:62`), `render_template()` (`:165`)
- **Side effects**: email task dispatch, logs

### `verification_email(org_slug=None)` — `redash/handlers/authentication.py:168`
- **Returns**: `json_response({...})`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `send_verify_email()` (`redash/authentication/account.py:44`), `json_response()` (`redash/handlers/base.py`)
- **Side effects**: email task dispatch

### `login(org_slug=None)` — `redash/handlers/authentication.py:176`
- **Returns**: `redirect(...)` on success/early exit, otherwise `render_template("login.html", ...)`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `url_for()` (`:186`, `:207`), `request.args.get()` (`:187`), `get_next_path()` (`redash/authentication/__init__.py:301`), `models.User.get_by_email_and_org()` (`:195`), `user.verify_password()` (`:196`), `login_user()` (`:198`), `flash()` (`:201`, `:203`, `:205`), `render_template()` (`:209`)
- **Side effects**: session login, flash messages

### `logout(org_slug=None)` — `redash/handlers/authentication.py:223`
- **Returns**: `redirect(get_login_url(...))`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `logout_user()` (`:225`), `get_login_url()` (`redash/authentication/__init__.py:23`)
- **Side effects**: session logout

### `base_href()` — `redash/handlers/authentication.py:229`
- **Returns**: URL string from `url_for` with `_external=True`
- **Params**: none
- **Calls**: `url_for()` (`:231`, `:233`)
- **Side effects**: none

### `date_time_format_config()` — `redash/handlers/authentication.py:238`
- **Returns**: dict with date/time formats
- **Params**: none
- **Calls**: `current_org.get_setting()` (`:239`, `:241`)
- **Side effects**: none

### `number_format_config()` — `redash/handlers/authentication.py:251`
- **Returns**: dict with integer/float formats
- **Params**: none
- **Calls**: `current_org.get_setting()` (`:253`, `:254`)
- **Side effects**: none

### `null_value_config()` — `redash/handlers/authentication.py:258`
- **Returns**: dict with null value
- **Params**: none
- **Calls**: `current_org.get_setting()` (`:260`)
- **Side effects**: none

### `client_config()` — `redash/handlers/authentication.py:264`
- **Returns**: dict of client config
- **Params**: none
- **Calls**: `get_latest_version()` (`:267`), `current_user.is_api_user()` (`:265`), `current_user.has_permission()` (`:273`), `current_org.get_setting()` (`:273`, `:278`-`:281`), `settings.email_server_is_configured()` (`:285`), `base_href()` (`:296`), `date_time_format_config()` (`:297`), `number_format_config()` (`:298`), `null_value_config()` (`:299`)
- **Side effects**: none

### `messages()` — `redash/handlers/authentication.py:304`
- **Returns**: list of message strings
- **Params**: none
- **Calls**: `current_user.is_email_verified` (`:307`)
- **Side effects**: none

### `config(org_slug=None)` — `redash/handlers/authentication.py:316`
- **Returns**: `json_response({...})`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `client_config()` (`:318`), `json_response()` (`redash/handlers/base.py`)
- **Side effects**: none

### `session(org_slug=None)` — `redash/handlers/authentication.py:321`
- **Returns**: `json_response({...})`
- **Params**:
  - org_slug: unknown — org slug
- **Calls**: `messages()` (`:339`), `client_config()` (`:341`), `json_response()` (`:336`)
- **Side effects**: none

---

### `get_login_url(external=False, next="/")` — `redash/authentication/__init__.py:23`
- **Returns**: login URL string
- **Params**:
  - external: bool — passed to `_external`
  - next: str — next redirect target
- **Calls**: `url_for()` (`:27`, `:29`)
- **Side effects**: none

### `sign(key, path, expires)` — `redash/authentication/__init__.py:34`
- **Returns**: HMAC hex digest string or `None`
- **Params**:
  - key: str — secret key
  - path: str — request path
  - expires: float — expiry timestamp
- **Calls**: `hmac.new()` (`:38`), `h.update()` (`:39`)
- **Side effects**: none

### `load_user(user_id_with_identity)` — `redash/authentication/__init__.py:44`
- **Returns**: `models.User` or `models.ApiUser` or `None`
- **Params**:
  - user_id_with_identity: str — user id with identity suffix
- **Calls**: `api_key_load_user_from_request()` (`:46`), `current_org._get_current_object()` (`:50`), `models.User.get_by_id_and_org()` (`:54`)
- **Side effects**: none

### `request_loader(request)` — `redash/authentication/__init__.py:63`
- **Returns**: user object or `None`
- **Params**:
  - request: flask request
- **Calls**: `hmac_load_user_from_request()` (`:66`, `:71`), `api_key_load_user_from_request()` (`:68`), `jwt_token_load_user_from_request()` (`:74`)
- **Side effects**: logs warning

### `hmac_load_user_from_request(request)` — `redash/authentication/__init__.py:78`
- **Returns**: user object or `None`
- **Params**:
  - request: flask request
- **Calls**: `request.args.get()` (`:79`, `:80`, `:82`), `request.view_args.get()` (`:81`), `models.User.query.get()` (`:87`), `sign()` (`:88`, `:95`), `models.Query.query.filter(...).one()` (`:94`), `models.ApiUser(...)` (`:98`)
- **Side effects**: none

### `get_user_from_api_key(api_key, query_id)` — `redash/authentication/__init__.py:108`
- **Returns**: user object or `None`
- **Params**:
  - api_key: str — API key
  - query_id: unknown — query id
- **Calls**: `current_org._get_current_object()` (`:115`), `models.User.get_by_api_key_and_org()` (`:117`), `models.ApiKey.get_by_api_key()` (`:122`), `models.Query.get_by_id_and_org()` (`:126`), `models.ApiUser(...)` (`:123`, `:128`)
- **Side effects**: none

### `get_api_key_from_request(request)` — `redash/authentication/__init__.py:138`
- **Returns**: API key string or `None`
- **Params**:
  - request: flask request
- **Calls**: `request.args.get()` (`:139`), `request.headers.get()` (`:144`, `:145`)
- **Side effects**: none

### `api_key_load_user_from_request(request)` — `redash/authentication/__init__.py:153`
- **Returns**: user object or `None`
- **Params**:
  - request: flask request
- **Calls**: `get_api_key_from_request()` (`:154`), `request.view_args.get()` (`:156`), `get_user_from_api_key()` (`:157`)
- **Side effects**: none

### `jwt_token_load_user_from_request(request)` — `redash/authentication/__init__.py:164`
- **Returns**: user object or `None`
- **Params**:
  - request: flask request
- **Calls**: `current_org._get_current_object()` (`:165`), `request.cookies.get()` (`:170`), `request.headers.get()` (`:172`), `jwt_auth.verify_jwt_token()` (`:177`), `models.User.get_by_email_and_org()` (`:195`), `create_and_login_user()` (`:197`)
- **Side effects**: may raise `Unauthorized`, may create user, may log in user

### `log_user_logged_in(app, user)` — `redash/authentication/__init__.py:202`
- **Returns**: `None`
- **Params**:
  - app: flask app
  - user: user object
- **Calls**: `record_event.delay()` (`:213`)
- **Side effects**: enqueues event task

### `redirect_to_login()` — `redash/authentication/__init__.py:216`
- **Returns**: dict+status for XHR/API or redirect response
- **Params**: none
- **Calls**: `request.headers.get()` (`:218`), `request.path` (`:219`), `get_login_url()` (`:222`), `redirect()` (`:224`)
- **Side effects**: none

### `logout_and_redirect_to_index()` — `redash/authentication/__init__.py:227`
- **Returns**: redirect response
- **Params**: none
- **Calls**: `logout_user()` (`:228`), `url_for()` (`:233`, `:235`)
- **Side effects**: session logout

### `init_app(app)` — `redash/authentication/__init__.py:240`
- **Returns**: `None`
- **Params**:
  - app: flask app
- **Calls**: `login_manager.init_app()` (`:246`), `create_google_oauth_blueprint()` (`redash/authentication/google_oauth.py:67`), `csrf.exempt()` (`:264`), `app.register_blueprint()` (`:265`), `user_logged_in.connect()` (`:267`), `login_manager.request_loader()` (`:268`)
- **Side effects**: registers blueprints, configures login manager, sets session lifetime

### `create_and_login_user(org, name, email, picture=None)` — `redash/authentication/__init__.py:271`
- **Returns**: user object or `None`
- **Params**:
  - org: organization object
  - name: str
  - email: str
  - picture: str or None
- **Calls**: `models.User.get_by_email_and_org()` (`:273`), `models.db.session.commit()` (`:278`, `:282`, `:294`), `models.User(...)` (`:285`), `models.db.session.add()` (`:293`), `login_user()` (`:296`)
- **Side effects**: DB write, session login

### `get_next_path(unsafe_next_path)` — `redash/authentication/__init__.py:301`
- **Returns**: safe path string
- **Params**:
  - unsafe_next_path: str
- **Calls**: `urlsplit()` (`:306`), `urlunsplit()` (`:309`)
- **Side effects**: none

---

### `verify_profile(org, profile)` — `redash/authentication/google_oauth.py:16`
- **Returns**: bool
- **Params**:
  - org: organization object
  - profile: dict
- **Calls**: `org.has_user()` (`:26`)
- **Side effects**: none

### `get_user_profile(access_token, logger)` — `redash/authentication/google_oauth.py:32`
- **Returns**: dict or `None`
- **Params**:
  - access_token: str
  - logger: logger
- **Calls**: `requests.get()` (`:34`), `response.json()` (`:40`)
- **Side effects**: HTTP call

### `build_redirect_uri()` — `redash/authentication/google_oauth.py:43`
- **Returns**: URL string
- **Params**: none
- **Calls**: `url_for()` (`:45`)
- **Side effects**: none

### `build_next_path(org_slug=None)` — `redash/authentication/google_oauth.py:48`
- **Returns**: URL string
- **Params**:
  - org_slug: unknown
- **Calls**: `request.args.get()` (`:49`), `session.get()` (`:52`), `url_for()` (`:58`)
- **Side effects**: none

### `create_google_oauth_blueprint(app)` — `redash/authentication/google_oauth.py:67`
- **Returns**: Flask `Blueprint`
- **Params**:
  - app: flask app
- **Calls**: `OAuth(app)` (`:68`), `oauth.register()` (`:74`), `url_for()` (`:83`, `:111`, `:116`, `:130`), `redirect()` (`:83`, `:111`, `:116`, `:130`, `:142`), `build_redirect_uri()` (`:87`), `build_next_path()` (`:89`, `:139`), `oauth.google.authorize_redirect()` (`:95`), `oauth.google.authorize_access_token()` (`:101`), `get_user_profile()` (`:113`), `verify_profile()` (`:123`), `create_and_login_user()` (`:133`), `logout_and_redirect_to_index()` (`:135`), `get_next_path()` (`:140`)
- **Side effects**: session writes, external OAuth redirect

### `org_login(org_slug)` — `redash/authentication/google_oauth.py:80`
- **Returns**: redirect response
- **Params**:
  - org_slug: str
- **Calls**: `redirect()` (`:83`), `url_for()` (`:83`)
- **Side effects**: session write (`session["org_slug"]`)

### `login()` — `redash/authentication/google_oauth.py:85`
- **Returns**: redirect response
- **Params**: none
- **Calls**: `build_redirect_uri()` (`:87`), `build_next_path()` (`:89`), `oauth.google.authorize_redirect()` (`:95`)
- **Side effects**: session write (`session["next_url"]`)

### `authorized()` — `redash/authentication/google_oauth.py:97`
- **Returns**: redirect response
- **Params**: none
- **Calls**: `oauth.google.authorize_access_token()` (`:101`), `get_user_profile()` (`:113`), `models.Organization.get_by_slug()` (`:119`), `verify_profile()` (`:123`), `create_and_login_user()` (`:133`), `logout_and_redirect_to_index()` (`:135`), `build_next_path()` (`:139`), `get_next_path()` (`:140`), `redirect()` (`:111`, `:116`, `:130`, `:142`)
- **Side effects**: session writes, session login, flashes

---

### `get_saml_client(org)` — `redash/authentication/saml_auth.py:24`
- **Returns**: `Saml2Client`
- **Params**:
  - org: organization object
- **Calls**: `org.get_setting()` (`:31`-`:36`), `url_for()` (`:39`, `:46`), `get_xmlsec_binary()` (`:73`), `mustache_render()` (`:84`), `json.loads()` (`:99`), `Saml2Config.load()` (`:102`), `Saml2Client(...)` (`:104`)
- **Side effects**: none

### `idp_initiated(org_slug=None)` — `redash/authentication/saml_auth.py:109`
- **Returns**: redirect response
- **Params**:
  - org_slug: unknown
- **Calls**: `current_org.get_setting()` (`:111`), `get_saml_client()` (`:115`), `saml_client.parse_authn_request_response()` (`:117`), `flash()` (`:122`), `redirect()` (`:113`, `:123`, `:146`), `create_and_login_user()` (`:136`), `logout_and_redirect_to_index()` (`:138`), `user.update_group_assignments()` (`:142`), `url_for()` (`:144`)
- **Side effects**: session login, possible group assignment

### `sp_initiated(org_slug=None)` — `redash/authentication/saml_auth.py:149`
- **Returns**: redirect response
- **Params**:
  - org_slug: unknown
- **Calls**: `current_org.get_setting()` (`:151`, `:156`), `get_saml_client()` (`:155`), `saml_client.prepare_for_authenticate()` (`:160`), `redirect()` (`:167`)
- **Side effects**: sets response headers

---

### `login(org_slug=None)` — `redash/authentication/ldap_auth.py:32`
- **Returns**: redirect response or `render_template("login.html", ...)`
- **Params**:
  - org_slug: unknown
- **Calls**: `url_for()` (`:34`, `:40`, `:57`), `request.args.get()` (`:35`), `get_next_path()` (`:36`), `auth_ldap_user()` (`:46`), `create_and_login_user()` (`:49`), `logout_and_redirect_to_index()` (`:55`), `flash()` (`:59`), `render_template()` (`:61`)
- **Side effects**: session login, flash

### `auth_ldap_user(username, password)` — `redash/authentication/ldap_auth.py:72`
- **Returns**: LDAP user entry or `None`
- **Params**:
  - username: str
  - password: str
- **Calls**: `escape_filter_chars()` (`:73`), `Server(...)` (`:74`), `Connection(...)` (`:76`, `:84`), `conn.search()` (`:86`), `conn.rebind()` (`:97`)
- **Side effects**: LDAP network operations

---

### `get_public_key_from_file(url)` — `redash/authentication/jwt_auth.py:12`
- **Returns**: key string
- **Params**:
  - url: str
- **Calls**: `open()` (`:14`), `key_file.read()` (`:15`)
- **Side effects**: file read, updates `get_public_keys.key_cache`

### `get_public_key_from_net(url)` — `redash/authentication/jwt_auth.py:21`
- **Returns**: list of public keys or JSON payload
- **Params**:
  - url: str
- **Calls**: `requests.get()` (`:22`), `r.raise_for_status()` (`:23`), `r.json()` (`:24`), `jwt.algorithms.RSAAlgorithm.from_jwk()` (`:28`)
- **Side effects**: HTTP call, updates `get_public_keys.key_cache`

### `get_public_keys(url)` — `redash/authentication/jwt_auth.py:38`
- **Returns**: list/dict of keys
- **Params**:
  - url: str
- **Calls**: `get_public_key_from_file()` (`:49`), `get_public_key_from_net()` (`:51`)
- **Side effects**: uses cache in `get_public_keys.key_cache`

### `verify_jwt_token(jwt_token, expected_issuer, expected_audience, algorithms, public_certs_url)` — `redash/authentication/jwt_auth.py:58`
- **Returns**: `(payload, valid_token)` tuple
- **Params**:
  - jwt_token: str
  - expected_issuer: str
  - expected_audience: str
  - algorithms: list
  - public_certs_url: str
- **Calls**: `get_public_keys()` (`:62`), `jwt.get_unverified_header()` (`:64`), `jwt.decode()` (`:73`), `logging.exception()` (`:80`)
- **Side effects**: logs exceptions

---

### `login(org_slug=None)` — `redash/authentication/remote_user_auth.py:19`
- **Returns**: redirect response
- **Params**:
  - org_slug: unknown
- **Calls**: `request.args.get()` (`:21`), `get_next_path()` (`:22`), `request.headers.get()` (`:28`), `redirect()` (`:26`, `:43`, `:51`), `create_and_login_user()` (`:47`), `logout_and_redirect_to_index()` (`:49`), `url_for()` (`:26`, `:43`, `:51`)
- **Side effects**: session login

---

### `invite_token(user)` — `redash/authentication/account.py:14`
- **Returns**: signed token string
- **Params**:
  - user: user object
- **Calls**: `serializer.dumps()` (`:15`)
- **Side effects**: none

### `verify_link_for_user(user)` — `redash/authentication/account.py:18`
- **Returns**: URL string
- **Params**:
  - user: user object
- **Calls**: `invite_token()` (`:19`), `base_url()` (`:20`)
- **Side effects**: none

### `invite_link_for_user(user)` — `redash/authentication/account.py:25`
- **Returns**: URL string
- **Params**:
  - user: user object
- **Calls**: `invite_token()` (`:26`), `base_url()` (`:27`)
- **Side effects**: none

### `reset_link_for_user(user)` — `redash/authentication/account.py:32`
- **Returns**: URL string
- **Params**:
  - user: user object
- **Calls**: `invite_token()` (`:33`), `base_url()` (`:34`)
- **Side effects**: none

### `validate_token(token)` — `redash/authentication/account.py:39`
- **Returns**: deserialized token value
- **Params**:
  - token: str
- **Calls**: `serializer.loads()` (`:41`)
- **Side effects**: none

### `send_verify_email(user, org)` — `redash/authentication/account.py:44`
- **Returns**: `None`
- **Params**:
  - user: user object
  - org: organization object
- **Calls**: `verify_link_for_user()` (`:45`), `render_template()` (`:46`, `:47`), `send_mail.delay()` (`:50`)
- **Side effects**: email task dispatch

### `send_invite_email(inviter, invited, invite_url, org)` — `redash/authentication/account.py:53`
- **Returns**: `None`
- **Params**:
  - inviter: user object
  - invited: user object
  - invite_url: str
  - org: organization object
- **Calls**: `render_template()` (`:55`, `:56`), `send_mail.delay()` (`:59`)
- **Side effects**: email task dispatch

### `send_password_reset_email(user)` — `redash/authentication/account.py:62`
- **Returns**: reset link string
- **Params**:
  - user: user object
- **Calls**: `reset_link_for_user()` (`:63`), `render_template()` (`:65`, `:66`), `send_mail.delay()` (`:69`)
- **Side effects**: email task dispatch

### `send_user_disabled_email(user)` — `redash/authentication/account.py:73`
- **Returns**: `None`
- **Params**:
  - user: user object
- **Calls**: `render_template()` (`:74`, `:75`), `send_mail.delay()` (`:78`)
- **Side effects**: email task dispatch

---

### `_get_current_org()` — `redash/authentication/org_resolving.py:9`
- **Returns**: `Organization` object
- **Params**: none
- **Calls**: `Organization.get_by_slug()` (`:18`)
- **Side effects**: sets `g.org`

---

### `email_server_is_configured()` — `redash/settings/__init__.py:249`
- **Returns**: bool
- **Params**: none
- **Calls**: none
- **Side effects**: none

---

## Defensive Patterns

| Location | Pattern | Trigger condition | Exact behavior when triggered |
|----------|---------|-------------------|-------------------------------|
| `redash/handlers/authentication.py:37-50` | try/catch | `NoResultFound`, `SignatureExpired`, or `BadSignature` in `render_token_login_page` | sets `error_message` and returns `render_template("error.html", error_message=...)` with status `400` |
| `redash/handlers/authentication.py:61-70` | state check | invite and `user.details.get("is_invitation_pending") is False` | returns `render_template("error.html", error_message=...)` with status `400` |
| `redash/handlers/authentication.py:74-83` | input validation | missing/empty/short password in POST | flashes error, sets `status_code = 400`, returns login page template with status `400` |
| `redash/handlers/authentication.py:125-133` | try/catch | `BadSignature` or `NoResultFound` in `verify` | returns `render_template("error.html", error_message=...)` with status `400` |
| `redash/handlers/authentication.py:148-149` | feature gate | `auth_password_login_enabled` false | `abort(404)` |
| `redash/handlers/authentication.py:158-164` | exception handling | `NoResultFound` in forgot password | logs error and continues to render form with `submitted=True` |
| `redash/handlers/authentication.py:179-185` | null check | `current_org == None` | redirects to `/setup` or `/` based on `MULTI_ORG` |
| `redash/handlers/authentication.py:189-190` | auth check | `current_user.is_authenticated` | redirects to `next_path` |
| `redash/handlers/authentication.py:192-205` | feature gate | password login disabled | flashes "Password login is not enabled for your organization." |
| `redash/authentication/__init__.py:35-37` | null check | `key` is falsy in `sign` | returns `None` |
| `redash/authentication/__init__.py:52-60` | try/catch | `NoResultFound`, `ValueError`, `AttributeError` in `load_user` | returns `None` |
| `redash/authentication/__init__.py:70-71` | fallback | unknown `settings.AUTH_TYPE` | logs warning and falls back to HMAC loader |
| `redash/authentication/__init__.py:85-105` | time bounds check | `signature` and `time.time() < expires <= time.time() + 3600` | only then attempts signature validation; otherwise returns `None` |
| `redash/authentication/__init__.py:109-110` | null check | missing `api_key` in `get_user_from_api_key` | returns `None` |
| `redash/authentication/__init__.py:118-119` | state check | user is disabled | returns `None` |
| `redash/authentication/__init__.py:169-174` | configuration gate | neither JWT cookie nor header name configured | returns `None` |
| `redash/authentication/__init__.py:184-185` | validation guard | JWT verification returns `token_is_valid == False` | raises `Unauthorized("Invalid JWT token")` |
| `redash/authentication/__init__.py:187-188` | null check | no payload | returns `None` |
| `redash/authentication/__init__.py:190-192` | required field check | payload missing `email` | logs info and returns `None` |
| `redash/authentication/__init__.py:218-221` | request type check | XHR or `/api/` path | returns `{"message": "Couldn't find resource. Please login and try again."}, 404` |
| `redash/authentication/__init__.py:230-236` | null check | `current_org == None` with `MULTI_ORG` | redirects to `/` (index_url is `/`) |
| `redash/authentication/__init__.py:302-316` | open redirect mitigation | `unsafe_next_path` present | strips scheme/netloc; if result empty sets `safe_next_path = "./"` |
| `redash/authentication/google_oauth.py:36-38` | status check | Google profile request returns 401 | logs warning and returns `None` |
| `redash/authentication/google_oauth.py:108-116` | null check | missing access token or profile | flashes "Validation error. Please retry." and redirects to login |
| `redash/authentication/google_oauth.py:123-130` | authorization check | `verify_profile` returns False | flashes "Your Google Apps account (...) isn't allowed." and redirects to login |
| `redash/authentication/saml_auth.py:111-114` | feature gate | `auth_saml_enabled` false | logs error and redirects to index |
| `redash/authentication/saml_auth.py:116-123` | try/catch | exception parsing SAML response | flashes "SAML login failed..." and redirects to login |
| `redash/authentication/saml_auth.py:157-159` | fallback value | empty `auth_saml_nameid_format` | uses `NAMEID_FORMAT_TRANSIENT` |
| `redash/authentication/ldap_auth.py:38-41` | feature gate | LDAP login disabled | logs error and redirects to index |
| `redash/authentication/ldap_auth.py:42-43` | auth check | `current_user.is_authenticated` | redirects to `next_path` |
| `redash/authentication/ldap_auth.py:92-93` | empty result check | LDAP search returns no entries | returns `None` |
| `redash/authentication/ldap_auth.py:97-98` | auth check | LDAP rebind fails | returns `None` |
| `redash/authentication/remote_user_auth.py:24-26` | feature gate | remote user login disabled | logs error and redirects to index |
| `redash/authentication/remote_user_auth.py:34-36` | special-case check | header value is "(null)" | sets `email = None` |
| `redash/authentication/remote_user_auth.py:37-43` | required value check | missing email header | logs error and redirects to index |
| `redash/authentication/jwt_auth.py:45-52` | cache check | key cache has URL | returns cached keys without fetching |
| `redash/authentication/jwt_auth.py:64-67` | key-id filter | JWT header has `kid` and keys dict | sets `keys = [keys.get(key_id)]` |
| `redash/authentication/jwt_auth.py:71-81` | try/catch | any exception during decode | logs exception, continues trying other keys, returns `(payload, False)` if none succeed |
| `redash/authentication/account.py:39-41` | token expiration | `serializer.loads` with `max_age` | raises `SignatureExpired`/`BadSignature` to caller (not caught here) |
| `redash/settings/__init__.py:61-64` | required setting check | `SECRET_KEY is None` | raises `Exception(...)` |
| `redash/settings/organization.py:5-9` | deprecation guard | `REDASH_SAML_LOCAL_METADATA_PATH` set | prints notice and exits (`SystemExit(1)`) |

---

## External Calls

| Location | Target | Input | Parameterized? | Error handling |
|----------|--------|-------|:-:|---|
| `redash/handlers/authentication.py:36` | DB query | `models.User.get_by_id_and_org(user_id, org)` | Yes | exceptions caught in caller (`NoResultFound`) |
| `redash/handlers/authentication.py:87-89` | DB write | `models.db.session.add(user)` + commit | N/A | no local error handling |
| `redash/handlers/authentication.py:136-137` | DB write | set `user.is_email_verified = True` and commit | N/A | no local error handling |
| `redash/handlers/authentication.py:157` | DB query | `models.User.get_by_email_and_org(email, org)` | Yes | `NoResultFound` caught/logged |
| `redash/handlers/authentication.py:195` | DB query | `models.User.get_by_email_and_org(email, org)` | Yes | `NoResultFound` caught, flash message |
| `redash/authentication/__init__.py:87` | DB query | `models.User.query.get(user_id)` | Yes | no local error handling |
| `redash/authentication/__init__.py:94` | DB query | `models.Query.query.filter(...).one()` | Yes | no local error handling |
| `redash/authentication/__init__.py:117` | DB query | `models.User.get_by_api_key_and_org(api_key, org)` | Yes | `NoResultFound` handled with fallbacks |
| `redash/authentication/__init__.py:122` | DB query | `models.ApiKey.get_by_api_key(api_key)` | Yes | `NoResultFound` handled with fallbacks |
| `redash/authentication/__init__.py:126` | DB query | `models.Query.get_by_id_and_org(query_id, org)` | Yes | no local error handling |
| `redash/authentication/__init__.py:195` | DB query | `models.User.get_by_email_and_org(email, org)` | Yes | `NoResultFound` triggers user creation |
| `redash/authentication/__init__.py:293-294` | DB write | create user and commit | N/A | no local error handling |
| `redash/authentication/__init__.py:213` | Queue/task | `record_event.delay(event)` | N/A | no local error handling |
| `redash/authentication/google_oauth.py:34` | HTTP call | GET https://www.googleapis.com/oauth2/v1/userinfo with OAuth header | N/A | on 401 returns `None` |
| `redash/authentication/google_oauth.py:119` | DB query | `models.Organization.get_by_slug(...)` | Yes | no local error handling |
| `redash/authentication/saml_auth.py:117` | SAML parsing | `saml_client.parse_authn_request_response(...)` | N/A | exception caught, flash + redirect |
| `redash/authentication/ldap_auth.py:76-84` | LDAP bind | `Connection(..., auto_bind=True)` | N/A | no local error handling |
| `redash/authentication/ldap_auth.py:86-90` | LDAP search | `conn.search(...)` | N/A | checks `conn.entries` length |
| `redash/authentication/ldap_auth.py:97` | LDAP rebind | `conn.rebind(...)` | N/A | returns `None` on failure |
| `redash/authentication/jwt_auth.py:14-15` | File read | `open(file_path).read()` | N/A | no local error handling |
| `redash/authentication/jwt_auth.py:22-24` | HTTP call | GET `public_certs_url` | N/A | `raise_for_status()` exceptions bubble |
| `redash/authentication/account.py:50` | Queue/task | `send_mail.delay([user.email], ...)` | N/A | no local error handling |
| `redash/authentication/account.py:59` | Queue/task | `send_mail.delay([invited.email], ...)` | N/A | no local error handling |
| `redash/authentication/account.py:69` | Queue/task | `send_mail.delay([user.email], ...)` | N/A | no local error handling |
| `redash/authentication/account.py:78` | Queue/task | `send_mail.delay([user.email], ...)` | N/A | no local error handling |

---

## Trust Assumptions

| Location | Assumption | Evidence |
|----------|-----------|---------|
| `redash/handlers/authentication.py:74-87` | `request.form["password"]` is present for POST | direct index access without checking keys beyond `"password" not in request.form` |
| `redash/handlers/authentication.py:152-155` | `request.form["email"]` exists in POST | direct use in `if request.method == "POST" and request.form["email"]` |
| `redash/handlers/authentication.py:195-196` | `request.form["email"]` and `request.form["password"]` exist | direct indexing without `.get` |
| `redash/authentication/__init__.py:81-83` | `request.view_args` contains `query_id` when needed | `request.view_args.get(...)` without default validation logic |
| `redash/authentication/__init__.py:177-183` | JWT claims include expected `iss` and `aud` | reads `payload["iss"]`, passes `audience` into decode |
| `redash/authentication/google_oauth.py:20-24` | `profile["email"]` is a valid email containing `@` | splits on `@` without validation |
| `redash/authentication/google_oauth.py:132` | `profile["picture"]` is present | constructs `picture_url` directly |
| `redash/authentication/saml_auth.py:127-131` | SAML attributes contain `FirstName` and `LastName` | direct indexing into `authn_response.ava` |
| `redash/authentication/ldap_auth.py:46` | POST provides `email` and `password` | direct indexing into `request.form` |
| `redash/authentication/remote_user_auth.py:28` | trusted header value is email | uses header value as email without parsing |
| `redash/authentication/jwt_auth.py:74-75` | JWT payload includes `iss` claim | `payload["iss"]` without guard |
| `redash/authentication/account.py:11-15` | `settings.SECRET_KEY` usable for serializer | serializer initialized at import time |
| `redash/authentication/org_resolving.py:18` | `Organization.get_by_slug(slug)` succeeds | no exception handling around lookup |

---

## Layer Transitions

| Direction | From | To | Data passed | Validation before handoff? |
|-----------|------|----|------------|:---:|
| Inbound | HTTP route | `authentication.login` | form `email`, `password`, query `next` | Partial (password login enabled, `get_next_path`) |
| Inbound | HTTP route | `authentication.invite/reset/verify` | URL token | Partial (token validation, exception handling) |
| Inbound | HTTP route | `google_oauth.authorized` | OAuth response/access token | Partial (checks access token, profile, domain) |
| Inbound | HTTP route | `saml_auth.idp_initiated` | SAMLResponse POST | Partial (feature gate, parse try/catch) |
| Inbound | HTTP route | `ldap_auth.login` | form `email`, `password` | Partial (LDAP auth result) |
| Inbound | HTTP route | `remote_user_auth.login` | header `REMOTE_USER_HEADER` | Partial (checks presence and "(null)") |
| Inbound | Flask request loader | `jwt_token_load_user_from_request` | JWT from cookie/header | Partial (JWT verification, email field check) |
| Outbound | `create_and_login_user` | DB layer | user lookup/create and commit | No (no extra validation in function) |
| Outbound | `auth_ldap_user` | LDAP server | search template and bind credentials | Partial (escape username, check results) |
| Outbound | `get_user_profile` | Google API | access token in header | Partial (401 handled) |
| Outbound | `verify_jwt_token` | JWKS endpoint/file | public certs URL | Partial (HTTP errors not caught here) |
| Outbound | `send_*_email` | task queue | email payload | No (no local validation) |
| Outbound | `log_user_logged_in` | task queue | login event | No |
