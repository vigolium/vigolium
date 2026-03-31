# Code Anatomy: URL-loading query runners (json/csv/excel/url) and HTTP data sources (Jira, Elasticsearch2, Drill) in Redash

Generated: 2026-03-30T00:00:00Z
Files read: 9

---

## Functions

### `split_sql_statements(query)` — `redash/query_runner/__init__.py:50`
- **Returns**: list of statement strings (non-empty; returns `['']` if all empty)
- **Params**: `query: str — SQL text`
- **Calls**: `strip_trailing_comments()` (local), `strip_trailing_semicolon()` (local), `is_empty_statement()` (local), `sqlparse.engine.FilterStack()`
- **Side effects**: none

### `combine_sql_statements(queries)` — `redash/query_runner/__init__.py:97`
- **Returns**: concatenated string joined by `";\n"`
- **Params**: `queries: list[str] — statements`
- **Calls**: none
- **Side effects**: none

### `find_last_keyword_idx(parsed_query)` — `redash/query_runner/__init__.py:101`
- **Returns**: index of last keyword token or `-1`
- **Params**: `parsed_query: sqlparse.sql.Statement — parsed query`
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.__init__(configuration)` — `redash/query_runner/__init__.py:124`
- **Returns**: None
- **Params**: `configuration: dict — data source config`
- **Calls**: none
- **Side effects**: sets `self.syntax`, `self.configuration`

### `BaseQueryRunner.name()` — `redash/query_runner/__init__.py:129`
- **Returns**: class name
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.type()` — `redash/query_runner/__init__.py:133`
- **Returns**: lowercase class name
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.enabled()` — `redash/query_runner/__init__.py:137`
- **Returns**: `True`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.host` (getter) — `redash/query_runner/__init__.py:141`
- **Returns**: `configuration['host']`
- **Params**: none
- **Calls**: none
- **Side effects**: raises `NotImplementedError` if missing

### `BaseQueryRunner.host` (setter) — `redash/query_runner/__init__.py:154`
- **Returns**: None
- **Params**: `host: str — new host`
- **Calls**: none
- **Side effects**: mutates `configuration['host']` or raises `NotImplementedError`

### `BaseQueryRunner.port` (getter) — `redash/query_runner/__init__.py:167`
- **Returns**: `configuration['port']`
- **Params**: none
- **Calls**: none
- **Side effects**: raises `NotImplementedError` if missing

### `BaseQueryRunner.port` (setter) — `redash/query_runner/__init__.py:179`
- **Returns**: None
- **Params**: `port: int — new port`
- **Calls**: none
- **Side effects**: mutates `configuration['port']` or raises `NotImplementedError`

### `BaseQueryRunner.configuration_schema()` — `redash/query_runner/__init__.py:193`
- **Returns**: `{}`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.annotate_query(query, metadata)` — `redash/query_runner/__init__.py:196`
- **Returns**: annotated string or original query
- **Params**: `query: str — SQL`, `metadata: dict — key/value annotations`
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.test_connection()` — `redash/query_runner/__init__.py:204`
- **Returns**: None
- **Params**: none
- **Calls**: `self.run_query()`
- **Side effects**: raises `NotImplementedError` if `noop_query` is `None`; raises `Exception(error)` on error

### `BaseQueryRunner.run_query(query, user)` — `redash/query_runner/__init__.py:212`
- **Returns**: not implemented
- **Params**: `query: str`, `user: object`
- **Calls**: none
- **Side effects**: raises `NotImplementedError`

### `BaseQueryRunner.fetch_columns(columns)` — `redash/query_runner/__init__.py:215`
- **Returns**: list of column dicts with unique names
- **Params**: `columns: list[tuple] — (name, type)`
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.get_schema(get_stats=False)` — `redash/query_runner/__init__.py:231`
- **Returns**: not supported
- **Params**: `get_stats: bool`
- **Calls**: none
- **Side effects**: raises `NotSupported`

### `BaseQueryRunner._handle_run_query_error(error)` — `redash/query_runner/__init__.py:234`
- **Returns**: None
- **Params**: `error: str|None`
- **Calls**: `logger.error()`
- **Side effects**: raises `Exception("Error during query execution. Reason: {error}")` if error

### `BaseQueryRunner._run_query_internal(query)` — `redash/query_runner/__init__.py:241`
- **Returns**: `results['rows']`
- **Params**: `query: str`
- **Calls**: `self.run_query()`
- **Side effects**: raises `Exception("Failed running query [<query>].")` on error

### `BaseQueryRunner.to_dict()` — `redash/query_runner/__init__.py:249`
- **Returns**: metadata dict
- **Params**: none
- **Calls**: `cls.name()`, `cls.type()`, `cls.configuration_schema()`
- **Side effects**: none

### `BaseQueryRunner.supports_auto_limit` — `redash/query_runner/__init__.py:258`
- **Returns**: `False`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.apply_auto_limit(query_text, should_apply_auto_limit)` — `redash/query_runner/__init__.py:261`
- **Returns**: `query_text`
- **Params**: `query_text: str`, `should_apply_auto_limit: bool`
- **Calls**: none
- **Side effects**: none

### `BaseQueryRunner.gen_query_hash(query_text, set_auto_limit=False)` — `redash/query_runner/__init__.py:264`
- **Returns**: hash value
- **Params**: `query_text: str`, `set_auto_limit: bool`
- **Calls**: `self.apply_auto_limit()`; `utils.gen_query_hash()`
- **Side effects**: none

### `BaseSQLQueryRunner.get_schema(get_stats=False)` — `redash/query_runner/__init__.py:270`
- **Returns**: list of schema dicts
- **Params**: `get_stats: bool`
- **Calls**: `_get_tables()`, `_get_tables_stats()` (optional)
- **Side effects**: none

### `BaseSQLQueryRunner._get_tables(schema_dict)` — `redash/query_runner/__init__.py:277`
- **Returns**: `[]`
- **Params**: `schema_dict: dict`
- **Calls**: none
- **Side effects**: none

### `BaseSQLQueryRunner._get_tables_stats(tables_dict)` — `redash/query_runner/__init__.py:280`
- **Returns**: None
- **Params**: `tables_dict: dict`
- **Calls**: `_run_query_internal()`
- **Side effects**: mutates `tables_dict` with `size`

### `BaseSQLQueryRunner.supports_auto_limit` — `redash/query_runner/__init__.py:286`
- **Returns**: `True`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseSQLQueryRunner.query_is_select_no_limit(query)` — `redash/query_runner/__init__.py:290`
- **Returns**: `True/False`
- **Params**: `query: str`
- **Calls**: `sqlparse.parse()`, `find_last_keyword_idx()`
- **Side effects**: none

### `BaseSQLQueryRunner.add_limit_to_query(query)` — `redash/query_runner/__init__.py:304`
- **Returns**: modified query string
- **Params**: `query: str`
- **Calls**: `sqlparse.parse()`
- **Side effects**: none

### `BaseSQLQueryRunner.apply_auto_limit(query_text, should_apply_auto_limit)` — `redash/query_runner/__init__.py:323`
- **Returns**: combined query string (possibly modified)
- **Params**: `query_text: str`, `should_apply_auto_limit: bool`
- **Calls**: `split_sql_statements()`, `query_is_select_no_limit()`, `add_limit_to_query()`, `combine_sql_statements()`
- **Side effects**: none

### `BaseHTTPQueryRunner.configuration_schema()` — `redash/query_runner/__init__.py:343`
- **Returns**: JSON schema dict with url/username/password
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseHTTPQueryRunner.get_auth()` — `redash/query_runner/__init__.py:365`
- **Returns**: `(username, password)` or `None`
- **Params**: none
- **Calls**: none
- **Side effects**: raises `ValueError("Username and Password required")` when required and missing

### `BaseHTTPQueryRunner.get_response(url, auth=None, http_method="get", **kwargs)` — `redash/query_runner/__init__.py:375`
- **Returns**: `(response, error)`
- **Params**: `url: str`, `auth: tuple|None`, `http_method: str`, `kwargs: dict`
- **Calls**: `requests_session.request()`
- **Side effects**: HTTP request; logs exceptions

### `register(query_runner_class)` — `redash/query_runner/__init__.py:414`
- **Returns**: None
- **Params**: `query_runner_class: type`
- **Calls**: `query_runner_class.enabled()`; `logger.debug()`
- **Side effects**: mutates global `query_runners`

### `get_query_runner(query_runner_type, configuration)` — `redash/query_runner/__init__.py:431`
- **Returns**: instance or `None`
- **Params**: `query_runner_type: str`, `configuration: dict`
- **Calls**: `query_runner_class(configuration)`
- **Side effects**: none

### `get_configuration_schema_for_query_runner_type(query_runner_type)` — `redash/query_runner/__init__.py:439`
- **Returns**: schema dict or `None`
- **Params**: `query_runner_type: str`
- **Calls**: `query_runner_class.configuration_schema()`
- **Side effects**: none

### `import_query_runners(query_runner_imports)` — `redash/query_runner/__init__.py:447`
- **Returns**: None
- **Params**: `query_runner_imports: list[str]`
- **Calls**: `__import__()`
- **Side effects**: imports modules

### `guess_type(value)` — `redash/query_runner/__init__.py:452`
- **Returns**: Redash type string
- **Params**: `value: any`
- **Calls**: `guess_type_from_string()`
- **Side effects**: none

### `guess_type_from_string(string_value)` — `redash/query_runner/__init__.py:463`
- **Returns**: Redash type string
- **Params**: `string_value: str|None`
- **Calls**: `int()`, `float()`, `parser.parse()`
- **Side effects**: none

### `with_ssh_tunnel(query_runner, details)` — `redash/query_runner/__init__.py:491`
- **Returns**: `query_runner` with wrapped `run_query`
- **Params**: `query_runner: BaseQueryRunner`, `details: dict`
- **Calls**: `open_tunnel()`; `settings.dynamic_settings.ssh_tunnel_auth()`
- **Side effects**: opens SSH tunnel; mutates query runner host/port during execution

### `Url.test_connection()` — `redash/query_runner/url.py:9`
- **Returns**: None
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Url.run_query(query, user)` — `redash/query_runner/url.py:12`
- **Returns**: `(json_data, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `self.get_response()`
- **Side effects**: HTTP request

### `parse_query(query)` — `redash/query_runner/json_ds.py:23`
- **Returns**: parsed YAML object
- **Params**: `query: str`
- **Calls**: `yaml.safe_load()`; `logging.exception()`
- **Side effects**: raises `QueryParseError` on empty or invalid YAML

### `_get_column_by_name(columns, column_name)` — `redash/query_runner/json_ds.py:47`
- **Returns**: column dict or `None`
- **Params**: `columns: list[dict]`, `column_name: str`
- **Calls**: none
- **Side effects**: none

### `_get_type(value)` — `redash/query_runner/json_ds.py:55`
- **Returns**: type string
- **Params**: `value: any`
- **Calls**: none
- **Side effects**: none

### `add_column(columns, column_name, column_type)` — `redash/query_runner/json_ds.py:59`
- **Returns**: None
- **Params**: `columns: list[dict]`, `column_name: str`, `column_type: str`
- **Calls**: `_get_column_by_name()`
- **Side effects**: appends to `columns`

### `_apply_path_search(response, path, default=None)` — `redash/query_runner/json_ds.py:64`
- **Returns**: nested value or `default`
- **Params**: `response: dict`, `path: str|None`, `default: any`
- **Calls**: none
- **Side effects**: raises `Exception("Couldn't find path ...")` if missing and no default

### `_normalize_json(data, path)` — `redash/query_runner/json_ds.py:82`
- **Returns**: list or `None`
- **Params**: `data: any`, `path: str|None`
- **Calls**: `_apply_path_search()`
- **Side effects**: none

### `_sort_columns_with_fields(columns, fields)` — `redash/query_runner/json_ds.py:93`
- **Returns**: list of columns
- **Params**: `columns: list[dict]`, `fields: list|None`
- **Calls**: `_get_column_by_name()`
- **Side effects**: none

### `parse_json(data, fields)` — `redash/query_runner/json_ds.py:101`
- **Returns**: `{rows, columns}`
- **Params**: `data: list[dict]`, `fields: list|None`
- **Calls**: `add_column()`, `_get_type()`, `_sort_columns_with_fields()`
- **Side effects**: none

### `JSON.configuration_schema()` — `redash/query_runner/json_ds.py:138`
- **Returns**: JSON schema dict (`base_url`, `username`, `password`)
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `JSON.__init__(configuration)` — `redash/query_runner/json_ds.py:150`
- **Returns**: None
- **Params**: `configuration: dict`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `yaml`

### `JSON.test_connection()` — `redash/query_runner/json_ds.py:154`
- **Returns**: None
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `JSON.run_query(query, user)` — `redash/query_runner/json_ds.py:157`
- **Returns**: `(data, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `parse_query()`, `_run_json_query()`
- **Side effects**: none

### `JSON._run_json_query(query)` — `redash/query_runner/json_ds.py:168`
- **Returns**: `(parsed_json, error)`
- **Params**: `query: dict`
- **Calls**: `RequestPagination.from_config()`, `_get_all_results()`, `parse_json()`
- **Side effects**: raises `QueryParseError` on invalid input

### `JSON._get_all_results(url, method, result_path, pagination, **request_options)` — `redash/query_runner/json_ds.py:200`
- **Returns**: `(results, error)`
- **Params**: `url: str`, `method: str`, `result_path: str|None`, `pagination: RequestPagination|None`, `request_options: dict`
- **Calls**: `urljoin()`, `_get_json_response()`, `_normalize_json()`, `pagination.next()`
- **Side effects**: HTTP requests via `_get_json_response()`

### `JSON._get_json_response(url, method, **request_options)` — `redash/query_runner/json_ds.py:219`
- **Returns**: `(result, error)`
- **Params**: `url: str`, `method: str`, `request_options: dict`
- **Calls**: `self.get_response()`, `response.json()`
- **Side effects**: HTTP request

### `RequestPagination.next(url, request_options, response)` — `redash/query_runner/json_ds.py:226`
- **Returns**: `(False, None, request_options)`
- **Params**: `url: str`, `request_options: dict`, `response: dict`
- **Calls**: none
- **Side effects**: none

### `RequestPagination.from_config(configuration, pagination)` — `redash/query_runner/json_ds.py:235`
- **Returns**: `UrlPagination` or `TokenPagination`
- **Params**: `configuration: dict`, `pagination: dict`
- **Calls**: `UrlPagination()`, `TokenPagination()`
- **Side effects**: raises `QueryParseError` on invalid config

### `UrlPagination.__init__(pagination)` — `redash/query_runner/json_ds.py:248`
- **Returns**: None
- **Params**: `pagination: dict`
- **Calls**: none
- **Side effects**: raises `QueryParseError` if `path` is not string

### `UrlPagination.next(url, request_options, response)` — `redash/query_runner/json_ds.py:253`
- **Returns**: `(has_more, next_url, request_options)`
- **Params**: `url: str`, `request_options: dict`, `response: dict`
- **Calls**: `_apply_path_search()`, `urljoin()`
- **Side effects**: none

### `TokenPagination.__init__(pagination)` — `redash/query_runner/json_ds.py:263`
- **Returns**: None
- **Params**: `pagination: dict`
- **Calls**: none
- **Side effects**: raises `QueryParseError` if `fields` is not list of 2

### `TokenPagination.next(url, request_options, response)` — `redash/query_runner/json_ds.py:268`
- **Returns**: `(has_more, url, request_options)`
- **Params**: `url: str`, `request_options: dict`, `response: dict`
- **Calls**: `_apply_path_search()`
- **Side effects**: mutates `request_options['params']`; raises `Exception` if token repeats

### `CSV.name()` — `redash/query_runner/csv.py:27`
- **Returns**: `"CSV"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `CSV.enabled()` — `redash/query_runner/csv.py:31`
- **Returns**: `enabled`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `CSV.configuration_schema()` — `redash/query_runner/csv.py:35`
- **Returns**: schema object with empty properties
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `CSV.__init__(configuration)` — `redash/query_runner/csv.py:41`
- **Returns**: None
- **Params**: `configuration: dict`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `yaml`

### `CSV.test_connection()` — `redash/query_runner/csv.py:45`
- **Returns**: None
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `CSV.run_query(query, user)` — `redash/query_runner/csv.py:48`
- **Returns**: `(data, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `yaml.safe_load()`, `requests_or_advocate.get()`, `pd.read_csv()`
- **Side effects**: HTTP request

### `CSV.get_schema()` — `redash/query_runner/csv.py:111`
- **Returns**: not supported
- **Params**: none
- **Calls**: none
- **Side effects**: raises `NotSupported`

### `Excel.enabled()` — `redash/query_runner/excel.py:27`
- **Returns**: `enabled`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Excel.configuration_schema()` — `redash/query_runner/excel.py:32`
- **Returns**: schema object with empty properties
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Excel.__init__(configuration)` — `redash/query_runner/excel.py:38`
- **Returns**: None
- **Params**: `configuration: dict`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `yaml`

### `Excel.test_connection()` — `redash/query_runner/excel.py:42`
- **Returns**: None
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Excel.run_query(query, user)` — `redash/query_runner/excel.py:45`
- **Returns**: `(data, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `yaml.safe_load()`, `requests_or_advocate.get()`, `pd.read_excel()`
- **Side effects**: HTTP request

### `Excel.get_schema()` — `redash/query_runner/excel.py:109`
- **Returns**: not supported
- **Params**: none
- **Calls**: none
- **Side effects**: raises `NotSupported`

### `ResultSet.__init__()` — `redash/query_runner/jql.py:10`
- **Returns**: None
- **Params**: none
- **Calls**: none
- **Side effects**: initializes `columns`, `rows`

### `ResultSet.add_row(row)` — `redash/query_runner/jql.py:14`
- **Returns**: None
- **Params**: `row: dict`
- **Calls**: `self.add_column()`
- **Side effects**: appends to `rows`

### `ResultSet.add_column(column, column_type=TYPE_STRING)` — `redash/query_runner/jql.py:20`
- **Returns**: None
- **Params**: `column: str`, `column_type: str`
- **Calls**: none
- **Side effects**: mutates `columns`

### `ResultSet.to_json()` — `redash/query_runner/jql.py:28`
- **Returns**: `{rows, columns}`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `ResultSet.merge(set)` — `redash/query_runner/jql.py:31`
- **Returns**: None
- **Params**: `set: ResultSet`
- **Calls**: none
- **Side effects**: concatenates `rows`

### `parse_issue(issue, field_mapping)` — `redash/query_runner/jql.py:35`
- **Returns**: OrderedDict row
- **Params**: `issue: dict`, `field_mapping: FieldMapping`
- **Calls**: `field_mapping.get_output_field_name()`, `field_mapping.get_dict_members()`, `field_mapping.get_dict_output_field_name()`
- **Side effects**: none

### `parse_issues(data, field_mapping)` — `redash/query_runner/jql.py:94`
- **Returns**: `ResultSet`
- **Params**: `data: dict`, `field_mapping: FieldMapping`
- **Calls**: `ResultSet.add_row()`, `parse_issue()`
- **Side effects**: none

### `parse_count(data)` — `redash/query_runner/jql.py:103`
- **Returns**: `ResultSet`
- **Params**: `data: dict`
- **Calls**: `ResultSet.add_row()`
- **Side effects**: none

### `FieldMapping.__init__(query_field_mapping)` — `redash/query_runner/jql.py:112`
- **Returns**: None
- **Params**: `query_field_mapping: dict`
- **Calls**: `re.search()`
- **Side effects**: populates `self.mapping`

### `FieldMapping.get_output_field_name(field_name)` — `redash/query_runner/jql.py:132`
- **Returns**: mapped output field name or original
- **Params**: `field_name: str`
- **Calls**: none
- **Side effects**: none

### `FieldMapping.get_dict_members(field_name)` — `redash/query_runner/jql.py:138`
- **Returns**: list of member names
- **Params**: `field_name: str`
- **Calls**: none
- **Side effects**: none

### `FieldMapping.get_dict_output_field_name(field_name, member_name)` — `redash/query_runner/jql.py:145`
- **Returns**: mapped output field name or `None`
- **Params**: `field_name: str`, `member_name: str`
- **Calls**: none
- **Side effects**: none

### `JiraJQL.name()` — `redash/query_runner/jql.py:160`
- **Returns**: `"JIRA (JQL)"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `JiraJQL.__init__(configuration)` — `redash/query_runner/jql.py:164`
- **Returns**: None
- **Params**: `configuration: dict`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `json`

### `JiraJQL.run_query(query, user)` — `redash/query_runner/jql.py:168`
- **Returns**: `(results_json, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `json_loads()`, `FieldMapping()`, `self.get_response()`, `parse_count()`, `parse_issues()`, `ResultSet.merge()`
- **Side effects**: HTTP requests (pagination loop)

### `ElasticSearch2.name()` — `redash/query_runner/elasticsearch2.py:40`
- **Returns**: `"Elasticsearch"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `ElasticSearch2.__init__(...)` — `redash/query_runner/elasticsearch2.py:44`
- **Returns**: None
- **Params**: `*args, **kwargs`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `json`

### `ElasticSearch2.get_response(url, auth=None, http_method="get", **kwargs)` — `redash/query_runner/elasticsearch2.py:48`
- **Returns**: `(response, error)`
- **Params**: `url: str`, `auth: tuple|None`, `http_method: str`, `kwargs: dict`
- **Calls**: `super().get_response()`
- **Side effects**: HTTP request; prepends base URL; sets `Accept: application/json`

### `ElasticSearch2.test_connection()` — `redash/query_runner/elasticsearch2.py:54`
- **Returns**: None
- **Params**: none
- **Calls**: `self.get_response()`
- **Side effects**: HTTP request; raises `Exception(error)` on error

### `ElasticSearch2.run_query(query, user)` — `redash/query_runner/elasticsearch2.py:59`
- **Returns**: `(data, None)`
- **Params**: `query: str`, `user: object`
- **Calls**: `_build_query()`, `self.get_response()`, `response.json()`, `_parse_results()`
- **Side effects**: HTTP request

### `ElasticSearch2._build_query(query)` — `redash/query_runner/elasticsearch2.py:67`
- **Returns**: `(query_dict, url, result_fields)`
- **Params**: `query: str`
- **Calls**: `json.loads()`
- **Side effects**: none

### `ElasticSearch2._parse_mappings(mappings_data)` — `redash/query_runner/elasticsearch2.py:75`
- **Returns**: mappings dict
- **Params**: `mappings_data: dict`
- **Calls**: none
- **Side effects**: none

### `ElasticSearch2.get_mappings()` — `redash/query_runner/elasticsearch2.py:102`
- **Returns**: mappings dict
- **Params**: none
- **Calls**: `self.get_response()`, `response.json()`, `_parse_mappings()`
- **Side effects**: HTTP request

### `ElasticSearch2.get_schema(*args, **kwargs)` — `redash/query_runner/elasticsearch2.py:106`
- **Returns**: list of schema dicts
- **Params**: none
- **Calls**: `get_mappings()`
- **Side effects**: none

### `ElasticSearch2._parse_results(result_fields, raw_result)` — `redash/query_runner/elasticsearch2.py:113`
- **Returns**: `{columns, rows}`
- **Params**: `result_fields: list|None`, `raw_result: dict`
- **Calls**: internal helpers
- **Side effects**: raises `Exception` on error conditions

### `OpenDistroSQLElasticSearch.__init__(...)` — `redash/query_runner/elasticsearch2.py:242`
- **Returns**: None
- **Params**: `*args, **kwargs`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `sql`

### `OpenDistroSQLElasticSearch._build_query(query)` — `redash/query_runner/elasticsearch2.py:246`
- **Returns**: `(sql_query, sql_query_url, None)`
- **Params**: `query: str`
- **Calls**: none
- **Side effects**: none

### `OpenDistroSQLElasticSearch.name()` — `redash/query_runner/elasticsearch2.py:252`
- **Returns**: `"Open Distro SQL Elasticsearch"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `OpenDistroSQLElasticSearch.type()` — `redash/query_runner/elasticsearch2.py:256`
- **Returns**: `"elasticsearch2_OpenDistroSQLElasticSearch"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `XPackSQLElasticSearch.__init__(...)` — `redash/query_runner/elasticsearch2.py:261`
- **Returns**: None
- **Params**: `*args, **kwargs`
- **Calls**: `super().__init__()`
- **Side effects**: sets `syntax` to `sql`

### `XPackSQLElasticSearch._build_query(query)` — `redash/query_runner/elasticsearch2.py:265`
- **Returns**: `(sql_query, sql_query_url, None)`
- **Params**: `query: str`
- **Calls**: none
- **Side effects**: none

### `XPackSQLElasticSearch._parse_results(result_fields, raw_result)` — `redash/query_runner/elasticsearch2.py:271`
- **Returns**: `{columns, rows}`
- **Params**: `result_fields: list|None`, `raw_result: dict`
- **Calls**: none
- **Side effects**: raises `Exception(error)` if error in response

### `XPackSQLElasticSearch.name()` — `redash/query_runner/elasticsearch2.py:298`
- **Returns**: `"X-Pack SQL Elasticsearch"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `XPackSQLElasticSearch.type()` — `redash/query_runner/elasticsearch2.py:302`
- **Returns**: `"elasticsearch2_XPackSQLElasticSearch"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `convert_type(string_value, actual_type)` — `redash/query_runner/drill.py:21`
- **Returns**: converted value
- **Params**: `string_value: str|None`, `actual_type: str`
- **Calls**: `int()`, `float()`, `parser.parse()`
- **Side effects**: none

### `parse_response(data)` — `redash/query_runner/drill.py:41`
- **Returns**: `{columns, rows}`
- **Params**: `data: dict`
- **Calls**: `guess_type()`, `convert_type()`
- **Side effects**: mutates row values in-place

### `Drill.name()` — `redash/query_runner/drill.py:74`
- **Returns**: `"Apache Drill"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Drill.configuration_schema()` — `redash/query_runner/drill.py:79`
- **Returns**: schema dict including `allowed_schemas`
- **Params**: none
- **Calls**: `super().configuration_schema()`
- **Side effects**: mutates schema

### `Drill.run_query(query, user)` — `redash/query_runner/drill.py:91`
- **Returns**: `(parsed_response, None)` or `(None, error)`
- **Params**: `query: str`, `user: object`
- **Calls**: `os.path.join()`, `self.get_response()`, `response.json()`, `parse_response()`
- **Side effects**: HTTP request

### `Drill.get_schema(get_stats=False)` — `redash/query_runner/drill.py:102`
- **Returns**: list of schema dicts
- **Params**: `get_stats: bool`
- **Calls**: `self.run_query()`, `_handle_run_query_error()`
- **Side effects**: none

### `ConfiguredSession.request(*args, **kwargs)` — `redash/utils/requests_session.py:20`
- **Returns**: `requests_or_advocate.Session.request()` result
- **Params**: `*args, **kwargs`
- **Calls**: `super().request()`
- **Side effects**: sets `allow_redirects=False` when `settings.REQUESTS_ALLOW_REDIRECTS` is false

---

## Defensive Patterns

| Location | Pattern | Trigger condition | Exact behavior when triggered |
|----------|---------|-------------------|-------------------------------|
| `redash/query_runner/__init__.py:205` | null check | `noop_query is None` | raises `NotImplementedError()` |
| `redash/query_runner/__init__.py:209` | error check | `error is not None` | raises `Exception(error)` |
| `redash/query_runner/__init__.py:234` | null check | `error is None` | returns without action |
| `redash/query_runner/__init__.py:238` | error handling | `error is not None` | logs error and raises `Exception("Error during query execution. Reason: {error}")` |
| `redash/query_runner/__init__.py:244` | error check | `error is not None` | raises `Exception("Failed running query [<query>].")` |
| `redash/query_runner/__init__.py:292` | length check | `len(parsed_query_list) == 0` | returns `False` |
| `redash/query_runner/__init__.py:297` | validation | `last_keyword_idx == -1` or first token not `SELECT` | returns `False` |
| `redash/query_runner/__init__.py:371` | required fields check | `requires_authentication` and missing user/pass | raises `ValueError("Username and Password required")` |
| `redash/query_runner/__init__.py:385` | try/except | request errors | logs exception and sets `error` message; returns `(response, error)` |
| `redash/query_runner/__init__.py:392` | status check | `response.status_code != 200` | sets `error = "{response_error} (<status>)."` |
| `redash/query_runner/__init__.py:395` | HTTPError handler | `requests_or_advocate.HTTPError` | logs exception; sets `error = "Failed to execute query. "` (response code/text formatting line follows on next line) |
| `redash/query_runner/__init__.py:399` | UnacceptableAddress handler | `UnacceptableAddressException` | logs exception; sets `error = "Can't query private addresses."` |
| `redash/query_runner/__init__.py:402` | RequestException handler | other requests exceptions | logs exception; sets `error = str(exc)` |
| `redash/query_runner/__init__.py:497` | NotImplemented check | `query_runner.host`/`port` not implemented | raises `NotImplementedError("SSH tunneling is not implemented for this query runner yet.")` |
| `redash/query_runner/__init__.py:509` | try/except | SSH tunnel setup failure | raises same error type with prefix `"SSH tunnel: <error>"` |
| `redash/query_runner/url.py:17` | input restriction | `base_url` set and `query` contains `"://"` | returns `(None, "Accepting only relative URLs to '<base_url>'")` |
| `redash/query_runner/url.py:32` | empty response check | `json_data` falsy | returns `(None, "Got empty response from '<url>'.")` |
| `redash/query_runner/json_ds.py:26` | empty query check | `query == ""` | raises `QueryParseError("Query is empty.")` |
| `redash/query_runner/json_ds.py:28` | try/except | YAML parse error | logs exception; raises `QueryParseError(error)` |
| `redash/query_runner/json_ds.py:74` | fallback value | missing path and `default` provided | returns `default` |
| `redash/query_runner/json_ds.py:77` | missing path check | missing path and no `default` | raises `Exception("Couldn't find path <path> in response.")` |
| `redash/query_runner/json_ds.py:169` | type check | `query` not dict | raises `QueryParseError("Query should be a YAML object describing the URL to query.")` |
| `redash/query_runner/json_ds.py:172` | missing field check | `url` not in query | raises `QueryParseError("Query must include 'url' option.")` |
| `redash/query_runner/json_ds.py:186` | type coercion | `request_options['auth']` is list | converts list to tuple |
| `redash/query_runner/json_ds.py:191` | method restriction | method not in `("get", "post")` | raises `QueryParseError("Only GET or POST methods are allowed.")` |
| `redash/query_runner/json_ds.py:194` | type check | `fields` not list | raises `QueryParseError("'fields' needs to be a list.")` |
| `redash/query_runner/json_ds.py:236` | config validation | `pagination` not dict or missing `type` | raises `QueryParseError("'pagination' should be an object with a `type` property")` |
| `redash/query_runner/json_ds.py:244` | config validation | unknown pagination type | raises `QueryParseError("Unknown 'pagination.type' <type>")` |
| `redash/query_runner/json_ds.py:250` | config validation | `pagination.path` not string | raises `QueryParseError("'pagination.path' should be a string")` |
| `redash/query_runner/json_ds.py:255` | pagination stop | `next_url` falsy | returns `(False, None, request_options)` |
| `redash/query_runner/json_ds.py:265` | config validation | `fields` not list of length 2 | raises `QueryParseError("'pagination.fields' should be a list of 2 field names")` |
| `redash/query_runner/json_ds.py:270` | pagination stop | `next_token` falsy | returns `(False, None, request_options)` |
| `redash/query_runner/json_ds.py:276` | infinite loop guard | `next_token == params.get(self.fields[1])` | raises `Exception("<field0> did not change; possible misconfiguration")` |
| `redash/query_runner/csv.py:52` | try/except | YAML parsing for URL/UA | on exception, leaves defaults `path=""`, `ua=""`, `args={}` |
| `redash/query_runner/csv.py:99` | KeyboardInterrupt handler | user cancel | returns `(None, "Query cancelled by user.")` |
| `redash/query_runner/csv.py:102` | UnacceptableAddress handler | private address blocked | returns `(None, "Can't query private addresses.")` |
| `redash/query_runner/csv.py:105` | generic error handler | any other exception | returns `(None, "Error reading <path>. <exception>")` |
| `redash/query_runner/excel.py:49` | try/except | YAML parsing for URL/UA | on exception, leaves defaults `path=""`, `ua=""`, `args={}` |
| `redash/query_runner/excel.py:97` | KeyboardInterrupt handler | user cancel | returns `(None, "Query cancelled by user.")` |
| `redash/query_runner/excel.py:100` | UnacceptableAddress handler | private address blocked | returns `(None, "Can't query private addresses.")` |
| `redash/query_runner/excel.py:103` | generic error handler | any other exception | returns `(None, "Error reading <path>. <exception>")` |
| `redash/query_runner/jql.py:39` | fallback value | missing `key` field | uses `issue.get("id", "unknown")` |
| `redash/query_runner/jql.py:42` | fallback value | missing `fields` in issue | uses empty dict `{}` |
| `redash/query_runner/jql.py:106` | fallback value | missing `total` | uses `len(data.get("issues", []))` |
| `redash/query_runner/jql.py:177` | required field enforcement | missing/empty `jql` | sets default `"created >= -30d order by created DESC"` |
| `redash/query_runner/jql.py:200` | pagination loop guard | `data.get("isLast", True)` | stops loop when `isLast` true or no `nextPageToken` |
| `redash/query_runner/elasticsearch2.py:95` | try/except | missing mapping keys | falls back to `index_mappings["mappings"]["properties"]` |
| `redash/query_runner/elasticsearch2.py:209` | error response check | `"error" in raw_result` | raises `Exception(error)` (truncates to 10240 chars) |
| `redash/query_runner/elasticsearch2.py:235` | fallback error | unexpected structure | raises `Exception("Redash failed to parse the results it got from Elasticsearch.")` |
| `redash/query_runner/elasticsearch2.py:272` | error response check | `raw_result.get("error")` | raises `Exception(error)` |
| `redash/query_runner/drill.py:22` | empty check | `string_value is None or ""` | returns empty string `""` |
| `redash/query_runner/drill.py:45` | empty columns check | `len(cols) == 0` | returns `{"columns": [], "rows": []}` |
| `redash/query_runner/drill.py:118` | input sanitization | `allowed_schemas` present | strips non `[a-zA-Z0-9_.`]` chars before building SQL |
| `redash/utils/requests_session.py:21` | redirect control | `settings.REQUESTS_ALLOW_REDIRECTS` is false | sets `allow_redirects=False` on request |

---

## External Calls

| Location | Target | Input | Parameterized? | Error handling |
|----------|--------|-------|:-:|---|
| `redash/query_runner/__init__.py:385` | HTTP request (`requests_session.request`) | `http_method`, `url`, `auth`, `kwargs` | Yes | catches `HTTPError`, `UnacceptableAddressException`, `RequestException`; returns `(response, error)` |
| `redash/query_runner/__init__.py:508` | SSH tunnel (`open_tunnel`) | bastion/remote addresses, auth | Yes | wraps exceptions and raises with `"SSH tunnel: ..."` |
| `redash/query_runner/url.py:26` | HTTP request (`BaseHTTPQueryRunner.get_response`) | `url` from config + query | Yes | returns error string on exceptions or non-200 |
| `redash/query_runner/json_ds.py:203` | URL construction (`urljoin`) | `base_url`, `url` | Yes | none |
| `redash/query_runner/json_ds.py:208` | HTTP request (`BaseHTTPQueryRunner.get_response`) | `url`, `method`, request options | Yes | returns `(response, error)`; `response.json()` used when no error |
| `redash/query_runner/csv.py:62` | HTTP request (`requests_or_advocate.get`) | `path`, `User-agent` header | Yes | catches `UnacceptableAddressException` and generic exceptions |
| `redash/query_runner/csv.py:63` | CSV parsing (`pandas.read_csv`) | response content | N/A | exceptions caught in try/except |
| `redash/query_runner/excel.py:60` | HTTP request (`requests_or_advocate.get`) | `path`, `User-agent` header | Yes | catches `UnacceptableAddressException` and generic exceptions |
| `redash/query_runner/excel.py:61` | Excel parsing (`pandas.read_excel`) | response content | N/A | exceptions caught in try/except |
| `redash/query_runner/jql.py:189` | HTTP request (`BaseHTTPQueryRunner.get_response`) | Jira URL + `params=query` | Yes | returns `(None, error)` on failure |
| `redash/query_runner/jql.py:201` | HTTP request (pagination) | Jira URL + `params` with `nextPageToken` | Yes | stops and returns error on failure |
| `redash/query_runner/elasticsearch2.py:52` | HTTP request (`BaseHTTPQueryRunner.get_response`) | base URL + path | Yes | error handled by base `get_response` |
| `redash/query_runner/elasticsearch2.py:62` | JSON parsing (`response.json()`) | HTTP response | N/A | errors not handled here |
| `redash/query_runner/elasticsearch2.py:103` | HTTP request (`get_response` for mappings) | `/_mappings` | Yes | error not checked before `response.json()` |
| `redash/query_runner/drill.py:96` | HTTP request (`BaseHTTPQueryRunner.get_response`) | `Drill URL + query.json`, JSON payload | Yes | returns `(None, error)` on failure |
| `redash/query_runner/drill.py:100` | JSON parsing (`response.json()`) | Drill response | N/A | errors not handled here |

---

## Trust Assumptions

| Location | Assumption | Evidence |
|----------|-----------|---------|
| `redash/query_runner/url.py:24` | Query string is a relative path when `base_url` configured | concatenates `base_url + query` after only checking `"://"` |
| `redash/query_runner/json_ds.py:175` | `method` in query is usable for HTTP | uses `method = query.get("method", "get")` then only allows `get/post` |
| `redash/query_runner/json_ds.py:176` | YAML `params/headers/data/auth/json/verify` are trusted and passed to requests | `request_options = project(...)` and forwarded to `get_response` |
| `redash/query_runner/json_ds.py:203` | `base_url` from configuration is valid | `url = urljoin(base_url, url)` without validation |
| `redash/query_runner/csv.py:55` | YAML contains `url` and `user-agent` fields | `path = args["url"]`, `ua = args["user-agent"]` inside try block |
| `redash/query_runner/excel.py:51` | YAML contains `url` and `user-agent` fields | `path = args["url"]`, `ua = args["user-agent"]` inside try block |
| `redash/query_runner/jql.py:170` | `configuration["url"]` is valid Jira base URL | uses `.rstrip("/")` and concatenates fixed path |
| `redash/query_runner/elasticsearch2.py:49` | `configuration["url"]` is valid base URL | prepends to requested path |
| `redash/query_runner/elasticsearch2.py:68` | Query JSON contains expected `index` and optional `result_fields` | `index_name = query.pop("index", "")` without validation |
| `redash/query_runner/drill.py:92` | `configuration["url"]` is a Drill base URL | `os.path.join` to build `query.json` endpoint |
| `redash/utils/requests_session.py:13` | Settings determine SSRF protection implementation | `requests_or_advocate` depends on `settings.ENFORCE_PRIVATE_ADDRESS_BLOCK` |

---

## Layer Transitions

| Direction | From | To | Data passed | Validation before handoff? |
|-----------|------|----|------------|:---:|
| Inbound | Query runner framework | `Url.run_query` | raw query string | Partial (checks for scheme only when base_url set) |
| Inbound | Query runner framework | `JSON.run_query` | raw YAML query | Partial (YAML parsed; requires `url`, method/fields validations) |
| Inbound | Query runner framework | `CSV.run_query` | raw YAML query | Partial (best-effort parse; exceptions ignored) |
| Inbound | Query runner framework | `Excel.run_query` | raw YAML query | Partial (best-effort parse; exceptions ignored) |
| Inbound | Query runner framework | `JiraJQL.run_query` | raw JSON query | Partial (ensures `jql` default, restricts fields) |
| Inbound | Query runner framework | `ElasticSearch2.run_query` | raw JSON query | Partial (JSON parsing only) |
| Inbound | Query runner framework | `Drill.run_query` | raw SQL query | No validation |
| Outbound | `BaseHTTPQueryRunner.get_response` | HTTP client (`requests_session`) | `url`, `auth`, `kwargs` | Partial (SSRF blocking if enabled, redirect setting) |
| Outbound | `JSON._get_all_results` | HTTP endpoint | `url`, `method`, request options | Partial (method allowlist `get/post`) |
| Outbound | `CSV.run_query` | HTTP endpoint | `path`, `User-agent` | No validation on URL in code path |
| Outbound | `Excel.run_query` | HTTP endpoint | `path`, `User-agent` | No validation on URL in code path |
| Outbound | `JiraJQL.run_query` | Jira API | `params` dict from query | Partial (defaults for missing fields) |
| Outbound | `ElasticSearch2.run_query` | Elasticsearch API | JSON body from query | No validation on query fields |
| Outbound | `Drill.run_query` | Drill API | JSON payload `{queryType, query}` | No validation |
