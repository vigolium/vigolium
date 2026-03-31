# Code Anatomy: Webhooks and Destinations

Generated: 2026-03-30T00:00:00Z
Files read: 17

---

## Functions

### `BaseDestination.__init__(configuration)` — `redash/destinations/__init__.py:11`
- **Returns**: None
- **Params**: configuration: unknown — assigned to `self.configuration`
- **Calls**: none
- **Side effects**: state mutation (`self.configuration`)

### `BaseDestination.name()` — `redash/destinations/__init__.py:15`
- **Returns**: class name string
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseDestination.type()` — `redash/destinations/__init__.py:19`
- **Returns**: lowercase class name string
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseDestination.icon()` — `redash/destinations/__init__.py:23`
- **Returns**: `"fa-bullseye"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseDestination.enabled()` — `redash/destinations/__init__.py:27`
- **Returns**: `True`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseDestination.configuration_schema()` — `redash/destinations/__init__.py:31`
- **Returns**: `{}`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `BaseDestination.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/__init__.py:34`
- **Returns**: raises `NotImplementedError`
- **Params**: alert: unknown; query: unknown; user: unknown; new_state: unknown; app: unknown; host: unknown; metadata: unknown; options: unknown
- **Calls**: none
- **Side effects**: raises exception

### `BaseDestination.to_dict()` — `redash/destinations/__init__.py:38`
- **Returns**: dict with name/type/icon/configuration_schema and optional deprecated flag
- **Params**: none
- **Calls**: `BaseDestination.name()` (`redash/destinations/__init__.py:15`), `BaseDestination.type()` (`redash/destinations/__init__.py:19`), `BaseDestination.icon()` (`redash/destinations/__init__.py:23`), `BaseDestination.configuration_schema()` (`redash/destinations/__init__.py:31`)
- **Side effects**: none

### `register(destination_class)` — `redash/destinations/__init__.py:51`
- **Returns**: None
- **Params**: destination_class: class
- **Calls**: `destination_class.enabled()`; `destination_class.name()`; `destination_class.type()`
- **Side effects**: mutates module-level `destinations` dict; logging

### `get_destination(destination_type, configuration)` — `redash/destinations/__init__.py:67`
- **Returns**: destination instance or `None`
- **Params**: destination_type: string; configuration: unknown
- **Calls**: destination class constructor
- **Side effects**: none

### `get_configuration_schema_for_destination_type(destination_type)` — `redash/destinations/__init__.py:74`
- **Returns**: schema dict or `None`
- **Params**: destination_type: string
- **Calls**: `destination_class.configuration_schema()`
- **Side effects**: none

### `import_destinations(destination_imports)` — `redash/destinations/__init__.py:82`
- **Returns**: None
- **Params**: destination_imports: iterable
- **Calls**: `__import__(destination_import)`
- **Side effects**: module imports

### `Webhook.configuration_schema()` — `redash/destinations/webhook.py:12`
- **Returns**: schema dict with url/username/password
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Webhook.icon()` — `redash/destinations/webhook.py:25`
- **Returns**: `"fa-bolt"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Webhook.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/webhook.py:29`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `serialize_alert` (`redash/serializers`); `json_dumps` (`redash/utils`); `requests.post`
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `Slack.configuration_schema()` — `redash/destinations/slack.py:10`
- **Returns**: schema dict with url
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Slack.icon()` — `redash/destinations/slack.py:20`
- **Returns**: `"fa-slack"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Slack.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/slack.py:24`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `json_dumps` (`redash/utils`); `requests.post`
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `Discord.configuration_schema()` — `redash/destinations/discord.py:18`
- **Returns**: schema dict with url
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Discord.icon()` — `redash/destinations/discord.py:27`
- **Returns**: `"fa-discord"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Discord.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/discord.py:31`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `requests.post`; `json_dumps` (`redash/utils`)
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `Mattermost.configuration_schema()` — `redash/destinations/mattermost.py:10`
- **Returns**: schema dict with url/username/icon_url/channel
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Mattermost.icon()` — `redash/destinations/mattermost.py:23`
- **Returns**: `"fa-bolt"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Mattermost.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/mattermost.py:27`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `json_dumps` (`redash/utils`); `requests.post`
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `HangoutsChat.name()` — `redash/destinations/hangoutschat.py:10`
- **Returns**: `"Google Hangouts Chat"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `HangoutsChat.type()` — `redash/destinations/hangoutschat.py:14`
- **Returns**: `"hangouts_chat"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `HangoutsChat.configuration_schema()` — `redash/destinations/hangoutschat.py:19`
- **Returns**: schema dict with url/icon_url
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `HangoutsChat.icon()` — `redash/destinations/hangoutschat.py:36`
- **Returns**: `"fa-bolt"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `HangoutsChat.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/hangoutschat.py:40`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `json_dumps` (`redash/utils`); `requests.post`
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `json_string_substitute(j, substitutions)` — `redash/destinations/microsoft_teams_webhook.py:10`
- **Returns**: substituted string or original `j`
- **Params**: j: string; substitutions: dict or None
- **Calls**: `Template.safe_substitute`
- **Side effects**: none

### `MicrosoftTeamsWebhook.name()` — `redash/destinations/microsoft_teams_webhook.py:51`
- **Returns**: `"Microsoft Teams Webhook"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `MicrosoftTeamsWebhook.type()` — `redash/destinations/microsoft_teams_webhook.py:55`
- **Returns**: `"microsoft_teams_webhook"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `MicrosoftTeamsWebhook.configuration_schema()` — `redash/destinations/microsoft_teams_webhook.py:59`
- **Returns**: schema dict with url/message_template
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `MicrosoftTeamsWebhook.icon()` — `redash/destinations/microsoft_teams_webhook.py:73`
- **Returns**: `"fa-bolt"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `MicrosoftTeamsWebhook.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/microsoft_teams_webhook.py:77`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `json_string_substitute` (`redash/destinations/microsoft_teams_webhook.py:10`); `requests.post`
- **Side effects**: HTTP POST to `options.get("url")`; logging

### `ChatWork.configuration_schema()` — `redash/destinations/chatwork.py:11`
- **Returns**: schema dict with api_token/room_id/message_template
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `ChatWork.icon()` — `redash/destinations/chatwork.py:28`
- **Returns**: `"fa-comment"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `ChatWork.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/chatwork.py:32`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `requests.post`
- **Side effects**: HTTP POST to ChatWork API; logging

### `Webex.configuration_schema()` — `redash/destinations/webex.py:13`
- **Returns**: schema dict with webex_bot_token/to_person_emails/to_room_ids
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Webex.icon()` — `redash/destinations/webex.py:32`
- **Returns**: `"fa-webex"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Webex.api_base_url` — `redash/destinations/webex.py:36`
- **Returns**: `"https://webexapis.com/v1/messages"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Webex.formatted_attachments_template(subject, description, query_link, alert_link)` — `redash/destinations/webex.py:41`
- **Returns**: list with adaptive card payloads
- **Params**: subject: string; description: string; query_link: string; alert_link: string
- **Calls**: `html.unescape`; `json.loads`
- **Side effects**: none

### `Webex.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/webex.py:177`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `Webex.formatted_attachments_template` (`redash/destinations/webex.py:41`); `Webex.post_message` (`redash/destinations/webex.py:215`)
- **Side effects**: HTTP POST via `post_message` for each destination ID

### `Webex.post_message(payload, headers)` — `redash/destinations/webex.py:215`
- **Returns**: None
- **Params**: payload: dict; headers: dict
- **Calls**: `requests.post`
- **Side effects**: HTTP POST to Webex API; logging

### `Datadog.configuration_schema()` — `redash/destinations/datadog.py:11`
- **Returns**: schema dict with api_key/tags/priority/source_type_name
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Datadog.icon()` — `redash/destinations/datadog.py:26`
- **Returns**: `"fa-datadog"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Datadog.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/datadog.py:30`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `json_dumps` (`redash/utils`); `requests.post`; `os.getenv`
- **Side effects**: HTTP POST to Datadog API; logging

### `Asana.configuration_schema()` — `redash/destinations/asana.py:11`
- **Returns**: schema dict with pat/project_id
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Asana.icon()` — `redash/destinations/asana.py:23`
- **Returns**: `"fa-asana"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Asana.api_base_url` — `redash/destinations/asana.py:27`
- **Returns**: `"https://app.asana.com/api/1.0/tasks"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Asana.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/asana.py:31`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `requests.post`; `textwrap.dedent`
- **Side effects**: HTTP POST to Asana API; logging

### `Email.configuration_schema()` — `redash/destinations/email.py:10`
- **Returns**: schema dict with addresses/subject_template
- **Params**: none
- **Calls**: `settings.ALERTS_DEFAULT_MAIL_SUBJECT_TEMPLATE`
- **Side effects**: none

### `Email.icon()` — `redash/destinations/email.py:26`
- **Returns**: `"fa-envelope"`
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Email.notify(alert, query, user, new_state, app, host, metadata, options)` — `redash/destinations/email.py:30`
- **Returns**: None
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict; options: ConfigurationContainer
- **Calls**: `open` (template file); `alert.render_template` (`redash/models/__init__.py:1054`); `Message` (flask_mail); `mail.send`
- **Side effects**: file read; email send; logging

### `notify_subscriptions(alert, new_state, metadata)` — `redash/tasks/alerts.py:11`
- **Returns**: None
- **Params**: alert: Alert; new_state: string; metadata: dict
- **Calls**: `utils.base_url`; `subscription.notify` (`redash/models/__init__.py:1477`)
- **Side effects**: outbound notifications; logging

### `should_notify(alert, new_state)` — `redash/tasks/alerts.py:20`
- **Returns**: bool
- **Params**: alert: Alert; new_state: string
- **Calls**: `utils.utcnow`
- **Side effects**: none

### `check_alerts_for_query(query_id, metadata)` — `redash/tasks/alerts.py:28`
- **Returns**: None
- **Params**: query_id: int; metadata: dict
- **Calls**: `models.Query.query.get`; `alert.evaluate` (`redash/models/__init__.py:1015`); `should_notify` (`redash/tasks/alerts.py:20`); `models.db.session.commit`; `notify_subscriptions` (`redash/tasks/alerts.py:11`)
- **Side effects**: DB updates; outbound notifications; logging

### `record_event(raw_event)` — `redash/tasks/general.py:14`
- **Returns**: None
- **Params**: raw_event: dict
- **Calls**: `models.Event.record` (`redash/models/__init__.py:1333`); `models.db.session.commit`; `requests.post`
- **Side effects**: DB insert; outbound HTTP to hooks; logging

### `version_check()` — `redash/tasks/general.py:33`
- **Returns**: None
- **Params**: none
- **Calls**: `run_version_check`
- **Side effects**: none

### `subscribe(form)` — `redash/tasks/general.py:37`
- **Returns**: None
- **Params**: form: dict
- **Calls**: `requests.post`
- **Side effects**: HTTP POST to version.redash.io

### `send_mail(to, subject, html, text)` — `redash/tasks/general.py:55`
- **Returns**: None
- **Params**: to: list; subject: string; html: string; text: string
- **Calls**: `Message` (flask_mail); `mail.send`
- **Side effects**: email send; logging

### `test_connection(data_source_id)` — `redash/tasks/general.py:64`
- **Returns**: `True` on success; exception object on failure
- **Params**: data_source_id: int
- **Calls**: `models.DataSource.get_by_id`; `data_source.query_runner.test_connection`
- **Side effects**: none

### `get_schema(data_source_id, refresh)` — `redash/tasks/general.py:75`
- **Returns**: schema dict on success; error dict on failure
- **Params**: data_source_id: int; refresh: bool
- **Calls**: `models.DataSource.get_by_id`; `data_source.get_schema`
- **Side effects**: none

### `sync_user_details()` — `redash/tasks/general.py:91`
- **Returns**: None
- **Params**: none
- **Calls**: `users.sync_last_active_at`
- **Side effects**: DB updates (via users module)

### `DestinationTypeListResource.get()` — `redash/handlers/destinations.py:16`
- **Returns**: list of destination dicts
- **Params**: none
- **Calls**: `destinations.values()`; `destination.to_dict()` (`redash/destinations/__init__.py:38`)
- **Side effects**: none

### `DestinationResource.get(destination_id)` — `redash/handlers/destinations.py:22`
- **Returns**: destination dict (with secrets masked)
- **Params**: destination_id: int
- **Calls**: `models.NotificationDestination.get_by_id_and_org`; `destination.to_dict(all=True)` (`redash/models/__init__.py:1412`); `self.record_event` (`redash/handlers/base.py:41`)
- **Side effects**: event recording (async task)

### `DestinationResource.post(destination_id)` — `redash/handlers/destinations.py:35`
- **Returns**: destination dict (with secrets masked)
- **Params**: destination_id: int
- **Calls**: `request.get_json`; `get_configuration_schema_for_destination_type` (`redash/destinations/__init__.py:74`); `destination.options.set_schema`; `destination.options.update`; `models.db.session.commit`
- **Side effects**: DB update; event recording on success is not present

### `DestinationResource.delete(destination_id)` — `redash/handlers/destinations.py:63`
- **Returns**: empty response (204)
- **Params**: destination_id: int
- **Calls**: `models.NotificationDestination.get_by_id_and_org`; `models.db.session.delete`; `models.db.session.commit`; `self.record_event` (`redash/handlers/base.py:41`)
- **Side effects**: DB delete; event recording

### `DestinationListResource.get()` — `redash/handlers/destinations.py:80`
- **Returns**: list of destination dicts
- **Params**: none
- **Calls**: `models.NotificationDestination.all`; `ds.to_dict()` (`redash/models/__init__.py:1412`); `self.record_event` (`redash/handlers/base.py:41`)
- **Side effects**: event recording

### `DestinationListResource.post()` — `redash/handlers/destinations.py:102`
- **Returns**: destination dict (with secrets masked)
- **Params**: none
- **Calls**: `request.get_json`; `require_fields` (`redash/handlers/base.py:64`); `get_configuration_schema_for_destination_type` (`redash/destinations/__init__.py:74`); `ConfigurationContainer`; `config.is_valid`; `models.db.session.add/commit`
- **Side effects**: DB insert

### `AlertResource.get(alert_id)` — `redash/handlers/alerts.py:24`
- **Returns**: serialized alert dict
- **Params**: alert_id: int
- **Calls**: `get_object_or_404` (`redash/handlers/base.py:70`); `require_access`; `self.record_event` (`redash/handlers/base.py:41`); `serialize_alert`
- **Side effects**: event recording

### `AlertResource.post(alert_id)` — `redash/handlers/alerts.py:30`
- **Returns**: serialized alert dict
- **Params**: alert_id: int
- **Calls**: `request.get_json`; `project`; `get_object_or_404` (`redash/handlers/base.py:70`); `require_admin_or_owner`; `self.update_model` (`redash/handlers/base.py:45`); `models.db.session.commit`; `self.record_event`
- **Side effects**: DB update; event recording

### `AlertResource.delete(alert_id)` — `redash/handlers/alerts.py:43`
- **Returns**: None (implicit)
- **Params**: alert_id: int
- **Calls**: `get_object_or_404` (`redash/handlers/base.py:70`); `require_admin_or_owner`; `models.db.session.delete`; `models.db.session.commit`
- **Side effects**: DB delete

### `AlertEvaluateResource.post(alert_id)` — `redash/handlers/alerts.py:51`
- **Returns**: None (implicit)
- **Params**: alert_id: int
- **Calls**: `get_object_or_404` (`redash/handlers/base.py:70`); `require_admin_or_owner`; `alert.evaluate` (`redash/models/__init__.py:1015`); `should_notify` (`redash/tasks/alerts.py:20`); `models.db.session.commit`; `notify_subscriptions` (`redash/tasks/alerts.py:11`); `self.record_event`
- **Side effects**: DB update; outbound notifications; event recording

### `AlertMuteResource.post(alert_id)` — `redash/handlers/alerts.py:66`
- **Returns**: None (implicit)
- **Params**: alert_id: int
- **Calls**: `get_object_or_404` (`redash/handlers/base.py:70`); `require_admin_or_owner`; `models.db.session.commit`; `self.record_event`
- **Side effects**: DB update; event recording

### `AlertMuteResource.delete(alert_id)` — `redash/handlers/alerts.py:75`
- **Returns**: None (implicit)
- **Params**: alert_id: int
- **Calls**: `get_object_or_404` (`redash/handlers/base.py:70`); `require_admin_or_owner`; `models.db.session.commit`; `self.record_event`
- **Side effects**: DB update; event recording

### `AlertListResource.post()` — `redash/handlers/alerts.py:85`
- **Returns**: serialized alert dict
- **Params**: none
- **Calls**: `request.get_json`; `require_fields` (`redash/handlers/base.py:64`); `models.Query.get_by_id_and_org`; `require_access`; `models.db.session.add/flush/commit`; `self.record_event` (`redash/handlers/base.py:41`)
- **Side effects**: DB insert; event recording

### `AlertListResource.get()` — `redash/handlers/alerts.py:109`
- **Returns**: list of serialized alerts
- **Params**: none
- **Calls**: `self.record_event` (`redash/handlers/base.py:41`); `models.Alert.all`; `serialize_alert`
- **Side effects**: event recording

### `AlertSubscriptionListResource.post(alert_id)` — `redash/handlers/alerts.py:116`
- **Returns**: subscription dict
- **Params**: alert_id: int
- **Calls**: `request.get_json`; `models.Alert.get_by_id_and_org`; `require_access`; `models.NotificationDestination.get_by_id_and_org`; `models.db.session.add/commit`; `self.record_event`
- **Side effects**: DB insert; event recording

### `AlertSubscriptionListResource.get(alert_id)` — `redash/handlers/alerts.py:143`
- **Returns**: list of subscription dicts
- **Params**: alert_id: int
- **Calls**: `models.Alert.get_by_id_and_org`; `require_access`; `models.AlertSubscription.all`; `s.to_dict()` (`redash/models/__init__.py:1465`)
- **Side effects**: none

### `AlertSubscriptionResource.delete(alert_id, subscriber_id)` — `redash/handlers/alerts.py:152`
- **Returns**: None (implicit)
- **Params**: alert_id: int; subscriber_id: int
- **Calls**: `models.AlertSubscription.query.get_or_404`; `require_admin_or_owner`; `models.db.session.delete/commit`; `self.record_event`
- **Side effects**: DB delete; event recording

### `get_location(ip)` — `redash/handlers/events.py:10`
- **Returns**: country name string or `"Unknown"`
- **Params**: ip: string or None
- **Calls**: `maxminddb.open_database`; `reader.get`
- **Side effects**: file access to GeoLite DB

### `event_details(event)` — `redash/handlers/events.py:22`
- **Returns**: details dict
- **Params**: event: Event
- **Calls**: none
- **Side effects**: none

### `serialize_event(event)` — `redash/handlers/events.py:36`
- **Returns**: event dict
- **Params**: event: Event
- **Calls**: `parse_ua`; `get_location` (`redash/handlers/events.py:10`); `event_details` (`redash/handlers/events.py:22`)
- **Side effects**: none

### `EventsResource.post()` — `redash/handlers/events.py:60`
- **Returns**: None (implicit)
- **Params**: none
- **Calls**: `request.get_json`; `self.record_event` (`redash/handlers/base.py:41`)
- **Side effects**: event recording (async task)

### `EventsResource.get()` — `redash/handlers/events.py:65`
- **Returns**: paginated events response
- **Params**: none
- **Calls**: `paginate` (`redash/handlers/base.py:80`)
- **Side effects**: none

### `BaseResource.__init__(*args, **kwargs)` — `redash/handlers/base.py:24`
- **Returns**: None
- **Params**: args: tuple; kwargs: dict
- **Calls**: `super().__init__`
- **Side effects**: sets `self._user = None`

### `BaseResource.dispatch_request(*args, **kwargs)` — `redash/handlers/base.py:28`
- **Returns**: result of parent dispatch
- **Params**: args: tuple; kwargs: dict
- **Calls**: `kwargs.pop("org_slug", None)`; `super().dispatch_request`
- **Side effects**: mutates kwargs

### `BaseResource.current_user` — `redash/handlers/base.py:33`
- **Returns**: current user object
- **Params**: none
- **Calls**: `current_user._get_current_object()`
- **Side effects**: none

### `BaseResource.current_org` — `redash/handlers/base.py:37`
- **Returns**: current org object
- **Params**: none
- **Calls**: `current_org._get_current_object()`
- **Side effects**: none

### `BaseResource.record_event(options)` — `redash/handlers/base.py:41`
- **Returns**: None
- **Params**: options: dict
- **Calls**: `record_event` (`redash/handlers/base.py:50`)
- **Side effects**: enqueues async event record

### `BaseResource.update_model(model, updates)` — `redash/handlers/base.py:45`
- **Returns**: None
- **Params**: model: object; updates: dict
- **Calls**: `setattr`
- **Side effects**: mutates model

### `record_event(org, user, options)` — `redash/handlers/base.py:50`
- **Returns**: None
- **Params**: org: Organization; user: User; options: dict
- **Calls**: `record_event_task.delay` (`redash/tasks/general.py:14` via import alias)
- **Side effects**: enqueues async job; mutates options dict

### `require_fields(req, fields)` — `redash/handlers/base.py:64`
- **Returns**: None
- **Params**: req: dict; fields: iterable
- **Calls**: `abort(400)`
- **Side effects**: raises HTTP 400 when missing fields

### `get_object_or_404(fn, *args, **kwargs)` — `redash/handlers/base.py:70`
- **Returns**: object or aborts
- **Params**: fn: callable; args: tuple; kwargs: dict
- **Calls**: `fn(*args, **kwargs)`; `abort(404)`
- **Side effects**: raises HTTP 404 on `None` or `NoResultFound`

### `paginate(query_set, page, page_size, serializer, **kwargs)` — `redash/handlers/base.py:80`
- **Returns**: dict with count/page/page_size/results
- **Params**: query_set: query; page: int; page_size: int; serializer: callable; kwargs: dict
- **Calls**: `query_set.count`; `abort(400)`; `query_set.paginate`; serializer (class or function)
- **Side effects**: none

### `org_scoped_rule(rule)` — `redash/handlers/base.py:103`
- **Returns**: rule string (prefixed with org slug if MULTI_ORG)
- **Params**: rule: string
- **Calls**: `settings.MULTI_ORG`
- **Side effects**: none

### `json_response(response)` — `redash/handlers/base.py:110`
- **Returns**: Flask response
- **Params**: response: object
- **Calls**: `json_dumps`
- **Side effects**: none

### `filter_by_tags(result_set, column)` — `redash/handlers/base.py:114`
- **Returns**: filtered result_set
- **Params**: result_set: query; column: column
- **Calls**: `request.args.getlist`; `result_set.filter`
- **Side effects**: none

### `order_results(results, default_order, allowed_orders, fallback=True)` — `redash/handlers/base.py:121`
- **Returns**: ordered results
- **Params**: results: query; default_order: object; allowed_orders: dict; fallback: bool
- **Calls**: `request.args.get`; `sort_query`
- **Side effects**: none

### `Event.__str__()` — `redash/models/__init__.py:1313`
- **Returns**: formatted string with user_id/action/object_type/object_id
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `Event.to_dict()` — `redash/models/__init__.py:1321`
- **Returns**: dict with event fields
- **Params**: none
- **Calls**: `self.created_at.isoformat()`
- **Side effects**: none

### `Event.record(event)` — `redash/models/__init__.py:1333`
- **Returns**: Event instance
- **Params**: event: dict
- **Calls**: `db.session.add`
- **Side effects**: DB insert (pending until commit)

### `NotificationDestination.__str__()` — `redash/models/__init__.py:1409`
- **Returns**: destination name string
- **Params**: none
- **Calls**: none
- **Side effects**: none

### `NotificationDestination.to_dict(all=False)` — `redash/models/__init__.py:1412`
- **Returns**: dict with id/name/type/icon and optional options
- **Params**: all: bool
- **Calls**: `self.destination.icon()`; `get_configuration_schema_for_destination_type` (`redash/destinations/__init__.py:74`); `self.options.set_schema`; `self.options.to_dict(mask_secrets=True)`
- **Side effects**: mutates `self.options` schema

### `NotificationDestination.destination` — `redash/models/__init__.py:1427`
- **Returns**: destination instance or `None`
- **Params**: none
- **Calls**: `get_destination` (`redash/destinations/__init__.py:67`)
- **Side effects**: none

### `NotificationDestination.all(org)` — `redash/models/__init__.py:1432`
- **Returns**: query of destinations for org
- **Params**: org: Organization
- **Calls**: `cls.query.filter` / `order_by`
- **Side effects**: none

### `NotificationDestination.notify(alert, query, user, new_state, app, host, metadata)` — `redash/models/__init__.py:1437`
- **Returns**: destination notify result (implicit None in implementations)
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict
- **Calls**: `get_configuration_schema_for_destination_type` (`redash/destinations/__init__.py:74`); `self.options.set_schema`; `self.destination.notify` (destination-specific)
- **Side effects**: outbound notification (HTTP/email/etc)

### `AlertSubscription.to_dict()` — `redash/models/__init__.py:1465`
- **Returns**: dict with id/user/alert_id and optional destination
- **Params**: none
- **Calls**: `self.user.to_dict()`; `self.destination.to_dict()`
- **Side effects**: none

### `AlertSubscription.all(alert_id)` — `redash/models/__init__.py:1473`
- **Returns**: query of subscriptions for alert
- **Params**: alert_id: int
- **Calls**: `AlertSubscription.query.join(User).filter`
- **Side effects**: none

### `AlertSubscription.notify(alert, query, user, new_state, app, host, metadata)` — `redash/models/__init__.py:1477`
- **Returns**: destination notify result (implicit None in implementations)
- **Params**: alert: Alert; query: Query; user: User; new_state: string; app: Redash app; host: string; metadata: dict
- **Calls**: `self.destination.notify` (if destination present); `ConfigurationContainer` (email fallback); `get_destination` (`redash/destinations/__init__.py:67`); `destination.notify`
- **Side effects**: outbound notification (HTTP/email/etc)

---

## Defensive Patterns

| Location | Pattern | Trigger condition | Exact behavior when triggered |
|----------|---------|-------------------|-------------------------------|
| `redash/destinations/webhook.py:30` | try/except | any exception during payload creation or HTTP | logs exception `"webhook send ERROR."`; returns None |
| `redash/destinations/webhook.py:50` | status code check | `resp.status_code != 200` | logs error `"webhook send ERROR. status_code => {status}"`; returns None |
| `redash/destinations/webhook.py:42` | conditional auth | `options.get("username")` truthy | sets HTTPBasicAuth; else `auth=None` |
| `redash/destinations/slack.py:52` | try/except | any exception during HTTP | logs exception `"Slack send ERROR."`; returns None |
| `redash/destinations/slack.py:55` | status code check | `resp.status_code != 200` | logs error `"Slack send ERROR. status_code => {status}"` |
| `redash/destinations/discord.py:57` | try/except | any exception during HTTP | logs exception `"Discord send ERROR: %s"` with exception; returns None |
| `redash/destinations/discord.py:64` | status code check | `resp.status_code != 200` and `!= 204` | logs error `"Discord send ERROR. status_code => {status_code}"` |
| `redash/destinations/mattermost.py:46` | try/except | any exception during HTTP | logs exception `"Mattermost webhook send ERROR."`; returns None |
| `redash/destinations/mattermost.py:50` | status code check | `resp.status_code != 200` | logs error `"Mattermost webhook send ERROR. status_code => {status}"` |
| `redash/destinations/hangoutschat.py:41` | try/except | any exception during message build or HTTP | logs exception `"webhook send ERROR."`; returns None |
| `redash/destinations/hangoutschat.py:70` | null check | `if host:` | only adds "OPEN QUERY" button when host truthy |
| `redash/destinations/hangoutschat.py:90` | status code check | `resp.status_code != 200` | logs error `"webhook send ERROR. status_code => {status}"` |
| `redash/destinations/microsoft_teams_webhook.py:18` | fallback value | `substitutions` is falsy | returns original `j` string |
| `redash/destinations/microsoft_teams_webhook.py:81` | try/except | any exception during payload build or HTTP | logs exception `"MS Teams Webhook send ERROR."`; returns None |
| `redash/destinations/microsoft_teams_webhook.py:108` | status code check | `resp.status_code != 200` | logs error `"MS Teams Webhook send ERROR. status_code => {status}"` |
| `redash/destinations/chatwork.py:33` | try/except | any exception during HTTP | logs exception `"ChatWork send ERROR."`; returns None |
| `redash/destinations/chatwork.py:58` | status code check | `resp.status_code != 200` | logs error `"ChatWork send ERROR. status_code => {status}"` |
| `redash/destinations/webex.py:43` | try/except | JSON parsing of description fails | builds fallback body with original description and links; returns fallback attachments |
| `redash/destinations/webex.py:106` | fallback value | parsed data is not 2D array | builds fallback body with original description and links; returns fallback attachments |
| `redash/destinations/webex.py:202` | null check | `destinations is None` | skips sending for that payload tag |
| `redash/destinations/webex.py:208` | length/bounds check | destination_id empty after strip | `continue` to next destination_id |
| `redash/destinations/webex.py:216` | try/except | any exception during HTTP | logs exception `"Webex send ERROR: {e}"`; returns None |
| `redash/destinations/webex.py:224` | status code check | `resp.status_code != 200` | logs error `"Webex send ERROR. status_code => {status}"` |
| `redash/destinations/datadog.py:84` | try/except | any exception during HTTP | logs exception `"Datadog send ERROR: %s"`; returns None |
| `redash/destinations/datadog.py:87` | status code check | `resp.status_code != 202` | logs error `"Datadog send ERROR. status_code => {status_code}"` |
| `redash/destinations/datadog.py:71` | fallback value | `tags` falsy | leaves `body["tags"]` as empty list, then extends with defaults |
| `redash/destinations/asana.py:50` | try/except | any exception during HTTP | logs exception `"Asana send ERROR. {exception}"`; returns None |
| `redash/destinations/asana.py:58` | status code check | `resp.status_code != 201` | logs error `"Asana send ERROR. status_code => {status}"` |
| `redash/destinations/email.py:33` | length/bounds check | `recipients` list empty | logs warning `"No emails given. Skipping send."` (continues execution) |
| `redash/destinations/email.py:36` | fallback value | `alert.custom_body` falsy | reads template file and uses `alert.render_template(...)` result |
| `redash/destinations/email.py:43` | try/except | any exception during subject/template or send | logs exception `"Mail send error."`; returns None |
| `redash/tasks/alerts.py:14` | try/except | any exception in subscription notify | logs exception `"Error with processing destination"`; continues loop |
| `redash/tasks/alerts.py:22` | null check | `alert.rearm` and `alert.last_triggered_at` set | computes `passed_rearm_threshold`; otherwise False |
| `redash/tasks/alerts.py:46` | redundant check | old_state unknown -> ok | logs debug and `continue` (skip notification) |
| `redash/tasks/alerts.py:50` | null check | `alert.muted` truthy | logs debug and `continue` (skip notification) |
| `redash/tasks/general.py:19` | try/except | any exception posting to event hooks | logs exception `"Failed posting to %s"`; continues loop |
| `redash/tasks/general.py:27` | status code check | `response.status_code != 200` | logs error `"Failed posting to %s: %s"` |
| `redash/tasks/general.py:56` | try/except | any exception during email send | logs exception `"Failed sending message: %s"`; returns None |
| `redash/tasks/general.py:65` | try/except | any exception during test_connection | returns exception object |
| `redash/tasks/general.py:75` | try/except | `NotSupported` in get_schema | returns error dict with code 1 and message |
| `redash/tasks/general.py:87` | try/except | any exception in get_schema | returns error dict with code 2/message/details |
| `redash/handlers/destinations.py:40` | null check | schema is None | abort(400) |
| `redash/handlers/destinations.py:51` | try/except | `ValidationError` on update | abort(400) |
| `redash/handlers/destinations.py:53` | try/except | `IntegrityError` on update | if "name" in error: abort(400, message=...) else abort(500) |
| `redash/handlers/destinations.py:108` | null check | schema is None | abort(400) |
| `redash/handlers/destinations.py:112` | validation check | `config.is_valid()` is False | abort(400) |
| `redash/handlers/destinations.py:126` | try/except | `IntegrityError` on create | if "name" in error: abort(400, message=...) else abort(500) |
| `redash/handlers/alerts.py:56` | conditional update | `should_notify` False | skips state update/commit; still calls notify_subscriptions |
| `redash/handlers/base.py:66` | required fields | field missing in request body | abort(400) |
| `redash/handlers/base.py:73` | null check | `rv is None` | abort(404) |
| `redash/handlers/base.py:75` | try/except | `NoResultFound` | abort(404) |
| `redash/handlers/base.py:83` | bounds check | `page < 1` | abort(400, "Page must be positive integer.") |
| `redash/handlers/base.py:86` | bounds check | page out of range | abort(400, "Page is out of range.") |
| `redash/handlers/base.py:89` | bounds check | `page_size > 250 or page_size < 1` | abort(400, "Page size is out of range (1-250).") |
| `redash/handlers/events.py:11` | null check | `ip is None` | returns "Unknown" |
| `redash/handlers/events.py:15` | try/except | any exception in GeoIP lookup | returns "Unknown" |
| `redash/models/__init__.py:1468` | null check | `self.destination` falsy | creates email destination fallback and notifies |

---

## External Calls

| Location | Target | Input | Parameterized? | Error handling |
|----------|--------|-------|:-:|---|
| `redash/destinations/webhook.py:43` | HTTP POST | `options.get("url")` with JSON body and optional basic auth | Yes | try/except; logs on non-200 |
| `redash/destinations/slack.py:53` | HTTP POST | `options.get("url")` with JSON payload | Yes | try/except; logs on non-200 |
| `redash/destinations/discord.py:58` | HTTP POST | `options.get("url")` with JSON payload | Yes | try/except; logs on non-200/204 |
| `redash/destinations/mattermost.py:47` | HTTP POST | `options.get("url")` with JSON payload | Yes | try/except; logs on non-200 |
| `redash/destinations/hangoutschat.py:89` | HTTP POST | `options.get("url")` with JSON payload | Yes | try/except; logs on non-200 |
| `redash/destinations/microsoft_teams_webhook.py:102` | HTTP POST | `options.get("url")` with JSON payload | Yes | try/except; logs on non-200 |
| `redash/destinations/chatwork.py:56` | HTTP POST | `https://api.chatwork.com/v2/rooms/{room_id}/messages` with form data | Yes | try/except; logs on non-200 |
| `redash/destinations/webex.py:217` | HTTP POST | `https://webexapis.com/v1/messages` with JSON payload | Yes | try/except; logs on non-200 |
| `redash/destinations/datadog.py:85` | HTTP POST | `https://{DATADOG_HOST}/api/v1/events` with JSON body | Yes | try/except; logs on non-202 |
| `redash/destinations/asana.py:51` | HTTP POST | `https://app.asana.com/api/1.0/tasks` with form data | Yes | try/except; logs on non-201 |
| `redash/destinations/email.py:39` | File read | `settings.REDASH_ALERTS_DEFAULT_MAIL_BODY_TEMPLATE_FILE` | N/A | no explicit error handling around open (within try/except for send) |
| `redash/destinations/email.py:52` | Email send | `Message(recipients, subject, html)` | N/A | try/except logs on error |
| `redash/tasks/alerts.py:44` | DB write | `alert.state`, `alert.last_triggered_at`, `models.db.session.commit()` | N/A | no local try/except (outer in check_alerts_for_query) |
| `redash/tasks/general.py:16` | DB write | `models.Event.record(raw_event)` + `models.db.session.commit()` | N/A | no local try/except in record_event (errors in hook posting handled) |
| `redash/tasks/general.py:26` | HTTP POST | `settings.EVENT_REPORTING_WEBHOOKS` with JSON | Yes | try/except; logs on non-200 |
| `redash/tasks/general.py:51` | HTTP POST | `https://version.redash.io/subscribe` with JSON | Yes | no try/except |
| `redash/tasks/general.py:59` | Email send | `Message(...)` -> `mail.send` | N/A | try/except logs on error |
| `redash/handlers/destinations.py:49` | DB write | `models.db.session.add/commit` (update destination) | N/A | try/except for ValidationError/IntegrityError |
| `redash/handlers/destinations.py:66` | DB delete | `models.db.session.delete/commit` | N/A | no local try/except |
| `redash/handlers/alerts.py:37` | DB write | `models.db.session.commit` (update alert) | N/A | no local try/except |
| `redash/handlers/alerts.py:101` | DB write | `models.db.session.add/flush/commit` (create alert) | N/A | no local try/except |
| `redash/handlers/events.py:14` | File read | GeoLite DB (`geolite2.geolite2_database()`) | N/A | try/except returns "Unknown" |
| `redash/handlers/base.py:61` | Queue publish | `record_event_task.delay(options)` | N/A | no local try/except |
| `redash/models/__init__.py:1351` | DB write | `db.session.add(event)` | N/A | no local try/except |
| `redash/models/__init__.py:1479` | Outbound notify | `self.destination.notify(...)` | N/A | no local try/except |

---

## Trust Assumptions

| Location | Assumption | Evidence |
|----------|-----------|---------|
| `redash/destinations/webhook.py:44` | `options.get("url")` is a valid URL | used directly in `requests.post` |
| `redash/destinations/slack.py:30` | `host` is valid and includes scheme/hostname | used to format URLs without validation |
| `redash/destinations/discord.py:55` | `colors.get(new_state)` yields acceptable color value | passed into payload without validation |
| `redash/destinations/hangoutschat.py:70` | `host` presence implies valid URL | only checks truthiness before using in openLink |
| `redash/destinations/microsoft_teams_webhook.py:86` | `options.get("message_template")` is JSON string | passed to `json_string_substitute` and sent as payload |
| `redash/destinations/chatwork.py:35` | `room_id` is provided and valid | inserted into API URL without validation |
| `redash/destinations/webex.py:194` | `options['webex_bot_token']` exists | indexed directly in headers |
| `redash/destinations/datadog.py:81` | `DATADOG_HOST` environment value is valid hostname | interpolated into URL |
| `redash/destinations/email.py:31` | `options.get("addresses")` is comma-separated list | split by comma without validation |
| `redash/tasks/alerts.py:12` | `alert.query_rel.org` is present | passed to `utils.base_url` without checks |
| `redash/handlers/destinations.py:40` | `req["type"]` exists | indexed without `require_fields` in update handler |
| `redash/handlers/alerts.py:32` | request JSON contains keys for `project` extraction | `project(req, ...)` used without validating presence of keys |
| `redash/handlers/events.py:62` | incoming event list items are valid event dicts | passed to `self.record_event` as-is |
| `redash/handlers/base.py:56` | request context has `user_agent` and `remote_addr` | accessed without guards |
| `redash/models/__init__.py:1478` | destination notify implementations accept given parameters | calls `self.destination.notify` without validation |

---

## Layer Transitions

| Direction | From | To | Data passed | Validation before handoff? |
|-----------|------|----|------------|:---:|
| Inbound | HTTP API | `DestinationListResource.post` | JSON body (`options`, `name`, `type`) | Yes (`require_fields`, schema validation) |
| Inbound | HTTP API | `DestinationResource.post` | JSON body with `type`, `name`, `options` | Partial (schema existence check; `ValidationError` handling) |
| Inbound | HTTP API | `AlertListResource.post` | JSON body (`options`, `name`, `query_id`) | Yes (`require_fields`, `require_access`) |
| Inbound | HTTP API | `AlertEvaluateResource.post` | Alert ID | Partial (permission check; no input validation) |
| Inbound | HTTP API | `EventsResource.post` | JSON list of events | No (passed directly to `record_event`) |
| Outbound | Handlers | `BaseResource.record_event` -> `record_event_task.delay` | event dict with user/org/ip/user_agent | Partial (adds fields; no schema validation) |
| Outbound | Tasks | `notify_subscriptions` -> `AlertSubscription.notify` | alert/query/user/new_state/app/host/metadata | No (passed directly) |
| Outbound | `AlertSubscription.notify` | destination notify methods | alert/query/user/new_state/app/host/metadata/options | No (uses stored options and passes through) |
| Outbound | Destinations | `requests.post` (webhooks) | payloads and URLs from options/host | No (URLs used as provided) |
| Outbound | Destinations | `mail.send` | email subject/body/recipients | Partial (recipient list derived from options) |
| Outbound | Tasks | `record_event` -> `requests.post` | event webhook payload | No (hook URL from settings) |
| Outbound | Tasks | `subscribe` -> `requests.post` | subscription form data | No (no validation in task) |
| Outbound | Models | `NotificationDestination.to_dict` | configuration schema and options | Partial (schema set; masked secrets) |
