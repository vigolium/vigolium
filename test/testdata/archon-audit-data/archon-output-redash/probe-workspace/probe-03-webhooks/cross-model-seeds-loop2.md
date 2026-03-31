## CROSS-01: Destination types enumeration

Source-A: PH-01 from backward-reasoner loop2 (round-1-hypotheses-loop2.md)
Source-B: PH-07 from contradiction-reasoner loop2 (round-2-hypotheses-loop2.md)
Connection: Same endpoint `DestinationTypeListResource.get` and same data exposure (enabled destination types). One focuses on auth gap, the other on lack of audit.
Combined hypothesis: Destination type enumeration provides reconnaissance value; if the admin-only gate is bypassed or logging is absent, attackers can discover available webhook/integration types without detection.
Test direction for causal-verifier: Verify auth enforcement and whether access is recorded; confirm response content includes full destination schemas/types.

## CROSS-02: Subscription list exposure

Source-A: PH-08 from backward-reasoner loop2
Source-B: PH-03 from contradiction-reasoner loop2
Connection: Same endpoint `AlertSubscriptionListResource.get` returning `AlertSubscription.to_dict()` with user/destination details; both highlight disclosure to view-only users.
Combined hypothesis: View-only users can enumerate subscription recipients and (if present) destination details, enabling phishing or webhook leakage.
Test direction for causal-verifier: Inspect `AlertSubscription.to_dict()` and `User.to_dict()` for exposed fields and whether destination options are included.

## CROSS-03: Subscription deletion context checks

Source-A: PH-09 from backward-reasoner loop2
Source-B: PH-04 from contradiction-reasoner loop2
Connection: Same endpoint `AlertSubscriptionResource.delete` and authorization logic around subscription deletion; both focus on insufficient contextual checks.
Combined hypothesis: Subscription deletion relies only on ownership and ignores alert context, allowing stealth opt-out or ID-based probing of subscription ownership.
Test direction for causal-verifier: Confirm delete path does not enforce alert_id context or access checks beyond `require_admin_or_owner`.

## CROSS-04: Alert update access controls

Source-A: PH-05 from backward-reasoner loop2
Source-B: PH-01 from contradiction-reasoner loop2
Connection: Same endpoint `AlertResource.post` and alert update path; both question whether query access is revalidated on update.
Combined hypothesis: Alert updates may allow rebinding to unauthorized queries or injecting notification content, leading to data exposure through alerts.
Test direction for causal-verifier: Inspect update path for query access checks and confirm which fields are permitted in updates.

## CROSS-05: Alert deletion audit/impact

Source-A: PH-06 from backward-reasoner loop2
Source-B: PH-02 from contradiction-reasoner loop2
Connection: Same endpoint `AlertResource.delete`; one highlights monitoring suppression, the other missing audit/event recording.
Combined hypothesis: Alert deletion can be used to suppress monitoring and may be under-audited, increasing stealth of destructive actions.
Test direction for causal-verifier: Verify delete path lacks record_event and check for any alternate audit logging.

## CROSS-06: Event webhook envelope targeting

Source-A: PH-12 from backward-reasoner loop2
Source-B: PH-06 from contradiction-reasoner loop2
Connection: Same trust boundary in `tasks/general.py:record_event` where schema-wrapped payload is forwarded to `EVENT_REPORTING_WEBHOOKS` URLs.
Combined hypothesis: Even with an envelope wrapper, attacker-controlled event payloads can trigger internal JSON endpoints that accept generic envelopes or ignore unknown fields.
Test direction for causal-verifier: Confirm payload shape and identify whether any internal endpoints or hooks accept nested `data` fields.

## CROSS-07: Destination deletion and event amplification

Source-A: PH-03 from backward-reasoner loop2
Source-B: PH-05 from contradiction-reasoner loop2
Connection: Same endpoint `DestinationResource.delete` (and other event-recording endpoints) — one focuses on destructive delete, the other on event webhook amplification via repeated calls.
Combined hypothesis: Destination deletion can both suppress notifications and generate event webhook traffic; repeated deletes across resources can amplify outbound webhook load.
Test direction for causal-verifier: Confirm `DestinationResource.delete` calls `record_event` and assess rate limiting or audit visibility.

## CROSS-08: Destination read and event amplification

Source-A: PH-02 from backward-reasoner loop2
Source-B: PH-05 from contradiction-reasoner loop2
Connection: Same endpoint `DestinationResource.get`; one highlights URL leakage, the other notes repeated GETs trigger event webhook traffic.
Combined hypothesis: Destination reads can both leak webhook URLs and be abused for event webhook amplification if record_event hooks are internal.
Test direction for causal-verifier: Verify `DestinationResource.get` uses record_event and confirm what fields are returned in `to_dict(all=True)`.

## CROSS-09: Events listing exposure + audit

Source-A: PH-11 from backward-reasoner loop2
Source-B: PH-08 from contradiction-reasoner loop2
Connection: Same endpoint `EventsResource.get` and same disclosure of IP/user-agent; both highlight lack of access logging.
Combined hypothesis: Event log access exposes user metadata at scale without auditing the access itself, increasing privacy risk.
Test direction for causal-verifier: Check whether `EventsResource.get` is admin-gated and whether access triggers record_event.
