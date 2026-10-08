# Supabase API contract

This is how the Supabase gateway answers the requests the agent makes, and how `internal/supabase` classifies each answer. The classifiers in `internal/supabase/errors.go` (`IsUnauthorized`, `IsForbidden`, `IsNotFound`) are derived from this table.

> **Status: expected behaviour, not yet verified.** The values below come from Supabase's documentation for PostgREST, Storage and GoTrue. Each row must be confirmed by probing **staging** (issue #88): record the observed status and body, then update the classifier lists if anything differs.

## Requests the agent makes

| Operation | Request | `apikey` | `Authorization` |
|---|---|---|---|
| RPC | `POST /rest/v1/rpc/<fn>` | anon key | `Bearer <access token>` |
| Release download | `GET /storage/v1/object/agent-releases/<asset>` | anon key | `Bearer <access token>` |
| Script download | `GET /storage/v1/object/authenticated/command-scripts/<path>` | anon key | `Bearer <access token>` |
| Token refresh | `POST /auth/v1/token?grant_type=refresh_token`, body `{"refresh_token": "..."}` | **anon key** | none |
| Agent login | `POST /functions/v1/agent-login`, body `{"agent_id", "agent_secret"}` | anon key | none |

Storage paths are concatenated verbatim, with no escaping. The updater depends on these URLs never changing.

## Error responses

| # | Case | Expected status | Expected body | Classification | Verified |
|---|---|---|---|---|---|
| 1 | Refresh with a **user JWT** as `apikey` (what supabase-go sent before P2) | 401 | `{"message":"Invalid API key"}` (gateway) | — (the bug P2 fixes) | ☐ |
| 2 | Refresh with the anon key, valid refresh token | 200 | new `access_token` + `refresh_token` | success | ☐ |
| 3 | Refresh token already rotated out | 400 | `{"code":400,"error_code":"refresh_token_already_used",...}` | terminal → agent-login | ☐ |
| 4 | Unknown/revoked refresh token | 400 | `{"error_code":"refresh_token_not_found",...}` | terminal → agent-login | ☐ |
| 5 | Reusing a rotated refresh token revokes the whole token family? | — | — | — | ☐ |
| 6 | RPC with an **expired** JWT | 401 | `{"code":"PGRST301","message":"JWT expired",...}` | unauthorized | ☐ |
| 7 | RPC with a **malformed** JWT | 401 | `{"code":"PGRST301",...}` | unauthorized | ☐ |
| 8 | RPC denied by a grant/RLS | 403 | `{"code":"42501","message":"permission denied ..."}` | forbidden | ☐ |
| 9 | RPC function missing | 404 | `{"code":"PGRST202",...}` | not found | ☐ |
| 10 | Storage download with an expired JWT | 400 | `{"statusCode":"400","error":"InvalidJWT","message":"..."}` | unauthorized | ☐ |
| 11 | Storage download of a missing object | 400 or 404 | `{"statusCode":"404","error":"not_found","message":"Object not found"}` | not found | ☐ |
| 12 | agent-login with bad credentials | 401 or 403 | function-defined | rejected (needs re-provisioning) | ☐ |
| 13 | agent-login rate limited | 429 | function-defined | not retryable (breaker backs off) | ☐ |

## Classifier lists

- **Unauthorized** (refresh the session and retry once): HTTP 401, or code `PGRST301`, `PGRST302`, `PGRST303`, `InvalidJWT` or `bad_jwt` on any status.
- **Forbidden** (do not refresh): HTTP 403 or code `42501`, unless the code is in the unauthorized list.
- **Not found**: HTTP 404, or code `not_found`, `NoSuchKey`, `NoSuchBucket` or `PGRST202`.

## Fleet check

Search production agent logs for `Auth: refresh attempt ... failed` immediately followed by `agent-login attempt`. Finding that pattern confirms the refresh bug in row 1 is live in the fleet. ☐
