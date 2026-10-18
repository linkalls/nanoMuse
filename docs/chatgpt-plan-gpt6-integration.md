# Android GPT-6.x via official Sign in with ChatGPT — implementation design

> **Status: design only. No Android runtime, authentication, or APK behavior is changed by this document.**

## Confirmed reproduction

- Debug APK built from upstream commit `2ffa1f98224e52e38c9d66b39754cd7b75339fc4` (`linkalls/nanoMuse` [CI run 39122856287](https://github.com/linkalls/nanoMuse/actions/runs/39122856287)).
- The same user's ChatGPT subscription works for **GPT-6.1 Sol in official Codex**.
- In nanoMuse, `gpt-5.6-sol` works, while `gpt-6-luna` and `gpt-6.1-sol` return HTTP 400, e.g. `The 'gpt-6-luna' model is not supported when using Codex with a ChatGPT account.`
- The successful official Codex request proves access by **that client/route**, not by every third-party authentication route.

## Current Android integration, and why the picker is misleading

| Source | Current behavior |
| --- | --- |
| `android/src/android/app/src/main/java/com/openminis/app/auth/OpenAIOAuthManager.kt` | Hardcoded Codex OAuth client; legacy `https://auth.openai.com/oauth/authorize`; scopes `openid profile email offline_access`. |
| `android/src/android/app/src/main/java/com/openminis/app/provider/openai/OpenAIProvider.kt` | OAuth inference at `https://chatgpt.com/backend-api/codex/responses`. |
| `android/src/android/app/src/main/java/com/openminis/app/provider/openai/OpenAIModelsApi.kt` | Queries legacy model endpoint, then **unconditionally adds** static GPT-6 entries missing from the live list (`live + builtInCodexOAuthModels.filter { ... }`). A visible option is therefore not proof of entitlement. |

Do **not** try to fix this by falsifying a Codex client ID, User-Agent, token claims, or response. A model-name change cannot grant server-side access.

## Supported alternative: Sign in with ChatGPT (OSS plan usage)

The official preview is a **distinct, opt-in connection**; retain existing legacy login separately to preserve working GPT-5.6 sessions and provide a safe fallback.

1. **Registration/sign-in.** Generate and persist a random `urn:uuid:…` `ext_agent_host_id` per Android installation. Open `https://auth.openai.com/api/accounts/authorize` in a system browser with `client_id=dynamic_agent_client` on first registration; include `agent_name_hint=nanoMuse`, PKCE S256, unique `state`, unique OIDC `nonce`, `response_type=code`, `redirect_uri=http://127.0.0.1:<port>/auth/callback`, `resource=https://api.openai.com/v1` and scopes `openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`. Bind the loopback listener before opening the browser. Validate callback state strictly; never proceed on mismatch. Registration returns an issued **per-account** `client_id`; use that to exchange the code and for future sign-ins. The callback must retain the `client_id`, not only the `code` and `state`. In the original code, the existing callback server receives only code/state and must be adapted for this new route.
2. **Token storage.** Validate the OIDC ID token (signature, issuer, nonce, audience, expiry), and confirm the `chatgpt.tokens.use.direct` permission was actually granted. Encrypt persisted tokens and issued client ID; associate the registered OAuth client with a specific account/workspace and host ID. Implement refresh token rotation; offer revocation/logout. Keep legacy Codex OAuth state independent. Never store tokens in logs or GitHub.
3. **Model picker.** Send `GET https://api.openai.com/v1/models` with the new bearer token, parse `models[]`, keep `visibility == "list"`, show `display_name`, send exact `slug` as `model`. Refresh on account switch. Never append a fixed set of models not returned by this endpoint. A list entry is only a display hint; **successful inference** verifies actual access.
4. **Inference.** Send `POST https://api.openai.com/v1/responses` with `Authorization: Bearer <SIWC_ACCESS_TOKEN>`, `store:false`, `stream:true`. Send input as an array with user/assistant/developer messages and explicit local tool definitions that conform to the official preview. Do not send unsupported parameters (`previous_response_id`, `background`, `metadata`, `temperature`, `top_p`, `max_output_tokens`, etc.) or top-level system message objects. Use official SSE event semantics: collect `response.output_text.delta`, treat `response.completed` as success, preserve `response.failed` / `response.incomplete`, and report HTTP errors and request IDs without exposing credentials. Respect supported tool namespaces and unsupported hosted tools.
5. **UX.** Label this option **Continue with ChatGPT**; disclose that it connects the ChatGPT plan and uses its quota, not API-key billing. Do not silently fall back to a separately billed API key. If a selected model gets a 400, show the exact server diagnostic and allow the user to choose another model or go to Coding agents.
6. **Tests and rollout.** Add mocked integration tests for initial and returning registration, callback `client_id`/state/nonce/PKCE, token and permission validation, refresh, model list parsing, request body and response streams, and 4xx/429. Live tests require an explicitly consenting account. Verify the selected GPT-6.1 Sol and GPT-6 Luna independently; **neither is guaranteed until a real request completes**. Build via `.github/workflows/android.yml` and ship as a separately signed test APK first.

### Existing immediate route (no model proxy)

`docs/coding-agents.md` already documents steering **the official Codex CLI installed and signed in on a remote computer** from nanoMuse Android's **Coding** screen using the nanoMuse Hub. It is the quickest route to a model confirmed working in that Codex installation. It requires that computer to be online. It is **not** the same as switching nanoMuse's normal chat model, and it does not provide a cloud PC for free.

## OpenAI primary sources

- [SIWC registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [SIWC models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [SIWC preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
- [SIWC errors and recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery)
- [SIWC Codex app-server integration](https://developers.openai.com/siwc/token-sharing-open-source/codex-app-server)
