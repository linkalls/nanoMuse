package com.openminis.app.auth

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.openminis.app.logging.AppLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.InetAddress
import java.net.ProxySelector
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import kotlin.coroutines.resume

/**
 * Thrown by [OpenAIOAuthManager] when DNS lookup or socket connect to
 * the OpenAI auth endpoint fails. The UI catches this specifically to
 * render the localized "check network / proxy" prompt instead of the
 * raw OkHttp message.
 */
class OAuthNetworkUnreachableException(cause: Throwable) : Exception(cause.message, cause)

class OpenAIOAuthManager(context: Context, instanceId: String) : OAuthManager(context, instanceId) {
    companion object {
        private const val TAG = "CodexOAuth"

        /**
         * Static helper: perform full login flow and save the access token.
         * Returns the access token. Mirrors ClaudeOAuthManager.login().
         */
        suspend fun login(context: Context, instanceId: String, providerRepository: com.openminis.app.data.repository.ProviderRepository): String {
            val manager = OpenAIOAuthManager(context, instanceId)
            val token = manager.performLogin(context)
            providerRepository.saveApiKey(instanceId, token)
            return token
        }
    }

    private var loginCallbackServer: OAuthCallbackServer? = null
    private var expectedState: String? = null

    /**
     * Perform the full OAuth login flow.
     * Returns the access token. Throws on failure.
     */
    /**
     * Official Sign in with ChatGPT / plan usage authorization. This is an opt-in
     * re-sign-in for existing Codex-OAuth users: legacy saved tokens stay valid
     * until the new flow has exchanged AND verified all granted credentials.
     */
    suspend fun performLogin(context: Context): String {
        loginCallbackServer?.stop()
        loginCallbackServer = null
        val authUrl = buildAuthorizationUrl()
        val params = withContext(Dispatchers.IO) {
            suspendCancellableCoroutine<Map<String, String>> { continuation ->
                val listener = OAuthCallbackServer(
                    port = callbackPort,
                    onCode = { _, _ -> },
                    onParameters = { result ->
                        if (continuation.isActive) continuation.resume(result)
                    },
                    loopbackOnly = true,
                )
                loginCallbackServer = listener
                listener.start()
                continuation.invokeOnCancellation {
                    listener.stop()
                    loginCallbackServer = null
                }
                CustomTabsIntent.Builder().setShowTitle(true).build()
                    .launchUrl(context, Uri.parse(authUrl))
            }
        }
        loginCallbackServer?.stop()
        loginCallbackServer = null
        val receivedState = params["state"].orEmpty()
        // State is REQUIRED on ALL callbacks, including OAuth error responses.
        require(receivedState.isNotEmpty() && receivedState == expectedState) { "ChatGPT login state mismatch" }
        params["error"]?.let { throw IllegalStateException("ChatGPT authorization: $it") }
        val code = params["code"].orEmpty()
        require(code.isNotBlank()) { "ChatGPT login returned no authorization code" }
        val registeredId = loadOAuthString("siwc_client_id")
        val issuedId = if (registeredId.isNullOrBlank()) {
            params["client_id"]?.takeIf { it.startsWith("oaiapp_") }
                ?: throw IllegalStateException("ChatGPT plan registration did not issue a client ID")
        } else {
            val callbackId = params["client_id"]
            require(callbackId.isNullOrEmpty() || callbackId == registeredId) { "ChatGPT registered client mismatch" }
            registeredId
        }
        return withContext(Dispatchers.IO) { exchangePlanCode(code, issuedId) }
    }

    // Existing legacy Codex tokens still refresh with their own issuer/client.
    val isChatGptPlan: Boolean get() = !loadOAuthString("siwc_client_id").isNullOrBlank()
    override val authURL = "https://auth.openai.com/api/accounts/authorize"
    override val tokenURL: String
        get() = if (isChatGptPlan) "https://auth.openai.com/api/accounts/oauth/token" else "https://auth.openai.com/oauth/token"
    override val clientId: String
        get() = loadOAuthString("siwc_client_id") ?: "app_EMoamEEZ73f0CkXaXp7hrann"
    override val clientSecret: String? = null
    override val callbackPort = 1455
    override val redirectPath = "/auth/callback"
    override val redirectUri: String get() = "http://127.0.0.1:$callbackPort$redirectPath"
    override val scopes = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"

    private var pendingNonce: String? = null

    override fun generateAndSavePKCE(): Pair<String, String> = generatePKCE().also { (verifier, _) ->
        saveOAuthString("verifier", verifier)
    }

    override fun buildAuthorizationUrl(): String {
        val (_, challenge) = generateAndSavePKCE()
        val state = generateState()
        expectedState = state
        val nonce = java.util.UUID.randomUUID().toString()
        pendingNonce = nonce
        val hostId = loadOAuthString("siwc_host_id") ?: ("urn:uuid:" + java.util.UUID.randomUUID()).also {
            saveOAuthString("siwc_host_id", it)
        }
        val registeredId = loadOAuthString("siwc_client_id")
        val requestId = registeredId ?: "dynamic_agent_client"
        val params = linkedMapOf(
            "client_id" to requestId,
            "ext_agent_host_id" to hostId,
            "redirect_uri" to redirectUri,
            "response_type" to "code",
            "scope" to scopes,
            "resource" to "https://api.openai.com/v1",
            "state" to state,
            "nonce" to nonce,
            "code_challenge" to challenge,
            "code_challenge_method" to "S256",
        )
        if (registeredId.isNullOrBlank()) params["agent_name_hint"] = "nanoMuse"
        else loadStoredTokens()?.optString("id_token")?.takeIf { it.isNotBlank() }?.let { params["id_token_hint"] = it }
        return authURL + "?" + params.entries.joinToString("&") { (k,v) ->
            "${Uri.encode(k)}=${Uri.encode(v)}"
        }
    }

    /** Uses form encoding and the registration-issued client ID, never the
     * legacy Codex client ID. Persist only after full ID-token validation. */
    private fun exchangePlanCode(code: String, issuedId: String): String {
        val verifier = loadOAuthString("verifier")
            ?: throw IllegalStateException("Missing PKCE verifier")
        val fields = linkedMapOf(
            "grant_type" to "authorization_code",
            "client_id" to issuedId,
            "code" to code,
            "code_verifier" to verifier,
            "redirect_uri" to redirectUri,
            "resource" to "https://api.openai.com/v1",
        )
        val form = fields.entries.joinToString("&") { (k,v) -> "${Uri.encode(k)}=${Uri.encode(v)}" }
        val req = okhttp3.Request.Builder()
            .url("https://auth.openai.com/api/accounts/oauth/token")
            .post(form.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
            .build()
        val data = systemAwareHttpClient.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw IllegalStateException("ChatGPT plan token exchange rejected (HTTP ${response.code})")
            JSONObject(response.body?.string() ?: "{}")
        }
        val access = data.optString("access_token")
        val idToken = data.optString("id_token")
        require(access.isNotBlank() && idToken.isNotBlank()) { "Incomplete ChatGPT plan credentials" }
        val scope = data.optString("scope")
        val permissions = scope.split(' ').toSet()
        require("chatgpt.tokens.use.direct" in permissions && "resource.invoke" in permissions) {
            "ChatGPT plan access was not approved for this account"
        }
        val identity = ChatGptPlanOidc.verify(idToken, issuedId, pendingNonce.orEmpty(), systemAwareHttpClient)
        val previouslyVerified = loadOAuthString("siwc_subject")
        require(previouslyVerified == null || previouslyVerified == identity.optString("sub")) {
            "ChatGPT account changed; use a separate provider for another account"
        }
        val expires = data.optLong("expires_in")
        if (expires > 0) data.put("expire_at", System.currentTimeMillis() + expires * 1000)
        // Atomic credential state only after verification and permissions.
        saveOAuthString("tokens", data.toString())
        saveOAuthString("siwc_client_id", issuedId)
        saveOAuthString("siwc_subject", identity.getString("sub"))
        parseIdToken(idToken)
        return access
    }

    override suspend fun refreshToken(): Boolean {
        if (!isChatGptPlan) return super.refreshToken()
        return withContext(Dispatchers.IO) {
            val old = loadStoredTokens() ?: return@withContext false
            val refresh = old.optString("refresh_token").takeIf { it.isNotBlank() } ?: return@withContext false
            val params = linkedMapOf(
                "grant_type" to "refresh_token",
                "refresh_token" to refresh,
                "client_id" to clientId,
                "resource" to "https://api.openai.com/v1",
            )
            val form = params.entries.joinToString("&") { (k,v) -> "${Uri.encode(k)}=${Uri.encode(v)}" }
            runCatching {
                val req = okhttp3.Request.Builder()
                    .url(tokenURL)
                    .post(form.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
                    .build()
                val newer = systemAwareHttpClient.newCall(req).execute().use { response ->
                    if (!response.isSuccessful) return@withContext false
                    JSONObject(response.body?.string() ?: "{}")
                }
                require(newer.optString("access_token").isNotBlank())
                val scopes = newer.optString("scope", old.optString("scope")).split(' ').toSet()
                require("chatgpt.tokens.use.direct" in scopes && "resource.invoke" in scopes)
                if (!newer.has("refresh_token")) newer.put("refresh_token", refresh)
                if (!newer.has("id_token")) newer.put("id_token", old.optString("id_token"))
                if (!newer.has("scope")) newer.put("scope", old.optString("scope"))
                val expires = newer.optLong("expires_in")
                if (expires > 0) newer.put("expire_at", System.currentTimeMillis() + expires * 1000)
                saveOAuthString("tokens", newer.toString())
                true
            }.getOrElse { false }
        }
    }

    var accountId: String?
        get() = loadOAuthString("account_id")
        private set(value) { value?.let { saveOAuthString("account_id", it) } }

    var planType: String?
        get() = loadOAuthString("plan_type")
        private set(value) { value?.let { saveOAuthString("plan_type", it) } }

    override suspend fun onTokensReceived(json: JSONObject) {
        val idToken = json.optString("id_token", "")
        if (idToken.isNotEmpty()) {
            parseIdToken(idToken)
        }
    }

    /**
     * Exchange authorization code for tokens using JSON body.
     * OpenAI requires application/json (same as Anthropic).
     *
     * [T-android-codex-oauth-dns] Uses a dedicated OkHttp client wired to
     * the system [ProxySelector] (the default selector reads
     * `Settings.Global.HTTP_PROXY` + ConnectivityManager's link proxy +
     * any active VPN routing). Pre-fix the shared OAuthManager.httpClient
     * was built with .build() defaults, which silently bypass VPN-style
     * SOCKS / fake-IP DNS proxies common in CN (Clash etc.) — users could
     * complete the browser-side login (Custom Tab uses system network
     * stack) but the in-app token POST resolved auth.openai.com via the
     * raw carrier resolver and got UnknownHostException.
     */
    private fun exchangeCodeJson(code: String): String {
        val jsonBody = JSONObject().apply {
            put("grant_type", "authorization_code")
            put("client_id", clientId)
            put("code", code)
            put("redirect_uri", redirectUri)
            put("code_verifier", loadOAuthString("verifier") ?: "")
        }

        AppLogger.info(TAG, "token exchange POST $tokenURL bodyLen=${jsonBody.toString().length}")
        logNetworkEnvironment(tokenURL)

        val request = okhttp3.Request.Builder()
            .url(tokenURL)
            .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
            .build()
        // Retry up to 3 times — DNS can briefly fail after Custom Tab closes
        var response: okhttp3.Response? = null
        var lastError: Exception? = null
        for (attempt in 1..3) {
            try {
                response = systemAwareHttpClient.newCall(request).execute()
                lastError = null
                break
            } catch (e: Exception) {
                AppLogger.warning(
                    TAG,
                    "token exchange attempt $attempt failed: ${e.javaClass.simpleName}: ${e.message}",
                )
                lastError = e
                if (attempt < 3) Thread.sleep(1000L * attempt)
            }
        }
        if (response == null) {
            AppLogger.error(
                TAG,
                "token exchange failed after 3 attempts: ${lastError?.javaClass?.simpleName}: ${lastError?.message}",
            )
            throw lastError?.let { wrapIfNetworkError(it) } ?: Exception("Token exchange failed")
        }
        val responseCode = response.code
        val responseBody = response.body?.string() ?: ""
        response.close()
        AppLogger.info(
            TAG,
            // nanoMuse: the success body carries the access, refresh and id tokens; mask them before they reach the log file.
            "token exchange response: $responseCode bodyLen=${responseBody.length} body[0..500]=${OAuthManager.sanitizeBody(responseBody, 500)}",
        )

        if (responseCode !in 200..299) {
            AppLogger.error(TAG, "token exchange non-2xx: $responseCode")
            throw Exception("Token exchange failed ($responseCode): $responseBody")
        }

        val json = JSONObject(responseBody)
        val accessToken = json.optString("access_token", "")
        if (accessToken.isEmpty()) {
            AppLogger.error(TAG, "no access_token field in response")
            throw Exception("No access_token in response")
        }

        // Save full token data (for refresh later)
        val expiresIn = json.optLong("expires_in", 0)
        if (expiresIn > 0) {
            json.put("expire_at", System.currentTimeMillis() + expiresIn * 1000)
        }
        saveOAuthString("tokens", json.toString())

        // Parse id_token for account info
        val idToken = json.optString("id_token", "")
        if (idToken.isNotEmpty()) {
            parseIdToken(idToken)
        }

        AppLogger.info(
            TAG,
            "token exchange OK accessTokenLen=${accessToken.length} expiresIn=${expiresIn}s hasRefresh=${json.has("refresh_token")}",
        )
        return accessToken
    }

    /**
     * Wrap raw network failures so the UI can render the localized
     * "check network / proxy" prompt instead of the cryptic
     * UnknownHostException text. Anything else passes through unchanged
     * so token-format errors / 4xx still surface their original message.
     */
    private fun wrapIfNetworkError(e: Throwable): Throwable =
        if (e is UnknownHostException || e is SocketTimeoutException) {
            OAuthNetworkUnreachableException(e)
        } else {
            e
        }

    /**
     * Log the resolved IP for [url]'s host plus the system-selected
     * proxy chain. Useful for diagnosing the "browser works but OkHttp
     * doesn't" gap on networks where the user is running a VPN-style
     * proxy (Clash, Shadowsocks) that intercepts via fake-IP DNS but
     * doesn't register as an HTTP_PROXY.
     */
    private fun logNetworkEnvironment(url: String) {
        val host = runCatching { URI(url).host }.getOrNull() ?: return
        try {
            val addr = InetAddress.getByName(host)
            AppLogger.info(TAG, "dns: $host → ${addr.hostAddress}")
        } catch (e: Exception) {
            AppLogger.warning(
                TAG,
                "dns lookup FAILED for $host: ${e.javaClass.simpleName}: ${e.message}",
            )
        }
        try {
            val proxies = ProxySelector.getDefault().select(URI(url))
            AppLogger.info(TAG, "proxy chain for $host: $proxies")
        } catch (e: Exception) {
            AppLogger.warning(TAG, "proxy lookup failed: ${e.message}")
        }
    }

    /**
     * Per-call OkHttp client wired to the system ProxySelector +
     * Authenticator with an interceptor that records the chosen route's
     * remote address. Lazy so the proxy state is read fresh each login
     * (network may have switched between cold-start and tap-Sign-in).
     */
    private val systemAwareHttpClient: okhttp3.OkHttpClient by lazy {
        okhttp3.OkHttpClient.Builder()
            .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .proxySelector(ProxySelector.getDefault())
            .addNetworkInterceptor { chain ->
                val req = chain.request()
                val route = chain.connection()?.route()
                AppLogger.info(
                    TAG,
                    "okhttp connect: url=${req.url} via proxy=${route?.proxy} socket=${route?.socketAddress}",
                )
                chain.proceed(req)
            }
            .proxyAuthenticator(io.github.nanomuse.net.OwnProviderProxy.authenticator) // nanoMuse: Settings → Network, a proxy with a password
            .build()
    }

    private fun parseIdToken(token: String) {
        try {
            val parts = token.split(".")
            if (parts.size >= 2) {
                val payload = String(java.util.Base64.getUrlDecoder().decode(parts[1]))
                val json = JSONObject(payload)
                accountId = json.optString("chatgpt_account_id").ifEmpty { null }
                planType = json.optString("chatgpt_plan_type").ifEmpty { null }
            }
        } catch (e: Exception) {
            AppLogger.warning(TAG, "id_token parse failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
