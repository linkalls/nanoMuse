package com.openminis.app.auth

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/** Validate the OIDC identity returned by official Sign in with ChatGPT.
 *
 * No unsigned JWT parsing is trusted. ID tokens are verified against the JWKS
 * advertised by OpenAI's OIDC discovery document, with issuer/audience/nonce
 * and expiry checks before credentials are accepted.
 */
internal object ChatGptPlanOidc {
    private val decoder = Base64.getUrlDecoder()
    private const val ISSUER = "https://auth.openai.com"
    private const val DISCOVERY = "$ISSUER/.well-known/openid-configuration"

    fun verify(token: String, expectedClientId: String, expectedNonce: String, http: OkHttpClient): JSONObject {
        require(expectedClientId.isNotBlank() && expectedNonce.isNotBlank())
        val pieces = token.split('.')
        require(pieces.size == 3) { "Invalid ChatGPT ID token" }
        val header = JSONObject(String(decoder.decode(pieces[0]), Charsets.UTF_8))
        val claims = JSONObject(String(decoder.decode(pieces[1]), Charsets.UTF_8))
        require(header.optString("alg") == "RS256") { "Unsupported ChatGPT ID token signature" }
        val kid = header.optString("kid").takeIf { it.isNotBlank() } ?: error("Missing JWT key ID")

        val jwksUrl = http.newCall(Request.Builder().url(DISCOVERY).get().build()).execute().use { response ->
            require(response.isSuccessful) { "OpenAI OIDC discovery failed" }
            JSONObject(response.body?.string() ?: "{}").getString("jwks_uri")
        }
        require(jwksUrl == "$ISSUER/.well-known/jwks.json") { "Unexpected OpenAI JWKS URI" }
        val keys = http.newCall(Request.Builder().url(jwksUrl).get().build()).execute().use { response ->
            require(response.isSuccessful) { "OpenAI JWKS lookup failed" }
            JSONObject(response.body?.string() ?: "{}").getJSONArray("keys")
        }
        val jwk = (0 until keys.length()).map { keys.getJSONObject(it) }.firstOrNull {
            it.optString("kid") == kid && it.optString("kty") == "RSA"
        } ?: error("ChatGPT ID token signing key not found")
        val exponent = BigInteger(1, decoder.decode(jwk.getString("e")))
        val modulus = BigInteger(1, decoder.decode(jwk.getString("n")))
        val rsa = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(rsa)
        verifier.update("${pieces[0]}.${pieces[1]}".toByteArray(Charsets.US_ASCII))
        require(verifier.verify(decoder.decode(pieces[2]))) { "Invalid ChatGPT ID token signature" }

        require(claims.optString("iss") == ISSUER) { "Unexpected ChatGPT ID token issuer" }
        val audience = claims.opt("aud")
        val matchesAudience = if (audience is org.json.JSONArray) {
            (0 until audience.length()).any { audience.optString(it) == expectedClientId }
        } else audience == expectedClientId
        require(matchesAudience) { "ChatGPT ID token client mismatch" }
        val now = System.currentTimeMillis() / 1000
        require(claims.optLong("exp") > now && claims.optLong("iat") <= now + 120) { "Expired or invalid ChatGPT ID token" }
        require(claims.optString("nonce") == expectedNonce) { "ChatGPT ID token nonce mismatch" }
        require(claims.optString("sub").isNotBlank()) { "ChatGPT ID token has no identity" }
        return claims
    }
}
