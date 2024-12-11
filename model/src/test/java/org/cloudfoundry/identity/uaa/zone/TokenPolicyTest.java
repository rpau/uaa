package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenPolicyTest {

    @Test
    public void json_has_expected_properties() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(1234);
        tokenPolicy.setRefreshTokenValidity(9876);
        tokenPolicy.setKeys(Collections.singletonMap("aKeyId", "KeyKeyKey"));

        String json = JsonUtils.writeValueAsString(tokenPolicy);
        Map properties = JsonUtils.readValue(json, Map.class);

        assertNotNull(properties);
        assertEquals(1234, properties.get("accessTokenValidity"));
        assertEquals(9876, properties.get("refreshTokenValidity"));
        assertNotNull(properties.get("keys"));
        Map keys = (Map) properties.get("keys");
        assertNotNull(keys);
        assertEquals(keys.size(), 1);
        assertEquals("KeyKeyKey", ((Map) keys.get("aKeyId")).get("signingKey"));
    }

    @Test
    public void test_default_values() {
        TokenPolicy policy = new TokenPolicy();
        assertFalse(policy.isRefreshTokenUnique());
        assertFalse(policy.isJwtRevocable());
        assertFalse(policy.isRefreshTokenRotate());
        assertEquals(TokenConstants.TokenFormat.OPAQUE.getStringValue(), policy.getRefreshTokenFormat());
    }

    @Test
    public void test_set_values() {
        TokenPolicy policy = new TokenPolicy();
        policy.setRefreshTokenUnique(true);
        policy.setJwtRevocable(true);
        policy.setRefreshTokenRotate(true);
        policy.setRefreshTokenFormat(TokenConstants.TokenFormat.JWT.getStringValue());
        assertTrue(policy.isRefreshTokenUnique());
        assertTrue(policy.isJwtRevocable());
        assertTrue(policy.isRefreshTokenRotate());
        assertEquals(TokenConstants.TokenFormat.JWT.getStringValue(), policy.getRefreshTokenFormat());
    }

    @Test
    public void nullSigningKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            TokenPolicy tokenPolicy = new TokenPolicy();
            tokenPolicy.setKeys(Collections.singletonMap("key-id", null));
        });
    }

    @Test
    public void emptySigningKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            TokenPolicy tokenPolicy = new TokenPolicy();
            tokenPolicy.setKeys(Collections.singletonMap("key-id", "             "));
        });
    }

    @Test
    public void nullKeyId() {
        assertThrows(IllegalArgumentException.class, () -> {
            TokenPolicy tokenPolicy = new TokenPolicy();
            tokenPolicy.setKeys(Collections.singletonMap(null, "signing-key"));
        });
    }

    @Test
    public void emptyKeyId() {
        assertThrows(IllegalArgumentException.class, () -> {
            TokenPolicy tokenPolicy = new TokenPolicy();
            tokenPolicy.setKeys(Collections.singletonMap(" ", "signing-key"));
        });
    }

    @Test
    public void deserializationOfTokenPolicyWithVerificationKey_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"verificationKey\":\"some-verification-key-1\",\"signingKey\":\"some-signing-key-1\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertEquals("some-signing-key-1", tokenPolicy.getKeys().get("key-id-1").getSigningKey());
    }

    @Test
    public void tokenPolicy_whenInvalidUniquenessValue_throwsException() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {

            TokenPolicy tokenPolicy = new TokenPolicy();

            tokenPolicy.setRefreshTokenFormat("invalid");
        });
        assertTrue(exception.getMessage().contains("Invalid refresh token format invalid. Acceptable values are: [opaque, jwt]"));
    }

    @Test
    public void deserializationOfTokenPolicyWithNoActiveKeyIdWithMultipleKeys_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"signingKey\":\"some-signing-key-1\"},\"key-id-2\":{\"signingKey\":\"some-signing-key-2\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertEquals("some-signing-key-1", tokenPolicy.getKeys().get("key-id-1").getSigningKey());
        assertEquals("some-signing-key-2", tokenPolicy.getKeys().get("key-id-2").getSigningKey());
    }

    @Test
    public void tokenPolicy_not_changed_if_keys_null() {
        final String sampleIdentityZone = getResourceAsString(getClass(), "SampleIdentityZone.json");
        IdentityZone identityZone = JsonUtils.readValue(sampleIdentityZone, IdentityZone.class);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        assertEquals("some-signing-key-1", tokenPolicy.getKeys().get("key-id-1").getSigningKey());
        assertEquals("some-cert", tokenPolicy.getKeys().get("key-id-1").getSigningCert());
        assertEquals("RS256", tokenPolicy.getKeys().get("key-id-1").getSigningAlg());
        tokenPolicy.setKeys(null);
        assertEquals("some-signing-key-1", tokenPolicy.getKeys().get("key-id-1").getSigningKey());
        assertEquals("some-cert", tokenPolicy.getKeys().get("key-id-1").getSigningCert());
        assertEquals("RS256", tokenPolicy.getKeys().get("key-id-1").getSigningAlg());
    }
}
