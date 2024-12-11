package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class InMemoryTokenStoreTests extends TokenStoreBaseTests {

    private InMemoryTokenStore tokenStore;

    @Override
    public InMemoryTokenStore getTokenStore() {
        return tokenStore;
    }

    @BeforeEach
    public void createStore() {
        AuthenticationKeyGenerator dummyKeyGenerator = new AuthenticationKeyGenerator() {
            private final String key = new AlphanumericRandomValueStringGenerator(10).generate();

            @Override
            public String extractKey(OAuth2Authentication authentication) {
                return key;
            }
        };
        tokenStore = new InMemoryTokenStore();
        tokenStore.clear();
        tokenStore.setAuthenticationKeyGenerator(dummyKeyGenerator);
    }

    @Test
    public void testTokenCountConsistency() {
        for (int i = 0; i <= 10; i++) {
            OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id" + i, false), new TestAuthentication("test", false));
            DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
            expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertNotNull(expectedOAuth2AccessToken);
        }
    }

    @Test
    public void testTokenCountConsistentWithExpiryQueue() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test", false));
        DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        for (int i = 0; i <= 10; i++) {
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertEquals(getTokenStore().getAccessTokenCount(), getTokenStore().getExpiryTokenCount());
            assertEquals(1, getTokenStore().getRefreshTokenCount());
        }
    }

    @Test
    public void testAutoFlush() {
        getTokenStore().setFlushInterval(3);
        assertEquals(3, getTokenStore().getFlushInterval());
        for (int i = 0; i <= 10; i++) {
            OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
                    RequestTokenFactory.createOAuth2Request("id" + i, false), new TestAuthentication("test", false));
            DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
            expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertNotNull(expectedOAuth2AccessToken);
        }
    }
}