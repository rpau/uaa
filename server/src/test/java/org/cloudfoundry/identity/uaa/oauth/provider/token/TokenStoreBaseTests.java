package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public abstract class TokenStoreBaseTests {

    public abstract TokenStore getTokenStore();

    @Test
    public void readingAuthenticationForTokenThatDoesNotExist() {
        assertThat(getTokenStore().readAuthentication("tokenThatDoesNotExist")).isNull();
    }

    @Test
    public void storeAccessToken() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
        assertThat(actualOAuth2AccessToken).isEqualTo(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken)).isEqualTo(expectedAuthentication);
        getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
        getTokenStore().removeAccessTokenUsingRefreshToken(new DefaultOAuth2RefreshToken("testToken"));
        assertThat(getTokenStore().readAccessToken("testToken")).isNull();
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue())).isNull();
    }

    @Test
    public void storeAccessTokenTwice() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
                RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
        assertThat(actualOAuth2AccessToken).isEqualTo(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken)).isEqualTo(expectedAuthentication);
        getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAccessToken("testToken")).isNull();
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue())).isNull();
    }

    @Test
    public void retrieveAccessToken() {
        //Test approved request
        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", true);
        OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test2", true));
        DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        expectedOAuth2AccessToken.setExpiration(new Date(Long.MAX_VALUE - 1));
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, authentication);

        //Test unapproved request
        storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
        authentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test2", true));
        OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().getAccessToken(authentication);
        assertThat(actualOAuth2AccessToken).isEqualTo(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getUserAuthentication()).isEqualTo(authentication.getUserAuthentication());
        // The authorizationRequest does not match because it is unapproved, but the token was granted to an approved request
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getOAuth2Request()).isNotEqualTo(storedOAuth2Request);
        actualOAuth2AccessToken = getTokenStore().getAccessToken(authentication);
        assertThat(actualOAuth2AccessToken).isEqualTo(expectedOAuth2AccessToken);
        getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAccessToken("testToken")).isNull();
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue())).isNull();
        assertThat(getTokenStore().getAccessToken(authentication)).isNull();
    }

    @Test
    public void findAccessTokensByClientIdAndUserName() {
        String clientId = "id" + UUID.randomUUID();
        String name = "test2" + UUID.randomUUID();
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(clientId, false), new TestAuthentication(name, false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByClientIdAndUserName(clientId, name);
        assertThat(actualOAuth2AccessTokens).hasSize(1);
    }

    @Test
    public void findAccessTokensByClientId() {
        String clientId = "id" + UUID.randomUUID();
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(clientId, false), new TestAuthentication("test2", false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByClientId(clientId);
        assertThat(actualOAuth2AccessTokens).hasSize(1);
    }

    @Test
    public void readingAccessTokenForTokenThatDoesNotExist() {
        assertThat(getTokenStore().readAccessToken("tokenThatDoesNotExist")).isNull();
    }

    @Test
    public void refreshTokenIsNotStoredDuringAccessToken() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        expectedOAuth2AccessToken.setRefreshToken(new DefaultOAuth2RefreshToken("refreshToken"));
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
        assertThat(actualOAuth2AccessToken.getRefreshToken()).isNotNull();

        assertThat(getTokenStore().readRefreshToken("refreshToken")).isNull();
    }

    @Test
    /**
     * NB: This used to test expiring refresh tokens. That test has been moved to sub-classes since not all stores support the functionality
     */
    public void storeRefreshToken() {
        String refreshToken = "testToken" + UUID.randomUUID();
        DefaultOAuth2RefreshToken expectedRefreshToken = new DefaultOAuth2RefreshToken(refreshToken);
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        getTokenStore().storeRefreshToken(expectedRefreshToken, expectedAuthentication);

        OAuth2RefreshToken actualExpiringRefreshToken = getTokenStore().readRefreshToken(refreshToken);
        assertThat(actualExpiringRefreshToken).isEqualTo(expectedRefreshToken);
        assertThat(getTokenStore().readAuthenticationForRefreshToken(expectedRefreshToken)).isEqualTo(expectedAuthentication);
        getTokenStore().removeRefreshToken(expectedRefreshToken);
        assertThat(getTokenStore().readRefreshToken(refreshToken)).isNull();
        assertThat(getTokenStore().readAuthentication(expectedRefreshToken.getValue())).isNull();
    }

    @Test
    public void readingRefreshTokenForTokenThatDoesNotExist() {
        assertThat(getTokenStore().readRefreshToken("tokenThatDoesNotExist")).isNull();
    }

    @Test
    public void getAccessTokenForDeletedUser() throws Exception {
        //Test approved request
        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", true);
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test", true));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
        assertThat(getTokenStore().getAccessToken(expectedAuthentication)).isEqualTo(expectedOAuth2AccessToken);
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue())).isEqualTo(expectedAuthentication);

        //Test unapproved request
        storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
        OAuth2Authentication anotherAuthentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test", true));
        assertThat(getTokenStore().getAccessToken(anotherAuthentication)).isEqualTo(expectedOAuth2AccessToken);
        // The generated key for the authentication is the same as before, but the two auths are not equal. This could
        // happen if there are 2 users in a system with the same username, or (more likely), if a user account was
        // deleted and re-created.
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getUserAuthentication()).isEqualTo(anotherAuthentication.getUserAuthentication());
        // The authorizationRequest does not match because it is unapproved, but the token was granted to an approved request
        assertThat(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getOAuth2Request()).isNotEqualTo(storedOAuth2Request);
    }

    @Test
    public void removeRefreshToken() {
        OAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken("testToken",
                new Date());
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        getTokenStore().storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
        getTokenStore().removeRefreshToken(expectedExpiringRefreshToken);

        assertThat(getTokenStore().readRefreshToken("testToken")).isNull();
    }

    @Test
    public void removedTokenCannotBeFoundByUsername() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("testToken");
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
                "id", false), new TestAuthentication("test2", false));
        getTokenStore().storeAccessToken(token, expectedAuthentication);
        getTokenStore().removeAccessToken(token);
        Collection<OAuth2AccessToken> tokens = getTokenStore().findTokensByClientIdAndUserName("id", "test2");
        assertThat(tokens).doesNotContain(token);
        assertThat(tokens).isEmpty();
    }

    protected static class TestAuthentication extends AbstractAuthenticationToken {

        private static final long serialVersionUID = 1L;
        private String principal;

        public TestAuthentication(String name, boolean authenticated) {
            super(null);
            setAuthenticated(authenticated);
            this.principal = name;
        }

        public Object getCredentials() {
            return null;
        }

        public Object getPrincipal() {
            return this.principal;
        }
    }

}
