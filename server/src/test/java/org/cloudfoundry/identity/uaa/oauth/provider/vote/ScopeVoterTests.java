package org.cloudfoundry.identity.uaa.oauth.provider.vote;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ScopeVoterTests {

    private final ScopeVoter voter = new ScopeVoter();

    @Test
    void testAbstainIfNotOAuth2() {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        assertEquals(
                AccessDecisionVoter.ACCESS_ABSTAIN,
                voter.vote(clientAuthentication, null,
                        Collections.singleton(new SecurityConfig("SCOPE_READ"))));
    }

    @Test
    void testDenyIfOAuth2AndExplictlyDenied() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertEquals(
                AccessDecisionVoter.ACCESS_DENIED,
                voter.vote(oAuth2Authentication, null,
                        Collections.singleton(new SecurityConfig("DENY_OAUTH"))));
    }

    @Test
    void testAccessGrantedIfScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertEquals(
                AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(oAuth2Authentication, null,
                        Collections.singleton(new SecurityConfig("SCOPE_READ"))));
    }

    @Test
    void testAccessGrantedIfScopesPresentWithPrefix() {
        voter.setScopePrefix("scope=");
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertEquals(
                AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(oAuth2Authentication, null,
                        Collections.singleton(new SecurityConfig("scope=read"))));
    }

    @Test
    void testAccessDeniedIfWrongScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        voter.setThrowException(false);
        assertEquals(
                AccessDecisionVoter.ACCESS_DENIED,
                voter.vote(oAuth2Authentication, null,
                        Collections.singleton(new SecurityConfig("SCOPE_WRITE"))));
    }

    @Test
    void testExceptionThrownIfWrongScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, null);
        voter.setDenyAccess("DENY_OAUTH");
        assertTrue(voter.supports(ScopeVoter.class));
        Set<ConfigAttribute> scopeWrite = Collections.singleton(new SecurityConfig("SCOPE_WRITE"));
        assertThrows(AccessDeniedException.class, () -> voter.vote(oAuth2Authentication, null, scopeWrite));
    }
}
