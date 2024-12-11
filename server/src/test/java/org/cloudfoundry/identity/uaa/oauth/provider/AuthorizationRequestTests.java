package org.cloudfoundry.identity.uaa.oauth.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class AuthorizationRequestTests {

    private AuthorizationRequest authorizationRequest;
    private AuthorizationRequest authorizationRequest2;

    @BeforeEach
    public void setUp() throws Exception {
        authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setAuthorities(Collections.emptyList());
        authorizationRequest2 = new AuthorizationRequest(Map.of("client_id", "id"), "id", Set.of("scope"), Set.of("resourceIds"),
                AuthorityUtils.createAuthorityList("scope", "authorities"), true, "state", "redirect:uri", Set.of("code"));
    }

    @Test
    public void testHashCode() {
        assertEquals(authorizationRequest.hashCode(), authorizationRequest.hashCode());
        assertNotEquals(authorizationRequest2.hashCode(), authorizationRequest.hashCode());
    }

    @Test
    public void testEquals() {
        assertEquals(authorizationRequest, authorizationRequest);
        assertNotEquals(authorizationRequest2, authorizationRequest);
        assertNotEquals(authorizationRequest2, new AuthorizationRequest(Map.of("client_id", "id"), "id", Set.of("scope"), Set.of("resourceIds"),
                AuthorityUtils.createAuthorityList("scope", "authorities"), false, "xxx", "redirect:uri", Set.of("code")));
    }
}
