package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class ClientAuthenticationSuccessEventTest {

    @Test
    void getAuditEvent() {
        UaaAuthenticationDetails authDetails = mock(UaaAuthenticationDetails.class);
        Authentication authentication = mock(Authentication.class);
        doReturn(authDetails).when(authentication).getDetails();
        doReturn("method").when(authDetails).getAuthenticationMethod();
        doReturn("clientid").when(authDetails).getClientId();
        ClientAuthenticationSuccessEvent event = new ClientAuthenticationSuccessEvent(authentication, "uaa");
        assertNotNull(event.getAuditEvent());
        assertTrue(event.toString().contains("Mock for Authentication"));
    }
}
