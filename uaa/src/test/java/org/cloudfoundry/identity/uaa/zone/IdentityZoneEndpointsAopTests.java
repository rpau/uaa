package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DefaultTestContext
class IdentityZoneEndpointsAopTests {

    @Autowired
    private IdentityZoneEndpoints identityZoneEndpoints;

    @Test
    void updateIdentityZone_WithObject() {
        assertThatThrownBy(() -> identityZoneEndpoints.updateIdentityZone(IdentityZone.getUaa(), null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void updateIdentityZone_WithId() {
        assertThatThrownBy(() -> identityZoneEndpoints.updateIdentityZone(null, IdentityZone.getUaaZoneId()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void createClient() {
        assertThatThrownBy(() -> identityZoneEndpoints.createClient(IdentityZone.getUaaZoneId(), null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void deleteClient() {
        assertThatThrownBy(() -> identityZoneEndpoints.deleteClient(IdentityZone.getUaaZoneId(), null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }
}
