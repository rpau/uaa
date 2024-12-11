package org.cloudfoundry.identity.uaa.provider;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;


public class KeystoneIdentityProviderDefinitionTest {

    @Test
    public void testEquals() {
        KeystoneIdentityProviderDefinition kipd1 = new KeystoneIdentityProviderDefinition();
        kipd1.setAddShadowUserOnLogin(true);
        KeystoneIdentityProviderDefinition kipd2 = new KeystoneIdentityProviderDefinition();
        kipd2.setAddShadowUserOnLogin(false);
        assertNotEquals(kipd1, kipd2);

        kipd2.setAddShadowUserOnLogin(true);
        assertEquals(kipd1, kipd2);
    }
}
