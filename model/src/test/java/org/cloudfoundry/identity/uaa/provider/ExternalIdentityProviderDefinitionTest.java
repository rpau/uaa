package org.cloudfoundry.identity.uaa.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExternalIdentityProviderDefinitionTest {

    ExternalIdentityProviderDefinition definition;

    @BeforeEach
    public void createDefinition() {
        definition = new ExternalIdentityProviderDefinition();
    }

    @Test
    public void testEquals() {
        ExternalIdentityProviderDefinition definition1 = new ExternalIdentityProviderDefinition();
        definition1.setAddShadowUserOnLogin(true);
        ExternalIdentityProviderDefinition definition2 = new ExternalIdentityProviderDefinition();
        definition2.setAddShadowUserOnLogin(false);

        assertNotEquals(definition1, definition2);
        definition2.setAddShadowUserOnLogin(true);
        assertEquals(definition1, definition2);
    }

    @Test
    public void testDefaultValueForStoreCustomAttributes() {
        assertTrue(definition.isStoreCustomAttributes());
    }

    @Test
    public void testEquals2() {
        ExternalIdentityProviderDefinition def = new ExternalIdentityProviderDefinition();
        def.setStoreCustomAttributes(false);
        assertNotEquals(definition, def);
    }
}
