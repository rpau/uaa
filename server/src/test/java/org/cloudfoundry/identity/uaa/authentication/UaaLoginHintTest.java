package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class UaaLoginHintTest {

    @Test
    public void testParseHintNull() {
        assertNull(UaaLoginHint.parseRequestParameter(null));
    }

    @Test
    public void testParseHintOrigin() {
        UaaLoginHint hint = UaaLoginHint.parseRequestParameter("{\"origin\":\"ldap\"}");
        assertNotNull(hint);
        assertEquals("ldap", hint.getOrigin());
    }
}
