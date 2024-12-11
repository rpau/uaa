package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Zoltan Maradics
 */
public class S256PkceVerifierTest {

    private S256PkceVerifier s256CodeChallengeMethod;

    private final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @BeforeEach
    public void createS256CodeChallengeMethod() throws Exception {
        s256CodeChallengeMethod = new S256PkceVerifier();
    }

    @Test
    public void testCodeVerifierMethodWithMatchParameters() throws Exception {
        assertTrue(s256CodeChallengeMethod.verify(validCodeVerifier, validCodeChallenge));
    }

    @Test
    public void testCodeVerifierMethodWithMismatchParameters() throws Exception {
        assertFalse(s256CodeChallengeMethod.verify(validCodeVerifier, validCodeVerifier));
    }

    @Test
    public void testCodeChallengeIsNull() throws Exception {
        assertFalse(s256CodeChallengeMethod.verify(validCodeVerifier, null));
    }

    @Test
    public void testCodeVerifierIsNull() throws Exception {
        assertFalse(s256CodeChallengeMethod.verify(null, validCodeChallenge));
    }

}
