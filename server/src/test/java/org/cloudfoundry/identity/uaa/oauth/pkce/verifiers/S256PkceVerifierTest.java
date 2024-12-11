package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Zoltan Maradics
 */
class S256PkceVerifierTest {

    private S256PkceVerifier s256CodeChallengeMethod;

    private final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @BeforeEach
    void createS256CodeChallengeMethod() throws Exception {
        s256CodeChallengeMethod = new S256PkceVerifier();
    }

    @Test
    void codeVerifierMethodWithMatchParameters() throws Exception {
        assertThat(s256CodeChallengeMethod.verify(validCodeVerifier, validCodeChallenge)).isTrue();
    }

    @Test
    void codeVerifierMethodWithMismatchParameters() throws Exception {
        assertThat(s256CodeChallengeMethod.verify(validCodeVerifier, validCodeVerifier)).isFalse();
    }

    @Test
    void codeChallengeIsNull() throws Exception {
        assertThat(s256CodeChallengeMethod.verify(validCodeVerifier, null)).isFalse();
    }

    @Test
    void codeVerifierIsNull() throws Exception {
        assertThat(s256CodeChallengeMethod.verify(null, validCodeChallenge)).isFalse();
    }

}
