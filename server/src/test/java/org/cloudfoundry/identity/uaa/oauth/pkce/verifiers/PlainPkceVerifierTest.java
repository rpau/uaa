package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Zoltan Maradics
 */
class PlainPkceVerifierTest {

    private PlainPkceVerifier plainPkceVerifier;

    private final String matchParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String mismatchParameter = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @BeforeEach
    void createPlainCodeChallengeMethod() throws Exception {
        plainPkceVerifier = new PlainPkceVerifier();
    }

    @Test
    void codeVerifierMethodWithMatchParameters() throws Exception {
        assertThat(plainPkceVerifier.verify(matchParameter, matchParameter)).isTrue();
    }

    @Test
    void codeVerifierMethodWithMismatchParameters() throws Exception {
        assertThat(plainPkceVerifier.verify(matchParameter, mismatchParameter)).isFalse();
    }

    @Test
    void codeChallengeIsNull() throws Exception {
        assertThat(plainPkceVerifier.verify(matchParameter, null)).isFalse();
    }

    @Test
    void codeVerifierIsNull() throws Exception {
        assertThat(plainPkceVerifier.verify(null, matchParameter)).isFalse();
    }

}
