package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LegacyTokenKeyTest {

    @Test
    public void shouldBuildLegacyTokenKey_withSecureKeyUrl() {
        LegacyTokenKey.setLegacySigningKey("secret", "http://uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        assertThat(legacyTokenKeyInfo.keyURL(), is("https://uaa.url/token_keys"));
    }

    @Test
    public void shouldBuildLegacyTokenKey() {
        LegacyTokenKey.setLegacySigningKey("secret", "https://another.uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        assertThat(legacyTokenKeyInfo.keyURL(), is("https://another.uaa.url/token_keys"));
    }

    @Test
    public void buildLegacyTokenKey_withInvalidKeyUrl() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->

                LegacyTokenKey.setLegacySigningKey("secret", "not a valid url"));
        assertTrue(exception.getMessage().contains("Invalid Key URL"));
    }

}