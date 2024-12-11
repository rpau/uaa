package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class RandomValueStringGeneratorTests {

    private RandomValueStringGenerator generator;

    @BeforeEach
    public void setup() {
        generator = new RandomValueStringGenerator();
    }

    @Test
    public void generate() {
        String value = generator.generate();
        assertNotNull(value);
        assertEquals(6, value.length(), "Authorization code is not correct size");
    }

    @Test
    public void generate_LargeLengthOnConstructor() {
        generator = new RandomValueStringGenerator(1024);
        String value = generator.generate();
        assertNotNull(value);
        assertEquals(1024, value.length(), "Authorization code is not correct size");
    }

    @Test
    public void getAuthorizationCodeString() {
        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        String value = generator.getAuthorizationCodeString(bytes);
        assertNotNull(value);
        assertEquals(10, value.length(), "Authorization code is not correct size");
    }

    @Test
    public void setLength() {
        generator.setLength(12);
        String value = generator.generate();
        assertEquals(12, value.length(), "Authorization code is not correct size");
    }

    @Test
    public void setLength_NonPositiveNumber() {
        assertThrows(IllegalArgumentException.class, () -> {
            generator.setLength(-1);
            generator.generate();
        });
    }

    @Test
    public void setRandom() {
        generator.setRandom(new SecureRandom());
        generator.setLength(12);
        String value = generator.generate();
        assertEquals(12, value.length(), "Authorization code is not correct size");
    }

    @Test
    public void setCodec() {
        generator = new RandomValueStringGenerator("0123456789".toCharArray());
        String value = generator.generate();
        assertFalse(value.contains("A"));
    }
}