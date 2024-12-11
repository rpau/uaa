package org.cloudfoundry.identity.uaa.logging;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LogSanitizerUtilTest {

    @Test
    public void testSanitizeInput() {
        assertEquals("one|two|three|four[SANITIZED]",
                LogSanitizerUtil.sanitize("one\ntwo\tthree\rfour"));
    }

    @Test
    public void testSanitizeCleanInput() {
        assertEquals("one two three four",
                LogSanitizerUtil.sanitize("one two three four"));
    }

    @Test
    public void testSanitizeNull() {
        assertEquals(null,
                LogSanitizerUtil.sanitize(null));
    }
}