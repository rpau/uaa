package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class AuthTimeDateConverterTest {
    @Test
    public void authTimeToDate_whenNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(null);
        assertNull(date);
    }

    @Test
    public void authTimeToDate_whenNotNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(1L);
        assertEquals(new Date(1000L), date);
    }

    @Test
    public void dateToAuthTime_whenNull() {
        Long authTime = AuthTimeDateConverter.dateToAuthTime(null);
        assertNull(authTime);
    }

    @Test
    public void dateToAuthTime_whenNotNull() {
        long authTime = AuthTimeDateConverter.dateToAuthTime(new Date(1000L));
        assertEquals(1, authTime);
    }
}