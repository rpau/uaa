package org.cloudfoundry.identity.uaa.oauth;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaOauth2ErrorHandlerTests {


    private final Map<HttpStatus, ClientHttpResponse> responses = new HashMap<>();
    private UaaOauth2ErrorHandler handler;

    @BeforeEach
    public void setUp() throws Exception {
        handler = new UaaOauth2ErrorHandler(null);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse r = mock(ClientHttpResponse.class);
            when(r.getStatusCode()).thenReturn(status);
            responses.put(status, r);
        }
    }

    @Test
    public void test500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError()) {
                Assertions.assertTrue(handler.hasError(response));
            } else {
                Assertions.assertFalse(handler.hasError(response));
            }
        }
    }

    @Test
    public void test400_500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError() || status.is4xxClientError()) {
                Assertions.assertTrue(handler.hasError(response));
            } else {
                Assertions.assertFalse(handler.hasError(response));
            }
        }
    }

    @Test
    public void testSetErrorLevel() {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        Assertions.assertEquals(HttpStatus.Series.SERVER_ERROR, handler.getErrorAtLevel());
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        Assertions.assertEquals(HttpStatus.Series.CLIENT_ERROR, handler.getErrorAtLevel());
    }

    @Test
    public void testSetErrorLevelThroughConstructor() {
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.SERVER_ERROR);
        Assertions.assertEquals(HttpStatus.Series.SERVER_ERROR, handler.getErrorAtLevel());
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.CLIENT_ERROR);
        Assertions.assertEquals(HttpStatus.Series.CLIENT_ERROR, handler.getErrorAtLevel());
    }

}