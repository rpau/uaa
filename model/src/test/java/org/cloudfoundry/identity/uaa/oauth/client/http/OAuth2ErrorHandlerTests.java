package org.cloudfoundry.identity.uaa.oauth.client.http;

import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResponseErrorHandler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2ErrorHandlerTests {

    @Mock
    private ClientHttpResponse response;

    private BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();

    private final class TestClientHttpResponse implements ClientHttpResponse {

        private final HttpHeaders headers;

        private final HttpStatus status;

        private final InputStream body;

        public TestClientHttpResponse(HttpHeaders headers, int status) {
            this(headers, status, new ByteArrayInputStream(new byte[0]));
        }

        public TestClientHttpResponse(HttpHeaders headers, int status, InputStream bodyStream) {
            this.headers = headers;
            this.status = HttpStatus.valueOf(status);
            this.body = bodyStream;
        }

        public InputStream getBody() throws IOException {
            return body;
        }

        public HttpHeaders getHeaders() {
            return headers;
        }

        public HttpStatus getStatusCode() throws IOException {
            return status;
        }

        public String getStatusText() throws IOException {
            return status.getReasonPhrase();
        }

        public int getRawStatusCode() throws IOException {
            return status.value();
        }

        public void close() {
        }
    }

    private OAuth2ErrorHandler handler;

    @BeforeEach
    public void setUp() throws Exception {
        handler = new OAuth2ErrorHandler(resource);

    }

    /**
     * test response with www-authenticate header
     */
    @Test
    public void testHandleErrorClientHttpResponse() {
        Throwable exception = assertThrows(Exception.class, () -> {

            HttpHeaders headers = new HttpHeaders();
            headers.set("www-authenticate", "Bearer error=foo");
            ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
            handler.handleError(response);

        });
        assertTrue(exception.getMessage().contains("401 Unauthorized"));

    }

    @Test
    public void testHandleErrorWithInvalidToken() {
        Throwable exception = assertThrows(AccessTokenRequiredException.class, () -> {

            HttpHeaders headers = new HttpHeaders();
            headers.set("www-authenticate", "Bearer error=\"invalid_token\", description=\"foo\"");
            ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
            handler.handleError(response);

        });
        assertTrue(exception.getMessage().contains("OAuth2 access denied"));

    }

    @Test
    public void testCustomHandler() {
        Throwable exception = assertThrows(Exception.class, () -> {

            OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {

                public boolean hasError(ClientHttpResponse response) throws IOException {
                    return true;
                }

                public void handleError(ClientHttpResponse response) throws IOException {
                    throw new RuntimeException("planned");
                }
            }, resource);

            HttpHeaders headers = new HttpHeaders();
            ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
            handler.handleError(response);

        });
        assertTrue(exception.getMessage().contains("planned"));

    }

    @Test
    public void testHandle500Error() {
        assertThrows(HttpServerErrorException.class, () -> {
            HttpHeaders headers = new HttpHeaders();
            ClientHttpResponse response = new TestClientHttpResponse(headers, 500);
            handler.handleError(response);
        });
    }

    @Test
    public void testHandleGeneric400Error() {
        assertThrows(HttpClientErrorException.class, () -> {
            HttpHeaders headers = new HttpHeaders();
            ClientHttpResponse response = new TestClientHttpResponse(headers, 400);
            handler.handleError(response);
        });
    }

    @Test
    public void testHandleGeneric403Error() {
        assertThrows(HttpClientErrorException.class, () -> {
            HttpHeaders headers = new HttpHeaders();
            ClientHttpResponse response = new TestClientHttpResponse(headers, 403);
            handler.handleError(response);
        });
    }

    @Test
    // See https://github.com/spring-projects/spring-security-oauth/issues/387
    public void testHandleGeneric403ErrorWithBody() {
        assertThrows(HttpClientErrorException.class, () -> {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            ClientHttpResponse response = new TestClientHttpResponse(headers, 403,
                    new ByteArrayInputStream("{}".getBytes()));
            handler = new OAuth2ErrorHandler(new DefaultResponseErrorHandler(), resource);
            handler.handleError(response);
        });
    }

    @Test
    public void testBodyCanBeUsedByCustomHandler() {
        Throwable exception = assertThrows(Exception.class, () -> {
            final String appSpecificBodyContent = "{\"some_status\":\"app error\"}";
            OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {
                public boolean hasError(ClientHttpResponse response) throws IOException {
                    return true;
                }

                public void handleError(ClientHttpResponse response) throws IOException {
                    InputStream body = response.getBody();
                    byte[] buf = new byte[appSpecificBodyContent.length()];
                    int readResponse = body.read(buf);
                    Assertions.assertEquals(buf.length, readResponse);
                    Assertions.assertEquals(appSpecificBodyContent, new String(buf, "UTF-8"));
                    throw new RuntimeException("planned");
                }
            }, resource);
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Length", "" + appSpecificBodyContent.length());
            headers.set("Content-Type", "application/json");
            InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
            ClientHttpResponse response = new TestClientHttpResponse(headers, 400, appSpecificErrorBody);
            handler.handleError(response);
        });
        assertTrue(exception.getMessage().contains("planned"));
    }

    @Test
    public void testHandleErrorWithMissingHeader() {
        assertThrows(HttpClientErrorException.class, () -> {

            final HttpHeaders headers = new HttpHeaders();
            when(response.getHeaders()).thenReturn(headers);
            when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);
            when(response.getBody()).thenReturn(new ByteArrayInputStream(new byte[0]));
            when(response.getStatusText()).thenReturn(HttpStatus.BAD_REQUEST.toString());
            handler.handleError(response);
        });
    }

    // gh-875
    @Test
    public void testHandleErrorWhenAccessDeniedMessageAndStatus400ThenThrowsUserDeniedAuthorizationException() {
        assertThrows(UserDeniedAuthorizationException.class, () -> {
            String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
            ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            ClientHttpResponse response = new TestClientHttpResponse(headers, 400, messageBody);
            handler.handleError(response);
        });
    }

    // gh-875
    @Test
    public void testHandleErrorWhenAccessDeniedMessageAndStatus403ThenThrowsOAuth2AccessDeniedException() {
        assertThrows(OAuth2AccessDeniedException.class, () -> {
            String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
            ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            ClientHttpResponse response = new TestClientHttpResponse(headers, 403, messageBody);
            handler.handleError(response);
        });
    }

    @Test
    public void testHandleMessageConversionExceptions() {
        assertThrows(HttpClientErrorException.class, () -> {
            HttpMessageConverter<?> extractor = new HttpMessageConverter() {
                @Override
                public boolean canRead(Class clazz, MediaType mediaType) {
                    return true;
                }

                @Override
                public boolean canWrite(Class clazz, MediaType mediaType) {
                    return false;
                }

                @Override
                public List<MediaType> getSupportedMediaTypes() {
                    return null;
                }

                @Override
                public Object read(Class clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
                    throw new HttpMessageConversionException("error");
                }

                @Override
                public void write(Object o, MediaType contentType, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {

                }
            };

            ArrayList<HttpMessageConverter<?>> messageConverters = new ArrayList<>();
            messageConverters.add(extractor);
            handler.setMessageConverters(messageConverters);

            HttpHeaders headers = new HttpHeaders();
            final String appSpecificBodyContent = "This user is not authorized";
            InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
            ClientHttpResponse response = new TestClientHttpResponse(headers, 401, appSpecificErrorBody);
            handler.handleError(response);
        });
    }
}
