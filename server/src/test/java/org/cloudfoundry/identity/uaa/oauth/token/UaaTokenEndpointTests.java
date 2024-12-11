package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

class UaaTokenEndpointTests {

    private UaaTokenEndpoint endpoint;

    private ResponseEntity mockResponseEntity;

    @BeforeEach
    void setup() {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, null));
        mockResponseEntity = mock(ResponseEntity.class);
    }

    @Test
    void allowsGetByDefault() throws Exception {
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void getIsDisabled() throws Exception {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, false));
        ResponseEntity response = mock(ResponseEntity.class);
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        assertThatExceptionOfType(HttpRequestMethodNotSupportedException.class).isThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap()));
    }

    @Test
    void postAllowsQueryStringByDefault() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("some-parameter=some-value");
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegatePost(mock(Principal.class), emptyMap(), request);
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void setAllowedRequestMethods() {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertThat(methods).isNotNull();
        assertThat(methods).hasSize(2);
        assertThat(methods).containsExactlyInAnyOrder(POST, GET);
    }

    @Test
    void callToGetAlwaysThrowsSuperMethod() {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.getAccessToken(mock(Principal.class), emptyMap()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }

    @Test
    void callToGetAlwaysThrowsOverrideMethod() {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }
}