package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.config.IdentityZoneConfigurationBootstrapTests.PRIVATE_KEY;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenValidationServiceTest {
    private TokenValidationService tokenValidationService;
    private UaaUserDatabase userDatabase;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private MultitenantClientServices mockMultitenantClientServices;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private Map<String, Object> header;
    private JWSSigner signer;
    private final String userId = "asdf-bfdsajk-asdfjsa";
    private final String clientId = "myclient";
    private Map<String, Object> content;

    @BeforeEach
    public void setup() throws ParseException, JOSEException {
        header = map(
                entry("alg", "RS256"),
                entry("kid", "key1"),
                entry("typ", "JWT")
        );
        content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg"),
                entry(CID, clientId),
                entry(SCOPE, Lists.newArrayList("foo.bar"))
        );
        signer = new KeyInfo(null, PRIVATE_KEY, DEFAULT_UAA_URL).getSigner();
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("key1", PRIVATE_KEY));

        userDatabase = mock(UaaUserDatabase.class);
        tokenEndpointBuilder = mock(TokenEndpointBuilder.class);
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId())).thenReturn(new UaaClientDetails(clientId, null, "foo.bar", null, null));
        UaaUser user = new UaaUser(userId, "marrisa", "koala", "marissa@gmail.com", buildGrantedAuthorities("foo.bar"), "Marissa", "Bloggs", null, null, null, null, true, null, null, null);
        when(userDatabase.retrieveUserById(userId)).thenReturn(user);

        tokenValidationService = new TokenValidationService(
                revocableTokenProvisioning,
                tokenEndpointBuilder,
                userDatabase,
                mockMultitenantClientServices,
                new KeyInfoService(DEFAULT_UAA_URL)
        );
    }

    @AfterEach
    public void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void validation_happyPath() {
        String accessToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(accessToken, true);
    }

    @Test
    public void validation_enforcesKeyId() {
        Throwable exception = assertThrows(InvalidTokenException.class, () -> {

            header.put("kid", "testKey");

            String accessToken = UaaTokenUtils.constructToken(header, content, signer);

            tokenValidationService.validateToken(accessToken, true);
        });
        assertTrue(exception.getMessage().contains("Token header claim [kid] references unknown signing key : [testKey]"));
    }

    @Test
    public void validationFails_whenUserNotFound() {
        Throwable exception = assertThrows(InvalidTokenException.class, () -> {

            when(userDatabase.retrieveUserById(userId)).thenThrow(UsernameNotFoundException.class);
            String accessToken = UaaTokenUtils.constructToken(header, content, signer);

            tokenValidationService.validateToken(accessToken, true);
        });
        assertTrue(exception.getMessage().contains("Token bears a non-existent user ID: " + userId));
    }

    @Test
    public void validationFails_whenClientNotFound() {
        Throwable exception = assertThrows(InvalidTokenException.class, () -> {

            when(mockMultitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId())).thenThrow(NoSuchClientException.class);
            String accessToken = UaaTokenUtils.constructToken(header, content, signer);

            tokenValidationService.validateToken(accessToken, true);
        });
        assertTrue(exception.getMessage().contains("Invalid client ID " + clientId));
    }

    @Test
    public void refreshToken_validatesWithScopeClaim_forBackwardsCompatibilityReasons() {
        Map<String, Object> content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg-r"),
                entry(CID, clientId),
                entry(SCOPE, Lists.newArrayList("foo.bar"))
        );
        String refreshToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(refreshToken, false);
    }

    @Test
    public void refreshToken_validatesWithGrantedScopesClaim() {
        Map<String, Object> content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg-r"),
                entry(CID, clientId),
                entry(GRANTED_SCOPES, Lists.newArrayList("foo.bar"))
        );
        String refreshToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(refreshToken, false);
    }

    private ArrayList<GrantedAuthority> buildGrantedAuthorities(String authority) {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(UaaAuthority.authority(authority));
        return grantedAuthorities;
    }
}