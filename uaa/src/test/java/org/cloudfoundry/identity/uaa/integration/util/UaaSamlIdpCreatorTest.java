package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class UaaSamlIdpCreatorTest {
    private static final String IDP_ZONE = "idp";
    private static final String SP_ZONE = "sp";
    public static final String ADMIN_CLIENT_SECRET = "adminsecret";

    @Value("${integration.test.base_url}")
    private String baseUrl;

    private UaaSamlIdpCreator uaaSamlIdpCreator;
    private String adminToken;

    @Before
    public void setup() throws Exception {
        adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", ADMIN_CLIENT_SECRET);
        uaaSamlIdpCreator = new UaaSamlIdpCreator(adminToken, baseUrl, IDP_ZONE, SP_ZONE);
        uaaSamlIdpCreator.cleanup();
    }

    @After
    public void cleanup() {
        uaaSamlIdpCreator.cleanup();
    }

    @Test
    public void create_createsSpAndIdpZones() {
        uaaSamlIdpCreator.create();

        IdentityZone createdZone = IdentityZoneUtils.getZone(adminToken, baseUrl, SP_ZONE);
        assertNotNull(createdZone);
        IdentityZone createdZone2 = IdentityZoneUtils.getZone(adminToken, baseUrl, IDP_ZONE);
        assertNotNull(createdZone2);
    }

    @Test
    public void create_registersIdentityProviderInSpZone() {
        uaaSamlIdpCreator.create();

        IdentityProvider identityProvider =
            IdentityProviderUtils.getIdentityProviderByOriginKey(adminToken, baseUrl, SP_ZONE, IDP_ZONE);
        assertNotNull(identityProvider);
        assertEquals(identityProvider.getType(), "saml");
    }

    @Test
    public void create_registersServiceProviderInIdpZone() {
        uaaSamlIdpCreator.create();

        SamlServiceProvider serviceProvider =
            IdentityProviderUtils.getServiceProviderByName(adminToken, baseUrl, IDP_ZONE, SP_ZONE);
        assertNotNull(serviceProvider);
    }

    @Test
    public void createUserInIdpZone_createsUser() {
        String username = "marissa";

        uaaSamlIdpCreator.create();
        ScimUser createdUser = uaaSamlIdpCreator.createUserInIdpZone(username);

        ScimUser user = UserUtils.getUserById(adminToken, baseUrl, IDP_ZONE, createdUser.getId());
        assertNotNull(user);
        assertEquals(username, user.getUserName());
    }
}