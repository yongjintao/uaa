package org.cloudfoundry.identity.uaa.integration.util;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.junit.Assert.assertTrue;

public class UaaSamlIdpCreator implements SamlIdentityProviderCreator {
    private final String adminToken;
    private String uaaBaseUrl;
    private final String idpZone;
    private final String spZone;

    public static SamlIdentityProviderCreator createUaaZoneAndReturnCreator(RestTemplate client,
                                                                            String url,
                                                                            String idpZone,
                                                                            String spZone) {
        return new UaaSamlIdpCreator("foo", url, idpZone, spZone);
    }

    public UaaSamlIdpCreator(String adminToken, String uaaBaseUrl, String idpZone, String spZone) {
        this.adminToken = adminToken;
        this.uaaBaseUrl = uaaBaseUrl;
        this.idpZone = idpZone;
        this.spZone = spZone;
    }

    private void createZones(String adminToken, String url) {
        IdentityZoneUtils.createZone(adminToken, url, idpZone, idpZone, new IdentityZoneConfiguration());
        IdentityZoneUtils.createZone(adminToken, url, spZone, spZone, new IdentityZoneConfiguration());
    }

    public void create() {
        createZones(adminToken, uaaBaseUrl);
        registerIdentityProvider();
        registerServiceProvider();
    }

    private void registerServiceProvider() {
        SamlIntegrationTestUtils.createServiceProvider(adminToken, uaaBaseUrl, "notused", spZone, idpZone);
    }

    @Override
    public IdentityProvider<SamlIdentityProviderDefinition> registerIdentityProvider() {
        assertTrue("The localhost subdomain " + spZone + " must be present in /etc/hosts",
            doesSupportZoneDNS(Lists.newArrayList(spZone + ".localhost")));

        return SamlIntegrationTestUtils.createUaaSamlIdentityProvider(idpZone, uaaBaseUrl, idpZone, spZone);
    }

    public void cleanup() {
        IdentityProviderUtils.deleteServiceProviderByNameIfExists(adminToken, uaaBaseUrl, idpZone, spZone);
        IdentityZoneUtils.deleteZoneIfExists(adminToken, uaaBaseUrl, idpZone);
        IdentityZoneUtils.deleteZoneIfExists(adminToken, uaaBaseUrl, spZone);
    }

    public ScimUser createUserInIdpZone(String username) {
        return UserUtils.createUser(
            adminToken, uaaBaseUrl, username, username, username, username + "@test.org", true, idpZone
        );
    }
}
