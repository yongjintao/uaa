package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class IdentityProviderUtils {
    public static IdentityProvider getIdentityProviderByOriginKey(String adminToken,
                                                                  String uaaUrl,
                                                                  String zoneSubdomain,
                                                                  String originKey) {

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        ResponseEntity<IdentityProvider[]> response =
            restTemplate.exchange(uaaUrl + "/identity-providers", HttpMethod.GET, request, IdentityProvider[].class);

        IdentityProvider[] providers = response.getBody();
        for (IdentityProvider provider : providers) {
            if (provider.getOriginKey().equalsIgnoreCase(originKey)) {
                return provider;
            }
        }
        return null;
    }

    public static SamlServiceProvider getServiceProviderByName(String adminToken,
                                                               String uaaUrl,
                                                               String zoneSubdomain,
                                                               String spName) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        ResponseEntity<SamlServiceProvider[]> response =
            restTemplate.exchange(uaaUrl + "/saml/service-providers", HttpMethod.GET, request, SamlServiceProvider[].class);

        SamlServiceProvider[] providers = response.getBody();
        for (SamlServiceProvider provider : providers) {
            if (provider.getName().equalsIgnoreCase(spName)) {
                return provider;
            }
        }
        return null;
    }

    public static void deleteServiceProviderById(String adminToken, String uaaUrl, String zoneSubdomain, String spId) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers =
            IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, zoneSubdomain);
        HttpEntity request = new HttpEntity(headers);

        restTemplate.exchange(uaaUrl + "/saml/service-providers/{id}", HttpMethod.DELETE, request, String.class, spId);
    }

    public static void deleteServiceProviderByName(String adminToken, String uaaUrl, String zoneSubdomain, String spName) {
        String id = getServiceProviderByName(adminToken, uaaUrl, zoneSubdomain, spName).getId();
        deleteServiceProviderById(adminToken, uaaUrl, zoneSubdomain, id);
    }

    public static void deleteServiceProviderByNameIfExists(String adminToken, String uaaUrl, String zoneSubdomain, String spName) {
        try {
            deleteServiceProviderByName(adminToken, uaaUrl, zoneSubdomain, spName);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                // ok to "fail" to delete entities that don't exist
            } else {
                throw e;
            }
        }
    }
}
