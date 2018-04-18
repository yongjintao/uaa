package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Assert;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Map;

public class IdentityZoneUtils {
    public static IdentityZone getZone(String adminToken, String baseUrl, String zoneId) {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.set("Authorization", "bearer " + adminToken);

        ResponseEntity<IdentityZone> response = template.exchange(
            baseUrl + "/identity-zones/" + zoneId,
            HttpMethod.GET,
            new HttpEntity(headers),
            IdentityZone.class);

        return response.getBody();
    }


    public static IdentityZone createZone(String adminToken,
                                          String url,
                                          String id,
                                          String subdomain,
                                          IdentityZoneConfiguration config) {

        RestTemplate restTemplate = new RestTemplate();
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setId(id);
        identityZone.setName(id);
        identityZone.setConfig(config);

        MultiValueMap<String, String> headers = IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, null);
        HttpEntity<IdentityZone> request = new HttpEntity<>(identityZone, headers);

        ResponseEntity<IdentityZone> zone = restTemplate.postForEntity(url + "/identity-zones", request, IdentityZone.class);
        return zone.getBody();
    }

    public static void deleteZone(String adminToken,
                                  String url,
                                  String id) {

        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers = IntegrationTestUtils.createHeadersWithTokenAndZone(adminToken, null);
        HttpEntity<IdentityZone> request = new HttpEntity<>(headers);

        restTemplate.exchange(url + "/identity-zones/{id}", HttpMethod.DELETE, request, String.class, id);
    }

    public static void deleteZoneIfExists(String adminToken,
                                          String url,
                                          String id) {
        try {
            deleteZone(adminToken, url, id);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                // ok to "fail" to delete entities that don't exist
            } else {
                throw e;
            }
        }
    }
}