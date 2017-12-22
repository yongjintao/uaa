package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest.getWebApplicationContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MfaUtilsMockMVC {

    public static void disableMfaProviderInZone(String zoneId) throws Exception {
        IdentityZoneConfiguration uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), zoneId);
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), zoneId, uaaZoneConfig);
    }

    public static void enableMfaProviderInZone(String zoneId, String providerName) throws Exception {
        IdentityZoneConfiguration uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), zoneId);
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(providerName);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), zoneId, uaaZoneConfig);
    }

    public static MfaProvider<GoogleMfaProviderConfig> createGoogleMfaProvider(String zoneId, String adminToken, MockMvc mockMvc) throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = new MfaProvider().setName(new RandomValueStringGenerator(5).generate());
        MockHttpServletRequestBuilder createMfaRequest = post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .header("X-Identity-Zone-Id", zoneId)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider));
        MockHttpServletResponse mfaProviderResponse = mockMvc.perform(createMfaRequest).andReturn().getResponse();
        assertEquals(HttpStatus.CREATED.value(), mfaProviderResponse.getStatus());
        return JsonUtils.readValue(mfaProviderResponse.getContentAsString(), MfaProvider.class);
    }

    public static MfaProvider<GoogleMfaProviderConfig> createGoogleMfaProvider(String adminToken, MockMvc mockMvc) throws Exception {
        return createGoogleMfaProvider("uaa", adminToken, mockMvc);
    }

    public static String performMfaPostVerifyWithCode(MockMvc mvc, MockHttpSession session) throws Exception {
        int code = MockMvcUtils.getMFACodeFromSession(session);
        return performMfaPostVerifyWithCode(code, mvc, session, "localhost");
    }

    public static String performMfaPostVerifyWithCode(int code, MockMvc mvc, MockHttpSession session, String host) throws Exception {
        return mvc.perform(post("/login/mfa/verify.do")
                .param("code", Integer.toString(code))
                .header("Host", host)
                .session(session)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/mfa/completed"))
                .andReturn().getResponse().getRedirectedUrl();
    }
}
