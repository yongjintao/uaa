package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class MfaUtilsMockMVC {

    public static MfaProvider<GoogleMfaProviderConfig> createGoogleMfaProvider(String zoneId, String adminToken, MockMvc mockMvc) throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = new MfaProvider().setName(new RandomValueStringGenerator(5).generate());
        MockHttpServletRequestBuilder createMfaRequest = post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .header("X-Identity-Zone-Id", zoneId)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider));
        MockHttpServletResponse mfaProviderResponse = mockMvc.perform(createMfaRequest).andReturn().getResponse();
        return JsonUtils.readValue(mfaProviderResponse.getContentAsString(), MfaProvider.class);
    }

    public static MfaProvider<GoogleMfaProviderConfig> createGoogleMfaProvider(String adminToken, MockMvc mockMvc) throws Exception {
        return createGoogleMfaProvider("uaa", adminToken, mockMvc);
    }
}
