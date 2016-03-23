package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;

@Component
public class AzureRequestEnhancerCustomizer {
    @Autowired
    private OAuth2RestTemplate userInfoRestTemplate;

    @Autowired
    private AzureRequestEnhancer azureRequestEnhancer;

    @PostConstruct
    public void testWiring() {
        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
        authorizationCodeAccessTokenProvider.setTokenRequestEnhancer(azureRequestEnhancer);
        userInfoRestTemplate.setAccessTokenProvider(authorizationCodeAccessTokenProvider);
    }
}


