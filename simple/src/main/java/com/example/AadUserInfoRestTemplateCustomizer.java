package com.example;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import java.io.IOException;
import java.util.Arrays;

public class AadUserInfoRestTemplateCustomizer implements UserInfoRestTemplateCustomizer {
    @Override
    public void customize(OAuth2RestTemplate oAuth2RestTemplate) {

        // no help here
        // by the time the authenticator is called, the token has already been retrieved
        oAuth2RestTemplate.setAuthenticator(new AadOauth2RequestAuthenticator());

        // Attempt 1: Use my own token provider, but it never gets called...
        oAuth2RestTemplate.setAccessTokenProvider(new AadAccessTokenProvider());

        // Even better, if only OAuth2RestTemplate provided a getter for AccessTokenProvider, I could add interceptors and or enhancers
        //AuthorizationCodeAccessTokenProvider provider = oAuth2RestTemplate.getAccessTokenProvider();

        ClientHttpRequestInterceptor myInterceptor = new ClientHttpRequestInterceptor() {
            @Override
            public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes, ClientHttpRequestExecution clientHttpRequestExecution) throws IOException {

                    ClientHttpResponse response  = clientHttpRequestExecution.execute(httpRequest, bytes);
                    return response;

            }
        };

        oAuth2RestTemplate.setInterceptors(Arrays.asList(myInterceptor));
    }
}
