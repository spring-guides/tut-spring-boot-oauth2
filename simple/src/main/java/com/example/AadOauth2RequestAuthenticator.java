package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.DefaultOAuth2RequestAuthenticator;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.web.client.RestTemplate;

public class AadOauth2RequestAuthenticator extends DefaultOAuth2RequestAuthenticator {

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public void authenticate(OAuth2ProtectedResourceDetails resource,
                             OAuth2ClientContext clientContext,
                             ClientHttpRequest request)
    {
        // this call is too late.  the token call was already made
        super.authenticate(resource, clientContext, request);
    }

    class AccessRequest {
        private final String client_id;
        private final String client_secret;
        private final String code;
        private final String grant_type;
        private final String redirect_uri;
        private final String resource;

        public AccessRequest(String client_id, String client_secret, String code, String grant_type, String redirect_uri, String resource) {
            this.client_id = client_id;
            this.client_secret = client_secret;
            this.code = code;
            this.grant_type = grant_type;
            this.redirect_uri = redirect_uri;
            this.resource = resource;
        }


        public String getClient_id() {
            return client_id;
        }

        public String getClient_secret() {
            return client_secret;
        }

        public String getCode() {
            return code;
        }

        public String getGrant_type() {
            return grant_type;
        }

        public String getRedirect_uri() {
            return redirect_uri;
        }

        public String getResource() {
            return resource;
        }
    }

}
