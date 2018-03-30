package com.example;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ClientCredentialsGrantTest {

   private ObjectMapper jsonMapper = new ObjectMapper();
   private TypeReference<Map<String, Object>> objectMapReference = new TypeReference<Map<String, Object>>() { };

   @Value("${security.oauth2.client.client-id}")
   private String clientId;
   @Value("${security.oauth2.client.client-secret}")
   private String clientSecret;
   @Value("${security.oauth2.client.scope}")
   private String scope;
   private String[] scopes;

   @Autowired
   private TestRestTemplate restTemplate;

   @Before
   public void setUp() {

      scopes = scope.split("\\s*,\\s*");
   }

   @Test
   public void test() throws Exception {

      MultiValueMap<String, String> requestFormMap;
      ResponseEntity<String> response;
      Map<String, Object> responseMap;
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

      // ----- Client Credentials Grant -----
      // If you provide your own client credentials in application.yml, you can use this Grant with those credentials.
      // security:
      //   oauth2:
      //     client:
      //       client-id: acme
      //       client-secret: acmesecret

      requestFormMap = new LinkedMultiValueMap<>();
      requestFormMap.add("grant_type", "client_credentials");
      requestFormMap.add("scope", scopes[0]);

      response = this.restTemplate
         .withBasicAuth(clientId, clientSecret)
         .postForEntity("/oauth/token", new HttpEntity<>(requestFormMap, headers) , String.class);

      Assert.assertEquals(200, response.getStatusCodeValue());

      responseMap = jsonMapper.readValue(response.getBody(), this.objectMapReference);
      /*
      {
        "access_token":"2f1cd8a7-89ab-4168-b4a9-fb1ef52e8e71",
        "token_type":"bearer",
        "expires_in":43199,
        "scope":"write"
      }
       */

      Assert.assertNotNull(responseMap.get("access_token"));
      Assert.assertEquals("bearer", responseMap.get("token_type"));
      Assert.assertTrue((int) responseMap.get("expires_in") > 1000);
      Assert.assertEquals(scopes[0], responseMap.get("scope"));

      String accessToken = (String) responseMap.get("access_token");

      // ----- Check Access Token -----
      // Check Access Token is available when you grant access to the check_token endpoint in application.yml.
      // security:
      //   oauth2:
      //     authorization:
      //       check-token-access: isAuthenticated()

      response = this.restTemplate
         .withBasicAuth(clientId, clientSecret)
         .getForEntity("/oauth/check_token?token={token}" , String.class, accessToken);

      Assert.assertEquals(200, response.getStatusCodeValue());

      responseMap = jsonMapper.readValue(response.getBody(), this.objectMapReference);
      /*
      {
        "scope":[ "write" ],
        "exp":1522440288,
        "authorities":[ "ROLE_USER" ],
        "client_id":"acme"
      }
       */

      Assert.assertEquals(scopes[0], List.class.cast(responseMap.get("scope")).get(0));
      Assert.assertTrue(Long.compare(Instant.now().getEpochSecond(), ((Integer) responseMap.get("exp"))) < 0);
      Assert.assertEquals("ROLE_USER", List.class.cast(responseMap.get("authorities")).get(0));
      Assert.assertEquals(clientId, responseMap.get("client_id"));
   }
}
