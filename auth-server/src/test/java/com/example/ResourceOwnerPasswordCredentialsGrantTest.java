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

import java.util.Map;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ResourceOwnerPasswordCredentialsGrantTest {

   private ObjectMapper jsonMapper = new ObjectMapper();
   private TypeReference<Map<String, Object>> objectMapReference = new TypeReference<Map<String, Object>>() { };

   @Value("${security.oauth2.client.client-id}")
   private String clientId;
   @Value("${security.oauth2.client.client-secret}")
   private String clientSecret;
   @Value("${security.user.name}")
   private String userName;
   @Value("${security.user.password}")
   private String userPassword;
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

      // ----- Resource Owner Password Credentials Grant -----
      // Spring Boot creates new random user credentials on every application start, unless you provide your own
      // user credentials in application.yml, in which case you can use this Grant with those credentials.
      // security:
      //   user:
      //     name: acmeuser
      //     password: acmeuserpassword

      requestFormMap = new LinkedMultiValueMap<>(4);
      requestFormMap.add("grant_type", "password");
      requestFormMap.add("scope", scopes[0]);
      requestFormMap.add("username", userName);
      requestFormMap.add("password", userPassword);

      response = this.restTemplate
         .withBasicAuth(clientId, clientSecret)
         .postForEntity("/oauth/token", new HttpEntity<>(requestFormMap, headers), String.class);

      Assert.assertEquals(200, response.getStatusCodeValue());

      responseMap = jsonMapper.readValue(response.getBody(), this.objectMapReference);
      /*
      {
        "access_token":"2fd811d9-a3e4-4e91-916a-58854ac96a3a",
        "token_type":"bearer",
        "refresh_token":"498e0caa-5337-44eb-a6e9-e0def946621f",
        "expires_in":43199,
        "scope":"write"
      }
       */

      Assert.assertNotNull(responseMap.get("access_token"));
      Assert.assertEquals("bearer", responseMap.get("token_type"));
      Assert.assertNotNull(responseMap.get("refresh_token"));
      Assert.assertTrue((int) responseMap.get("expires_in") > 1000);
      Assert.assertEquals(scopes[0], responseMap.get("scope"));

      String refreshToken = (String) responseMap.get("refresh_token");

      // ----- Renew Access Token with Refresh Token -----

      requestFormMap = new LinkedMultiValueMap<>(3);
      requestFormMap.add("grant_type", "refresh_token");
      requestFormMap.add("scope", scopes[0]);
      requestFormMap.add("refresh_token", refreshToken);

      response = this.restTemplate
         .withBasicAuth(clientId, clientSecret)
         .postForEntity("/oauth/token", new HttpEntity<>(requestFormMap, headers), String.class);

      Assert.assertEquals(200, response.getStatusCodeValue());

      responseMap = jsonMapper.readValue(response.getBody(), this.objectMapReference);
      /*
      {
        "access_token":"5adad4cd-23c6-4174-8f5e-7e1906b54f60",
        "token_type":"bearer",
        "refresh_token":"498e0caa-5337-44eb-a6e9-e0def946621f",
        "expires_in":43199,
        "scope":"write"
      }
       */

      Assert.assertNotNull(responseMap.get("access_token"));
      Assert.assertEquals("bearer", responseMap.get("token_type"));
      Assert.assertEquals(refreshToken, responseMap.get("refresh_token"));
      Assert.assertTrue((int) responseMap.get("expires_in") > 1000);
      Assert.assertEquals(scopes[0], responseMap.get("scope"));
   }
}
