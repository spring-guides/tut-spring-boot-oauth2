/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
@EnableOAuth2Sso
@Controller
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@Bean
	public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
		return new OAuth2RestTemplate(resource, context);
	}

	@Bean
	public AuthoritiesExtractor authoritiesExtractor(OAuth2RestOperations template) {
		return map -> {
			String url = (String) map.get("organizations_url");
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> orgs = template.getForObject(url, List.class);
			if (orgs.stream().anyMatch(org -> "spring-projects".equals(org.get("login")))) {
				return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
			}
			throw new BadCredentialsException("Not in Spring Team");
		};
	}

	@RequestMapping("/user")
	@ResponseBody
	public Principal user(Principal principal) {
		return principal;
	}

	@RequestMapping("/unauthenticated")
	public String unauthenticated() {
		return "redirect:/?error=true";
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**", "/error**").permitAll().anyRequest()
				.authenticated().and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
		// @formatter:on
	}

	@Configuration
	protected static class ServletCustomizer {
		@Bean
		public WebServerFactoryCustomizer<ConfigurableWebServerFactory> customizer() {
			return container -> {
				container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
			};
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

}
