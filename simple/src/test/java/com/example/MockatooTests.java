/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("mockatoo")
public class MockatooTests {

	private static final String MOCKATOO_ORIGIN = "https://app.mockatoo.globalunderdog.com";

	@LocalServerPort
	private int port;

	private HttpClient client;

	private Map<String, String> cookies;

	@Before
	public void setUp() {
		this.cookies = new HashMap<>();
		this.client = HttpClient.newBuilder()
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();
	}

	@Test
	public void githubLoginRedirectsToMockatoo() throws Exception {
		HttpResponse<String> response = get(local("/oauth2/authorization/github"));

		assertEquals(302, response.statusCode());
		URI location = URI.create(location(response));
		assertEquals(MOCKATOO_ORIGIN, location.getScheme() + "://" + location.getAuthority());
		assertEquals("/github/login/oauth/authorize", location.getPath());
	}

	@Test
	public void githubSignInWorksAgainstMockatoo() throws Exception {
		String email = System.getenv("MOCKATOO_TEST_EMAIL");
		String password = System.getenv("MOCKATOO_TEST_PASSWORD");
		assumeTrue("MOCKATOO_TEST_EMAIL and MOCKATOO_TEST_PASSWORD are not set", email != null && !email.isBlank()
			&& password != null && !password.isBlank());

		HttpResponse<String> response = get(local("/"));
		assertEquals(302, response.statusCode());

		response = get(URI.create(location(response)));
		assertEquals(302, response.statusCode());
		URI authorization = URI.create(location(response));
		assertEquals(MOCKATOO_ORIGIN, authorization.getScheme() + "://" + authorization.getAuthority());

		response = get(authorization);
		assertEquals(303, response.statusCode());
		URI login = authorization.resolve(location(response));

		response = get(login);
		assertEquals(200, response.statusCode());
		assertTrue(this.cookies.containsKey("mock_csrf"));
		String csrf = inputValue(response.body(), "csrf");
		String loginCsrf = csrf;
		assertTrue("CSRF cookie does not match form", loginCsrf.equals(this.cookies.get("mock_csrf")));
		String next = inputValue(response.body(), "next");
		response = post(login.resolve("/login"), Map.of(
			"csrf", csrf,
			"next", next,
			"email", email,
			"password", password));
		assertEquals(303, response.statusCode());

		URI consent = login.resolve(location(response));
		response = get(consent);
		assertEquals(200, response.statusCode());
		csrf = inputValue(response.body(), "csrf");
		String query = inputValue(response.body(), "query");
		response = post(consent.resolve("/github/login/oauth/authorize"), Map.of(
			"csrf", csrf,
			"query", query,
			"decision", "approve"));
		assertEquals(303, response.statusCode());

		URI callback = URI.create(location(response));
		assertEquals("localhost", callback.getHost());
		response = get(callback);
		assertTrue(response.statusCode() >= 300 && response.statusCode() < 400);
		URI home = callback.resolve(location(response));
		assertEquals("/", home.getPath());

		response = get(home);
		assertEquals(200, response.statusCode());
	}

	private HttpResponse<String> get(URI uri) throws Exception {
		HttpResponse<String> response = this.client.send(request(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
		rememberCookies(response);
		return response;
	}

	private HttpResponse<String> post(URI uri, Map<String, String> values) throws Exception {
		String form = values.entrySet().stream()
			.map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
			.reduce((left, right) -> left + "&" + right)
			.orElse("");
		HttpRequest request = request(uri)
			.header("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString(form))
			.build();
		HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
		rememberCookies(response);
		return response;
	}

	private HttpRequest.Builder request(URI uri) {
		HttpRequest.Builder request = HttpRequest.newBuilder(uri);
		String cookieHeader = this.cookies.entrySet().stream()
			.map(entry -> entry.getKey() + "=" + entry.getValue())
			.reduce((left, right) -> left + "; " + right)
			.orElse("");
		if (!cookieHeader.isEmpty()) {
			request.header("Cookie", cookieHeader);
		}
		return request;
	}

	private void rememberCookies(HttpResponse<?> response) {
		for (String setCookie : response.headers().allValues("Set-Cookie")) {
			String[] pair = setCookie.split(";", 2)[0].split("=", 2);
			if (pair.length == 2) {
				if (pair[1].isEmpty()) {
					this.cookies.remove(pair[0]);
				}
				else {
					this.cookies.put(pair[0], pair[1]);
				}
			}
		}
	}

	private URI local(String path) {
		return URI.create("http://localhost:" + this.port + path);
	}

	private static String location(HttpResponse<?> response) {
		String location = response.headers().firstValue("Location").orElse(null);
		assertNotNull("Expected a Location header", location);
		return location;
	}

	private static String inputValue(String html, String name) {
		Pattern pattern = Pattern.compile("<input\\b[^>]*\\bname=\\\"" + Pattern.quote(name)
			+ "\\\"[^>]*\\bvalue=\\\"([^\\\"]*)\\\"", Pattern.CASE_INSENSITIVE);
		Matcher matcher = pattern.matcher(html);
		assertTrue("Expected an input named " + name, matcher.find());
		return matcher.group(1).replace("&amp;", "&");
	}

	private static String encode(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

}
