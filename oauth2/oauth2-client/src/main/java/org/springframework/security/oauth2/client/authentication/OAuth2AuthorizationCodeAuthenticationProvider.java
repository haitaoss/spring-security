/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthenticationProvider} for the OAuth 2.0 Authorization
 * Code Grant.
 *
 * <p>
 * This {@link AuthenticationProvider} is responsible for authenticating an Authorization
 * Code credential with the Authorization Server's Token Endpoint and if valid, exchanging
 * it for an Access Token credential.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenResponseClient
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token
 * Request</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token
 * Response</a>
 */
public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";

	private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the
	 * provided parameters.
	 * @param accessTokenResponseClient the client used for requesting the access token
	 * credential from the Token Endpoint
	 */
	public OAuth2AuthorizationCodeAuthenticationProvider(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
		OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationResponse();
		// 授权方返回的信息是 错误状态码
		if (authorizationResponse.statusError()) {
			// 抛出异常
			throw new OAuth2AuthorizationException(authorizationResponse.getError());
		}
		// 授权信息
		OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationRequest();
		// 请求发送的state 和响应的state 不一致。state是唯一标识
		if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
			// 报错
			throw new OAuth2AuthorizationException(oauth2Error);
		}
		/**
		 * 根据 code 请求第三方服务拿到 访问令牌
		 *
		 * Tips：authorizationCodeAuthentication.getAuthorizationExchange() 可以拿到 code
		 *
		 * {@link DefaultAuthorizationCodeTokenResponseClient#getTokenResponse(OAuth2AuthorizationCodeGrantRequest)}
		 * */
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(
				new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(),
						authorizationCodeAuthentication.getAuthorizationExchange()));
		// 装饰成 OAuth2AuthorizationCodeAuthenticationToken
		OAuth2AuthorizationCodeAuthenticationToken authenticationResult = new OAuth2AuthorizationCodeAuthenticationToken(
				authorizationCodeAuthentication.getClientRegistration(),
				authorizationCodeAuthentication.getAuthorizationExchange(), accessTokenResponse.getAccessToken(),
				accessTokenResponse.getRefreshToken(), accessTokenResponse.getAdditionalParameters());
		authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
