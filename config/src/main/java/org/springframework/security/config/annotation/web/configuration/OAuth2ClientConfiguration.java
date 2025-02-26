/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.util.ClassUtils;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * {@link Configuration} for OAuth 2.0 Client support.
 *
 * <p>
 * This {@code Configuration} is conditionally imported by {@link OAuth2ImportSelector}
 * when the {@code spring-security-oauth2-client} module is present on the classpath.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2ImportSelector
 */
@Import(OAuth2ClientConfiguration.OAuth2ClientWebMvcImportSelector.class)
final class OAuth2ClientConfiguration {

	static class OAuth2ClientWebMvcImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			// 不存在
			if (!ClassUtils.isPresent("org.springframework.web.servlet.DispatcherServlet",
					getClass().getClassLoader())) {
				return new String[0];
			}
			/**
			 * 注册配置类。其作用是注册 OAuth2AuthorizedClientArgumentResolver
			 * {@link org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration.OAuth2ClientWebMvcSecurityConfiguration}
			 */
			return new String[] { "org.springframework.security.config.annotation.web.configuration."
					+ "OAuth2ClientConfiguration.OAuth2ClientWebMvcSecurityConfiguration" };
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientWebMvcSecurityConfiguration implements WebMvcConfigurer {

		private ClientRegistrationRepository clientRegistrationRepository;

		private OAuth2AuthorizedClientRepository authorizedClientRepository;

		private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

		private OAuth2AuthorizedClientManager authorizedClientManager;

		private SecurityContextHolderStrategy securityContextHolderStrategy;

		@Override
		public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
			OAuth2AuthorizedClientManager authorizedClientManager = getAuthorizedClientManager();
			if (authorizedClientManager != null) {
				// 用于解析有 @RegisteredOAuth2AuthorizedClient 的参数
				OAuth2AuthorizedClientArgumentResolver resolver = new OAuth2AuthorizedClientArgumentResolver(
						authorizedClientManager);
				if (this.securityContextHolderStrategy != null) {
					resolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
				}
				argumentResolvers.add(resolver);
			}
		}

		@Autowired(required = false)
		void setClientRegistrationRepository(List<ClientRegistrationRepository> clientRegistrationRepositories) {
			if (clientRegistrationRepositories.size() == 1) {
				this.clientRegistrationRepository = clientRegistrationRepositories.get(0);
			}
		}

		@Autowired(required = false)
		void setAuthorizedClientRepository(List<OAuth2AuthorizedClientRepository> authorizedClientRepositories) {
			if (authorizedClientRepositories.size() == 1) {
				this.authorizedClientRepository = authorizedClientRepositories.get(0);
			}
		}

		@Autowired(required = false)
		void setAccessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
		}

		@Autowired(required = false)
		void setAuthorizedClientManager(List<OAuth2AuthorizedClientManager> authorizedClientManagers) {
			if (authorizedClientManagers.size() == 1) {
				this.authorizedClientManager = authorizedClientManagers.get(0);
			}
		}

		@Autowired(required = false)
		void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
			this.securityContextHolderStrategy = strategy;
		}

		private OAuth2AuthorizedClientManager getAuthorizedClientManager() {
			if (this.authorizedClientManager != null) {
				return this.authorizedClientManager;
			}
			OAuth2AuthorizedClientManager authorizedClientManager = null;
			// 构造一个 OAuth2AuthorizedClientManager
			if (this.clientRegistrationRepository != null && this.authorizedClientRepository != null) {
				if (this.accessTokenResponseClient != null) {
					// @formatter:off
					OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder
						.builder()
						// 最终会设置 AuthorizationCodeOAuth2AuthorizedClientProvider
						.authorizationCode()
						// 最终会设置 RefreshTokenOAuth2AuthorizedClientProvider
						.refreshToken()
						// 最终会设置 ClientCredentialsOAuth2AuthorizedClientProvider
						.clientCredentials((configurer) -> configurer.accessTokenResponseClient(this.accessTokenResponseClient))
						// 最终会设置 PasswordOAuth2AuthorizedClientProvider
						.password()
						.build();
					// @formatter:on
					// 构造出 DefaultOAuth2AuthorizedClientManager
					DefaultOAuth2AuthorizedClientManager defaultAuthorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
							this.clientRegistrationRepository, this.authorizedClientRepository);
					// 为其设置 authorizedClientProvider
					defaultAuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
					// 设置为属性
					authorizedClientManager = defaultAuthorizedClientManager;
				}
				else {
					// 构造这个，其实和上面的一样，只是少了对 ClientCredentialsOAuth2AuthorizedClientProvider 的自定义的环节
					authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
							this.clientRegistrationRepository, this.authorizedClientRepository);
				}
			}
			return authorizedClientManager;
		}

	}

}
