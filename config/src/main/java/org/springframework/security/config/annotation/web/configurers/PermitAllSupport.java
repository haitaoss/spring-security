/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry.UrlMapping;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configures non-null URL's to grant access to every URL
 *
 * @author Rob Winch
 * @since 3.2
 */
final class PermitAllSupport {

	private PermitAllSupport() {
	}

	static void permitAll(HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http, String... urls) {
		for (String url : urls) {
			if (url != null) {
				permitAll(http, new ExactUrlRequestMatcher(url));
			}
		}
	}

	@SuppressWarnings("unchecked")
	static void permitAll(HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http,
			RequestMatcher... requestMatchers) {
		/**
		 * ExpressionUrlAuthorizationConfigurer 会注册 FilterSecurityInterceptor
		 * 这是基于 SpEL 表达式的。
		 *
		 * TODOHAITAO: 2023/5/16 功能很复杂包含了 认证鉴权的逻辑
		 * */
		ExpressionUrlAuthorizationConfigurer<?> configurer = http
				.getConfigurer(ExpressionUrlAuthorizationConfigurer.class);
		/**
		 * AuthorizeHttpRequestsConfigurer 会注册 AuthorizationFilter
		 *
		 * TODOHAITAO: 2023/5/16 功能很复杂包含了 认证鉴权的逻辑
		 * */
		AuthorizeHttpRequestsConfigurer<?> httpConfigurer = http.getConfigurer(AuthorizeHttpRequestsConfigurer.class);

		// 存在一个
		boolean oneConfigurerPresent = configurer == null ^ httpConfigurer == null;
		// 有且只能有一个
		Assert.state(oneConfigurerPresent,
				"permitAll only works with either HttpSecurity.authorizeRequests() or HttpSecurity.authorizeHttpRequests(). "
						+ "Please define one or the other but not both.");

		// 遍历
		for (RequestMatcher matcher : requestMatchers) {
			if (matcher != null) {
				if (configurer != null) {
					// 注册规则
					configurer.getRegistry().addMapping(0, new UrlMapping(matcher,
							SecurityConfig.createList(ExpressionUrlAuthorizationConfigurer.permitAll)));
				}
				else {
					// 注册映射规则
					httpConfigurer.addFirst(matcher, AuthorizeHttpRequestsConfigurer.permitAllAuthorizationManager);
				}
			}
		}
	}

	private static final class ExactUrlRequestMatcher implements RequestMatcher {

		private String processUrl;

		private ExactUrlRequestMatcher(String processUrl) {
			this.processUrl = processUrl;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String uri = request.getRequestURI();
			String query = request.getQueryString();
			if (query != null) {
				uri += "?" + query;
			}
			if ("".equals(request.getContextPath())) {
				return uri.equals(this.processUrl);
			}
			return uri.equals(request.getContextPath() + this.processUrl);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("ExactUrl [processUrl='").append(this.processUrl).append("']");
			return sb.toString();
		}

	}

}
