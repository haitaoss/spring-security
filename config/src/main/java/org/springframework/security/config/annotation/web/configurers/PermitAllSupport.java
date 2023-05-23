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

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry.UrlMapping;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

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
		 *
		 * 其实就是将 requestMatchers 对应的权限数据注册到 configurer 中。因为鉴权的逻辑是找到 匹配 request 的 requestMatcher
		 * 就使用 requestMatcher 对应的权限逻辑验证 authentication 是否具备权限
		 *
		 * 注：这种方式已经过时了，不推荐使用了，因为它的鉴权每次都是执行 SpEL 非常的耗时
		 *
		 * 示例代码 {@link cn.haitaoss.config.security.SecurityFilterChainConfig#filterChain3}
		 * */
		ExpressionUrlAuthorizationConfigurer<?> configurer = http
				.getConfigurer(ExpressionUrlAuthorizationConfigurer.class);
		/**
		 * AuthorizeHttpRequestsConfigurer 会注册 AuthorizationFilter。
		 * 鉴权思路同上，他默认提供了很多种鉴权实现(字符串匹配、集合contains、属性值) 还支持写复杂的SpEL，所以性能比较好。
		 *
		 * 示例代码 {@link cn.haitaoss.config.security.SecurityFilterChainConfig#filterChain2}
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
					// 注册 matcher+权限
					configurer.getRegistry().addMapping(0, new UrlMapping(matcher,
							SecurityConfig.createList(ExpressionUrlAuthorizationConfigurer.permitAll)));
				}
				else {
					// 注册 matcher+权限
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
