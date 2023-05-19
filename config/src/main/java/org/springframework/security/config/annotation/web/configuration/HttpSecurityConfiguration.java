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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * {@link Configuration} that exposes the {@link HttpSecurity} bean.
 *
 * @author Eleftheria Stein
 * @since 5.4
 */
@Configuration(proxyBeanMethods = false)
class HttpSecurityConfiguration {

	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.";

	private static final String HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

	private ObjectPostProcessor<Object> objectPostProcessor;

	private AuthenticationManager authenticationManager;

	private AuthenticationConfiguration authenticationConfiguration;

	private ApplicationContext context;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

	@Autowired
	void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		/**
		 * @EnableWebSecurity 上的 @EnableGlobalAuthentication 会注册
		 * */
		this.objectPostProcessor = objectPostProcessor;
	}

	void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired
	void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
		/**
		 * @EnableWebSecurity 上的 @EnableGlobalAuthentication 会注册
		 * */
		this.authenticationConfiguration = authenticationConfiguration;
	}

	@Autowired
	void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Autowired(required = false)
	void setContentNegotiationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
		this.contentNegotiationStrategy = contentNegotiationStrategy;
	}

	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype") // 原型的
	HttpSecurity httpSecurity() throws Exception {
		WebSecurityConfigurerAdapter.LazyPasswordEncoder passwordEncoder = new WebSecurityConfigurerAdapter.LazyPasswordEncoder(
				this.context);
		// 是用来实现认证逻辑的，密码的匹配是依赖 passwordEncoder 实现的
		AuthenticationManagerBuilder authenticationBuilder = new WebSecurityConfigurerAdapter.DefaultPasswordEncoderAuthenticationManagerBuilder(
				this.objectPostProcessor, passwordEncoder);
		/**
		 * 设置 parentAuthenticationManager
		 * 默认会通过 authenticationConfiguration.getAuthenticationManager() 得到
		 * 		{@link AuthenticationConfiguration#getAuthenticationManager()}
		 * */
		authenticationBuilder.parentAuthenticationManager(authenticationManager());
		/**
		 *
		 * 从IOC容器中获取 AuthenticationEventPublisher 没有就默认用 AuthenticationEventPublisher
		 * */
		authenticationBuilder.authenticationEventPublisher(getAuthenticationEventPublisher());
		/**
		 * new 一个 HttpSecurity
		 *
		 * 会设置 setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
		 * */
		HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
		// 是用来设置、清空 securityContextHolderStrategy 中记录的 context
		WebAsyncManagerIntegrationFilter webAsyncManagerIntegrationFilter = new WebAsyncManagerIntegrationFilter();
		webAsyncManagerIntegrationFilter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		// @formatter:off
		http
			/**
			 * 会添加 CsrfConfigurer 它的作用是添加 CsrfFilter
			 * 		{@link CsrfConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.csrf(withDefaults())
			/**
			 * webAsyncManagerIntegrationFilter 作为默认的 filter
			 *
			 * 注：filter 的类型是有限定的，必须是内置的类型，否则会报错。
			 * 	内置的Filter类型看这里 {@link org.springframework.security.config.annotation.web.builders.FilterOrderRegistration#FilterOrderRegistration()}
			 * */
			.addFilter(webAsyncManagerIntegrationFilter)
			/**
			 * 会添加 ExceptionHandlingConfigurer 它的作用是添加 ExceptionTranslationFilter
			 * 		{@link ExceptionHandlingConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.exceptionHandling(withDefaults())
			/**
			 * 会添加 HeadersConfigurer 它的作用是添加 HeaderWriterFilter
			 * 		{@link HeadersConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.headers(withDefaults())
			/**
			 * 会添加 SessionManagementConfigurer 它的作用是添加 SessionManagementFilter
			 * 		{@link SessionManagementConfigurer#init( HttpSecurityBuilder)}
			 * 		{@link SessionManagementConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.sessionManagement(withDefaults())
			/**
			 * 会添加 SecurityContextConfigurer 它的作用是添加 SecurityContextHolderFilter 或者 SecurityContextPersistenceFilter
			 * 		{@link SecurityContextConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.securityContext(withDefaults())
			/**
			 * 会添加 RequestCacheConfigurer 它的作用是添加 RequestCacheAwareFilter
			 * 		{@link RequestCacheConfigurer#init( HttpSecurityBuilder)}
			 * 		{@link RequestCacheConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.requestCache(withDefaults())
			/**
			 * 会添加 AnonymousConfigurer 它的作用是添加 AnonymousAuthenticationFilter
			 * 		{@link AnonymousConfigurer#init( HttpSecurityBuilder)}
			 *		{@link AnonymousConfigurer#configure( HttpSecurityBuilder)}
			 *
			 * Tips: 这个很关键，默认会设置 AnonymousAuthenticationProvider 是用来实现认证的，这是最简单的认证方式。
			 * 		可以理解成没有认证，因为认证的信息是由 AnonymousAuthenticationFilter 生成的，肯定能认证通过。
			 * */
			.anonymous(withDefaults())
			/**
			 * 会添加 ServletApiConfigurer 它的作用是添加 SecurityContextHolderAwareRequestFilter
			 * 		{@link ServletApiConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.servletApi(withDefaults())
			/**
			 * 会添加 DefaultLoginPageConfigurer 它的作用是添加 DefaultLoginPageGeneratingFilter、DefaultLogoutPageGeneratingFilter
			 * 		{@link DefaultLoginPageConfigurer#init( HttpSecurityBuilder)}
			 * 		{@link DefaultLoginPageConfigurer#configure( HttpSecurityBuilder)}
			 * */
			.apply(new DefaultLoginPageConfigurer<>());
		/**
		 * 会添加 LogoutConfigurer 它的作用是添加 LogoutFilter
		 * 		{@link LogoutConfigurer#init( HttpSecurityBuilder)}
		 * 		{@link LogoutConfigurer#configure( HttpSecurityBuilder)}
		 * */
		http.logout(withDefaults());
		// @formatter:on
		/**
		 * 读取 META-INF/spring.factories 文件 key是 `AbstractHttpConfigurer.class.getName()`
		 * 添加到 http 中
		 * */
		applyDefaultConfigurers(http);
		return http;
	}

	private AuthenticationManager authenticationManager() throws Exception {
		// 为空 就通过 authenticationConfiguration.getAuthenticationManager()
		return (this.authenticationManager != null) ? this.authenticationManager
				: this.authenticationConfiguration.getAuthenticationManager();
	}

	private AuthenticationEventPublisher getAuthenticationEventPublisher() {
		// 从IOC容器中获取
		if (this.context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
			return this.context.getBean(AuthenticationEventPublisher.class);
		}
		// 使用默认的
		return this.objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
	}

	private void applyDefaultConfigurers(HttpSecurity http) throws Exception {
		ClassLoader classLoader = this.context.getClassLoader();
		// 读取 META-INF/spring.factories 文件 key是 `AbstractHttpConfigurer.class.getName()`
		List<AbstractHttpConfigurer> defaultHttpConfigurers = SpringFactoriesLoader
				.loadFactories(AbstractHttpConfigurer.class, classLoader);
		for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
			// 添加默认 configurer
			http.apply(configurer);
		}
	}

	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.put(ApplicationContext.class, this.context);
		sharedObjects.put(ContentNegotiationStrategy.class, this.contentNegotiationStrategy);
		return sharedObjects;
	}

}
