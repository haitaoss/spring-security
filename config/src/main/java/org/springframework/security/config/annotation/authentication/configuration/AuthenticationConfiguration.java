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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * Exports the authentication {@link Configuration}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@Configuration(proxyBeanMethods = false)
/**
 * 会注册 AutowireBeanFactoryObjectPostProcessor 到容器中
 * */
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {
	private AtomicBoolean buildingAuthenticationManager = new AtomicBoolean();

	private ApplicationContext applicationContext;

	private AuthenticationManager authenticationManager;

	private boolean authenticationManagerInitialized;

	private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigurers = Collections.emptyList();

	/**
	 * 默认注入的是 AutowireBeanFactoryObjectPostProcessor，它的作用是对参数进行初始化和属性填充
	 */
	private ObjectPostProcessor<Object> objectPostProcessor;

	/**
	 * AuthenticationManagerBuilder 是用来生成 AuthenticationManager，
	 * AuthenticationManager 是用来进行认证的
	 * @param objectPostProcessor
	 * @param context
	 * @return
	 */
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
			ApplicationContext context) {
		/**
		 * 特点是尝试从IOC容器中获取 PasswordEncoder，拿不到就new一个默认的
		 * */
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		/**
		 * 尝试从IOC容器中获取 AuthenticationEventPublisher，拿不到就new一个默认的
		 * */
		AuthenticationEventPublisher authenticationEventPublisher = getAuthenticationEventPublisher(context);
		// 构造出 DefaultPasswordEncoderAuthenticationManagerBuilder
		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		/**
		 * 继承 GlobalAuthenticationConfigurerAdapter 抽象类，
		 * 它的职责是 获取有 @EnableGlobalAuthentication 注解的bean，会进行 getBean 将bean实例化出来，也就是提前初始化
		 * */
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}

	@Bean
	public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(
			ApplicationContext context) {
		/**
		 * 继承 GlobalAuthenticationConfigurerAdapter 抽象类，
		 * 它的职责是为  AuthenticationManagerBuilder 添加 InitializeUserDetailsManagerConfigurer 这个 configurer，
		 * 而 InitializeUserDetailsManagerConfigurer 的功能是若IOC容器中只有一个 UserDetailsService 类型的bean，就构造一个
		 * DaoAuthenticationProvider 设置给 AuthenticationManagerBuilder
		 * */
		return new InitializeUserDetailsBeanManagerConfigurer(context);
	}

	@Bean
	public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(
			ApplicationContext context) {
		/**
		 * 继承 GlobalAuthenticationConfigurerAdapter 抽象类，
		 * 它的职责是为  AuthenticationManagerBuilder 添加 InitializeAuthenticationProviderManagerConfigurer 这个 configurer，
		 * 而 InitializeAuthenticationProviderManagerConfigurer 的功能是若IOC容器中只有一个 AuthenticationProvider 类型的bean，
		 * 就将其设置给 AuthenticationManagerBuilder
		 * */
		return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
	}

	public AuthenticationManager getAuthenticationManager() throws Exception {
		// 已经初始化了
		if (this.authenticationManagerInitialized) {
			// 直接返回
			return this.authenticationManager;
		}
		/**
		 * 从IOC容器中获取 AuthenticationManagerBuilder
		 * Tips：本类的 {@link #authenticationManagerBuilder} 方法注册了
		 * */
		AuthenticationManagerBuilder authBuilder = this.applicationContext.getBean(AuthenticationManagerBuilder.class);
		// 默认是false
		if (this.buildingAuthenticationManager.getAndSet(true)) {
			return new AuthenticationManagerDelegator(authBuilder);
		}
		/**
		 * 遍历 globalAuthConfigurers
		 *
		 * Tips：
		 * 	1. globalAuthConfigurers 是通过依赖注入得到的
		 * 	2. 本类的 {@link #enableGlobalAuthenticationAutowiredConfigurer}、
		 * 		{@link #initializeAuthenticationProviderBeanManagerConfigurer}、
		 * 		{@link #initializeUserDetailsBeanManagerConfigurer} 方法注册了。
		 *
		 * Tips：
		 * 		initializeAuthenticationProviderBeanManagerConfigurer 先执行，会判断IOC容器中存在 AuthenticationProvider 就设置给 authBuilder ，
		 * 		initializeUserDetailsBeanManagerConfigurer 会判断IOC容器中存在 UserDetailsService 就设置 DaoAuthenticationProvider 给 authBuilder。
		 *		不会设置两个，因为设置之前会判断是否有 {@link AuthenticationManagerBuilder#authenticationProviders} ,所以可以理解成两者是互斥的
		 * */
		for (GlobalAuthenticationConfigurerAdapter config : this.globalAuthConfigurers) {
			// 添加 config
			authBuilder.apply(config);
		}
		/**
		 * 生成实例。最关键是回调注册的 config
		 *
		 * {@link AbstractConfiguredSecurityBuilder#doBuild()}
		 * 		1. 回调 GlobalAuthenticationConfigurerAdapter#init
		 * 		2. 回调 GlobalAuthenticationConfigurerAdapter#configure
		 * 		3. 构造出实例对象
		 * */
		this.authenticationManager = authBuilder.build();
		if (this.authenticationManager == null) {
			// 尝试从容器中获取 AuthenticationManager 类型的bean
			this.authenticationManager = getAuthenticationManagerBean();
		}
		// 标记为 true
		this.authenticationManagerInitialized = true;
		return this.authenticationManager;
	}

	@Autowired(required = false)
	public void setGlobalAuthenticationConfigurers(List<GlobalAuthenticationConfigurerAdapter> configurers) {
		// 排序
		configurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		this.globalAuthConfigurers = configurers;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	private AuthenticationEventPublisher getAuthenticationEventPublisher(ApplicationContext context) {
		// 尝试从IOC容器中获取
		if (context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
			return context.getBean(AuthenticationEventPublisher.class);
		}
		// 使用默认的
		return this.objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
	}

	@SuppressWarnings("unchecked")
	private <T> T lazyBean(Class<T> interfaceName) {
		LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
		String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.applicationContext,
				interfaceName);
		if (beanNamesForType.length == 0) {
			return null;
		}
		String beanName = getBeanName(interfaceName, beanNamesForType);
		lazyTargetSource.setTargetBeanName(beanName);
		lazyTargetSource.setBeanFactory(this.applicationContext);
		ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
		// 加工
		proxyFactory = this.objectPostProcessor.postProcess(proxyFactory);
		proxyFactory.setTargetSource(lazyTargetSource);
		// 返回代理对象
		return (T) proxyFactory.getObject();
	}

	private <T> String getBeanName(Class<T> interfaceName, String[] beanNamesForType) {
		if (beanNamesForType.length == 1) {
			return beanNamesForType[0];
		}
		List<String> primaryBeanNames = getPrimaryBeanNames(beanNamesForType);
		Assert.isTrue(primaryBeanNames.size() != 0, () -> "Found " + beanNamesForType.length + " beans for type "
				+ interfaceName + ", but none marked as primary");
		Assert.isTrue(primaryBeanNames.size() == 1,
				() -> "Found " + primaryBeanNames.size() + " beans for type " + interfaceName + " marked as primary");
		return primaryBeanNames.get(0);
	}

	private List<String> getPrimaryBeanNames(String[] beanNamesForType) {
		List<String> list = new ArrayList<>();
		if (!(this.applicationContext instanceof ConfigurableApplicationContext)) {
			return Collections.emptyList();
		}
		for (String beanName : beanNamesForType) {
			if (((ConfigurableApplicationContext) this.applicationContext).getBeanFactory().getBeanDefinition(beanName)
					.isPrimary()) {
				list.add(beanName);
			}
		}
		return list;
	}

	private AuthenticationManager getAuthenticationManagerBean() {
		return lazyBean(AuthenticationManager.class);
	}

	private static <T> T getBeanOrNull(ApplicationContext applicationContext, Class<T> type) {
		try {
			return applicationContext.getBean(type);
		}
		catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	private static class EnableGlobalAuthenticationAutowiredConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final ApplicationContext context;

		private static final Log logger = LogFactory.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

		EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
			this.context = context;
		}

		@Override
		public void init(AuthenticationManagerBuilder auth) {
			/**
			 * 获取有这个注解的bean，会进行 getBean 将bean实例化出来，也就是提前初始化
			 * */
			Map<String, Object> beansWithAnnotation = this.context
					.getBeansWithAnnotation(EnableGlobalAuthentication.class);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Eagerly initializing %s", beansWithAnnotation));
			}
		}

	}

	/**
	 * Prevents infinite recursion in the event that initializing the
	 * AuthenticationManager.
	 *
	 * @author Rob Winch
	 * @since 4.1.1
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {

		private AuthenticationManagerBuilder delegateBuilder;

		private AuthenticationManager delegate;

		private final Object delegateMonitor = new Object();

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			this.delegateBuilder = delegateBuilder;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			return this.delegate.authenticate(authentication);
		}

		@Override
		public String toString() {
			return "AuthenticationManagerDelegator [delegate=" + this.delegate + "]";
		}

	}

	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
				throws Exception {
			return super.inMemoryAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
			return super.jdbcAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService).passwordEncoder(this.defaultPasswordEncoder);
		}

	}

	static class LazyPasswordEncoder implements PasswordEncoder {

		private ApplicationContext applicationContext;

		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			// 不为空，说明已经初始化了
			if (this.passwordEncoder != null) {
				// 直接返回
				return this.passwordEncoder;
			}
			// 从IOC容器中获取
			PasswordEncoder passwordEncoder = getBeanOrNull(this.applicationContext, PasswordEncoder.class);
			// 为空
			if (passwordEncoder == null) {
				// 获取不到就使用默认的
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}
