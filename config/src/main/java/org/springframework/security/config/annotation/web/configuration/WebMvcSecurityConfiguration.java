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

import java.util.List;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.BeanResolver;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.method.annotation.CsrfTokenArgumentResolver;
import org.springframework.security.web.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * Used to add a {@link RequestDataValueProcessor} for Spring MVC and Spring Security CSRF
 * integration. This configuration is added whenever {@link EnableWebMvc} is added by
 * <a href="
 * {@docRoot}/org/springframework/security/config/annotation/web/configuration/SpringWebMvcImportSelector.html">SpringWebMvcImportSelector</a>
 * and the DispatcherServlet is present on the classpath. It also adds the
 * {@link AuthenticationPrincipalArgumentResolver} as a
 * {@link HandlerMethodArgumentResolver}.
 *
 * @author Rob Winch
 * @author Dan Zheng
 * @since 3.2
 */
class WebMvcSecurityConfiguration implements WebMvcConfigurer, ApplicationContextAware {

	private BeanResolver beanResolver;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	/**
	 * 扩展 MVC 会用到的参数解析器
	 * @param argumentResolvers initially an empty list
	 */
	@Override
	@SuppressWarnings("deprecation")
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		// 处理有 @AuthenticationPrincipal 注解的参数
		AuthenticationPrincipalArgumentResolver authenticationPrincipalResolver = new AuthenticationPrincipalArgumentResolver();
		authenticationPrincipalResolver.setBeanResolver(this.beanResolver);
		authenticationPrincipalResolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		argumentResolvers.add(authenticationPrincipalResolver);
		argumentResolvers
				.add(new org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver());
		// 处理有 @CurrentSecurityContext 注解的参数
		CurrentSecurityContextArgumentResolver currentSecurityContextArgumentResolver = new CurrentSecurityContextArgumentResolver();
		currentSecurityContextArgumentResolver.setBeanResolver(this.beanResolver);
		currentSecurityContextArgumentResolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		argumentResolvers.add(currentSecurityContextArgumentResolver);
		// 处理 CsrfToken 类型的参数
		argumentResolvers.add(new CsrfTokenArgumentResolver());
	}

	@Bean
	RequestDataValueProcessor requestDataValueProcessor() {
		return new CsrfRequestDataValueProcessor();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.beanResolver = new BeanFactoryResolver(applicationContext.getAutowireCapableBeanFactory());
		if (applicationContext.getBeanNamesForType(SecurityContextHolderStrategy.class).length == 1) {
			// 获取容器中的 SecurityContextHolderStrategy
			this.securityContextHolderStrategy = applicationContext.getBean(SecurityContextHolderStrategy.class);
		}
	}

}
