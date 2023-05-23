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

package org.springframework.security.config.annotation.method.configuration;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Dynamically determines which imports to include using the {@link EnableMethodSecurity}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
final class MethodSecuritySelector implements ImportSelector {

	private final ImportSelector autoProxy = new AutoProxyRegistrarSelector();

	@Override
	public String[] selectImports(@NonNull AnnotationMetadata importMetadata) {
		// 没有 @EnableMethodSecurity
		if (!importMetadata.hasAnnotation(EnableMethodSecurity.class.getName())) {
			// 返回空数组，表示啥都不注册到 BeanFactory 中，这是Spring的知识
			return new String[0];
		}
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		/**
		 * 获取默认要注入的配置类 {@link AutoProxyRegistrarSelector#selectImports(AdviceMode)}
		 * 默认是注册这个 AutoProxyRegistrar 它的作用是会注册 InfrastructureAdvisorAutoProxyCreator 到BeanFactory中，
		 * 其作用是根据从 BeanFactory 中获取 @Role(BeanDefinition.ROLE_INFRASTRUCTURE) 的 Advisor 类型的bean，完成动态代理实现的AOP
		 * */
		List<String> imports = new ArrayList<>(Arrays.asList(this.autoProxy.selectImports(importMetadata)));
		// 根据注解属性值决定是否添加配置类
		if (annotation.prePostEnabled()) {
			/**
			 * 默认是启用的。
			 *
			 * 其实就是注册4个 Advisor：
			 * 	- 有 @PreAuthorize 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：先鉴权在执行方法
			 * 	- 有 @PostAuthorize 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：先执行方法在鉴权
			 * 	- 有 @PreFilter 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：对方法的参数列表做修改
			 * 	- 有 @PostFilter 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：对方法的返回值做修改
			 * */
			imports.add(PrePostMethodSecurityConfiguration.class.getName());
		}
		if (annotation.securedEnabled()) {
			// 同上。对 @Secured 先鉴权在执行方法
			imports.add(SecuredMethodSecurityConfiguration.class.getName());
		}
		if (annotation.jsr250Enabled()) {
			// 同上 对 @RolesAllowed、@DenyAll、@PermitAll 先鉴权在执行方法
			imports.add(Jsr250MethodSecurityConfiguration.class.getName());
		}
		return imports.toArray(new String[0]);
	}

	private static final class AutoProxyRegistrarSelector extends AdviceModeImportSelector<EnableMethodSecurity> {

		private static final String[] IMPORTS = new String[] { AutoProxyRegistrar.class.getName() };

		private static final String[] ASPECTJ_IMPORTS = new String[] {
				MethodSecurityAspectJAutoProxyRegistrar.class.getName() };

		@Override
		protected String[] selectImports(@NonNull AdviceMode adviceMode) {
			if (adviceMode == AdviceMode.PROXY) {
				return IMPORTS;
			}
			if (adviceMode == AdviceMode.ASPECTJ) {
				return ASPECTJ_IMPORTS;
			}
			throw new IllegalStateException("AdviceMode '" + adviceMode + "' is not supported");
		}

	}

}
