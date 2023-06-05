/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * Allows registering Objects to participate with an {@link AutowireCapableBeanFactory}'s
 * post processing of {@link Aware} methods, {@link InitializingBean#afterPropertiesSet()}
 * , and {@link DisposableBean#destroy()}.
 *
 * @author Rob Winch
 * @since 3.2
 */
final class AutowireBeanFactoryObjectPostProcessor
		implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {

	private final Log logger = LogFactory.getLog(getClass());

	private final AutowireCapableBeanFactory autowireBeanFactory;

	private final List<DisposableBean> disposableBeans = new ArrayList<>();

	private final List<SmartInitializingSingleton> smartSingletons = new ArrayList<>();

	AutowireBeanFactoryObjectPostProcessor(AutowireCapableBeanFactory autowireBeanFactory) {
		Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
		this.autowireBeanFactory = autowireBeanFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}
		T result = null;
		try {
			/**
			 * 对 bean 进行初始化。
			 * 也就是会执行： 初始化前后置、初始化、初始化后置
			 */
			result = (T) this.autowireBeanFactory.initializeBean(object, object.toString());
		}
		catch (RuntimeException ex) {
			Class<?> type = object.getClass();
			throw new RuntimeException("Could not postProcess " + object + " of type " + type, ex);
		}
		/**
		 * 填充bean。
		 * 也就是完成bean的属性注入
		 */
		this.autowireBeanFactory.autowireBean(object);
		if (result instanceof DisposableBean) {
			/**
			 * 记录 DisposableBean 类型的 result。
			 * 因为 AutowireBeanFactoryObjectPostProcessor 实现了 DisposableBean 接口，
			 * 所以IOC容器在销毁bean的的时候会回调方法 {@link AutowireBeanFactoryObjectPostProcessor#destroy()}
			 */
			this.disposableBeans.add((DisposableBean) result);
		}
		if (result instanceof SmartInitializingSingleton) {
			/**
			 * 记录 SmartInitializingSingleton 类型的 result。
			 * 因为 AutowireBeanFactoryObjectPostProcessor 实现了 SmartInitializingSingleton 接口，
			 * 所以IOC容器在完成单例bean的创建后会回调方法 {@link AutowireBeanFactoryObjectPostProcessor#afterSingletonsInstantiated()}
			 */
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}

	@Override
	public void afterSingletonsInstantiated() {
		// 遍历记录的 SmartInitializingSingleton
		for (SmartInitializingSingleton singleton : this.smartSingletons) {
			// 回调
			singleton.afterSingletonsInstantiated();
		}
	}

	@Override
	public void destroy() {
		// 回调
		for (DisposableBean disposable : this.disposableBeans) {
			try {
				// 回调
				disposable.destroy();
			}
			catch (Exception ex) {
				this.logger.error(ex);
			}
		}
	}

}
