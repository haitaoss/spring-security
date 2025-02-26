/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.access.intercept;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Default implementation of <tt>FilterInvocationDefinitionSource</tt>.
 * <p>
 * Stores an ordered map of {@link RequestMatcher}s to <tt>ConfigAttribute</tt>
 * collections and provides matching of {@code FilterInvocation}s against the items stored
 * in the map.
 * <p>
 * The order of the {@link RequestMatcher}s in the map is very important. The <b>first</b>
 * one which matches the request will be used. Later matchers in the map will not be
 * invoked if a match has already been found. Accordingly, the most specific matchers
 * should be registered first, with the most general matches registered last.
 * <p>
 * The most common method creating an instance is using the Spring Security namespace. For
 * example, the {@code pattern} and {@code access} attributes of the
 * {@code <intercept-url>} elements defined as children of the {@code <http>} element are
 * combined to build the instance used by the {@code FilterSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class DefaultFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	protected final Log logger = LogFactory.getLog(getClass());

	private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

	/**
	 * Sets the internal request map from the supplied map. The key elements should be of
	 * type {@link RequestMatcher}, which. The path stored in the key will depend on the
	 * type of the supplied UrlMatcher.
	 * @param requestMap order-preserving map of request definitions to attribute lists
	 */
	public DefaultFilterInvocationSecurityMetadataSource(
			LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap) {
		this.requestMap = requestMap;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<>();
		this.requestMap.values().forEach(allAttributes::addAll);
		return allAttributes;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) {
		final HttpServletRequest request = ((FilterInvocation) object).getRequest();
		int count = 0;
		// 遍历
		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : this.requestMap.entrySet()) {
			/**
			 * request 匹配
			 */
			if (entry.getKey().matches(request)) {
				// 返回配置的属性(就是这个 request 对应的权限信息)
				return entry.getValue();
			}
			else {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Did not match request to %s - %s (%d/%d)", entry.getKey(),
							entry.getValue(), ++count, this.requestMap.size()));
				}
			}
		}
		// 说明没有对request配置权限，可以理解成无需权限就
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

}
