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

package org.springframework.security.web.access.expression;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

/**
 * Voter which handles web authorisation decisions.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use {@link WebExpressionAuthorizationManager} instead
 */
@Deprecated
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {

	private final Log logger = LogFactory.getLog(getClass());

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

	@Override
	public int vote(Authentication authentication, FilterInvocation filterInvocation,
			Collection<ConfigAttribute> attributes) {
		Assert.notNull(authentication, "authentication must not be null");
		Assert.notNull(filterInvocation, "filterInvocation must not be null");
		Assert.notNull(attributes, "attributes must not be null");
		/**
		 * 获取配置的属性。
		 * 迭代 attributes 找到是 WebExpressionConfigAttribute 类型的就返回，也就是只会检验一个 ConfigAttribute
		 * */
		WebExpressionConfigAttribute webExpressionConfigAttribute = findConfigAttribute(attributes);
		// 为空，说明没设置权限信息
		if (webExpressionConfigAttribute == null) {
			this.logger
					.trace("Abstained since did not find a config attribute of instance WebExpressionConfigAttribute");
			// 弃权
			return ACCESS_ABSTAIN;
		}
		// 构造 EvaluationContext。
		EvaluationContext ctx = webExpressionConfigAttribute.postProcess(
				this.expressionHandler.createEvaluationContext(authentication, filterInvocation), filterInvocation);
		// 计算表达式
		boolean granted = ExpressionUtils.evaluateAsBoolean(webExpressionConfigAttribute.getAuthorizeExpression(), ctx);
		if (granted) {
			// 授权
			return ACCESS_GRANTED;
		}
		this.logger.trace("Voted to deny authorization");
		// 拒绝
		return ACCESS_DENIED;
	}

	private WebExpressionConfigAttribute findConfigAttribute(Collection<ConfigAttribute> attributes) {
		for (ConfigAttribute attribute : attributes) {
			// 适配类型直接 return，说明只会校验一个而已
			if (attribute instanceof WebExpressionConfigAttribute) {
				return (WebExpressionConfigAttribute) attribute;
			}
		}
		return null;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof WebExpressionConfigAttribute;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void setExpressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		this.expressionHandler = expressionHandler;
	}

}
