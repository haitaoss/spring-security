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

package org.springframework.security.access.vote;

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * Simple concrete implementation of
 * {@link org.springframework.security.access.AccessDecisionManager} that uses a
 * consensus-based approach.
 * <p>
 * "Consensus" here means majority-rule (ignoring abstains) rather than unanimous
 * agreement (ignoring abstains). If you require unanimity, please see
 * {@link UnanimousBased}.
 *
 * @deprecated Use {@link AuthorizationManager} instead
 */
@Deprecated
public class ConsensusBased extends AbstractAccessDecisionManager {

	private boolean allowIfEqualGrantedDeniedDecisions = true;

	public ConsensusBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}

	/**
	 * This concrete implementation simply polls all configured
	 * {@link AccessDecisionVoter}s and upon completion determines the consensus of
	 * granted against denied responses.
	 * <p>
	 * If there were an equal number of grant and deny votes, the decision will be based
	 * on the {@link #isAllowIfEqualGrantedDeniedDecisions()} property (defaults to true).
	 * <p>
	 * If every <code>AccessDecisionVoter</code> abstained from voting, the decision will
	 * be based on the {@link #isAllowIfAllAbstainDecisions()} property (defaults to
	 * false).
	 * @param authentication the caller invoking the method
	 * @param object the secured object
	 * @param configAttributes the configuration attributes associated with the method
	 * being invoked
	 * @throws AccessDeniedException if access is denied
	 */
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException {
		int grant = 0;
		int deny = 0;
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			/**
			 * 投票结果
			 * 		{@link org.springframework.security.web.access.expression.WebExpressionVoter#vote(Authentication, org.springframework.security.web.FilterInvocation, Collection)}
			 */
			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
			case AccessDecisionVoter.ACCESS_GRANTED:
				// 同意数加一
				grant++;
				break;
			case AccessDecisionVoter.ACCESS_DENIED:
				// 拒绝数加一
				deny++;
				break;
			default:
				break;
			}
		}
		// 同意数 大于 拒绝数
		if (grant > deny) {
			return;
		}
		// 拒绝数 大于 同意数
		if (deny > grant) {
			// 抛出异常
			throw new AccessDeniedException(
					this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
		}
		// 持平
		if ((grant == deny) && (grant != 0)) {
			// 默认是 true
			if (this.allowIfEqualGrantedDeniedDecisions) {
				return;
			}
			throw new AccessDeniedException(
					this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
		}
		// To get this far, every AccessDecisionVoter abstained
		checkAllowIfAllAbstainDecisions();
	}

	public boolean isAllowIfEqualGrantedDeniedDecisions() {
		return this.allowIfEqualGrantedDeniedDecisions;
	}

	public void setAllowIfEqualGrantedDeniedDecisions(boolean allowIfEqualGrantedDeniedDecisions) {
		this.allowIfEqualGrantedDeniedDecisions = allowIfEqualGrantedDeniedDecisions;
	}

}
