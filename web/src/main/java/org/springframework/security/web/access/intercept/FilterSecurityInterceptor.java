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

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.*;
import java.io.IOException;

/**
 * Performs security handling of HTTP resources via a filter implementation.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of
 * type {@link FilterInvocationSecurityMetadataSource}.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @author Rob Winch
 * @deprecated Use {@link AuthorizationFilter} instead
 */
@Deprecated
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

	private FilterInvocationSecurityMetadataSource securityMetadataSource;

	private boolean observeOncePerRequest = true;

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 * @param arg0 ignored
	 *
	 */
	@Override
	public void init(FilterConfig arg0) {
	}

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 */
	@Override
	public void destroy() {
	}

	/**
	 * Method that is actually called by the filter chain. Simply delegates to the
	 * {@link #invoke(FilterInvocation)} method.
	 * @param request the servlet request
	 * @param response the servlet response
	 * @param chain the filter chain
	 * @throws IOException if the filter chain fails
	 * @throws ServletException if the filter chain fails
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		invoke(new FilterInvocation(request, response, chain));
	}

	public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	@Override
	public SecurityMetadataSource obtainSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
		this.securityMetadataSource = newSource;
	}

	@Override
	public Class<?> getSecureObjectClass() {
		return FilterInvocation.class;
	}

	public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
		// 是适配的（其实就是有标记）
		if (isApplied(filterInvocation) && this.observeOncePerRequest) {
			// 放行
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
			return;
		}
		// first time this request being called, so perform security checking
		if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
			// 设置标记
			filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
		}
		/**
		 * 执行前（会进行认证和鉴权）
		 * 1. 根据 request 获取为 request 配置的权限信息
		 * 2. 未认证过就进行认证。	AuthenticationManager#authenticate
		 * 2. 校验认证信息是否具备配置的权限	AccessDecisionManager#decide
		 * */
		InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
		try {
			// 放行
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
		}
		finally {
			/**
			 * 执行完(完成调用)。
			 * 根据 token.isContextHolderRefreshRequired() 决定是否更新 securityContextHolderStrategy 记录的 SecurityContext。
			 *
			 * 比如 {@link AbstractSecurityInterceptor#beforeInvocation(Object)} 会构造新的SecurityContext, 并将原来的SecurityContext
			 * 记录到 token 中，finallyInvocation 就是判断是否构造了新的SecurityContext，若是新的执行完之后 应当在这一步恢复SecurityContext
			 * */
			super.finallyInvocation(token);
		}
		/**
		 * 执行后。
		 *
		 * 回调 afterInvocationManager#decide 对返回值进行鉴权，但是 FilterSecurityInterceptor 没设置这个属性所以没有这个步骤。
		 * */
		super.afterInvocation(token, null);
	}

	private boolean isApplied(FilterInvocation filterInvocation) {
		return (filterInvocation.getRequest() != null)
				&& (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
	}

	/**
	 * Indicates whether once-per-request handling will be observed. By default this is
	 * <code>true</code>, meaning the <code>FilterSecurityInterceptor</code> will only
	 * execute once-per-request. Sometimes users may wish it to execute more than once per
	 * request, such as when JSP forwards are being used and filter security is desired on
	 * each included fragment of the HTTP request.
	 * @return <code>true</code> (the default) if once-per-request is honoured, otherwise
	 * <code>false</code> if <code>FilterSecurityInterceptor</code> will enforce
	 * authorizations for each and every fragment of the HTTP request.
	 */
	public boolean isObserveOncePerRequest() {
		return this.observeOncePerRequest;
	}

	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}

}
