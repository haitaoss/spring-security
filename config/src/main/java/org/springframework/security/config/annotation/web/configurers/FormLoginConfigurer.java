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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds form based authentication. All attributes have reasonable defaults making all
 * parameters are optional. If no {@link #loginPage(String)} is specified, a default login
 * page will be generated by the framework.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link UsernamePasswordAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated
 *
 * <ul>
 * <li>{@link AuthenticationEntryPoint}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link org.springframework.security.authentication.AuthenticationManager}</li>
 * <li>{@link RememberMeServices} - is optionally used. See {@link RememberMeConfigurer}
 * </li>
 * <li>{@link SessionAuthenticationStrategy} - is optionally used. See
 * {@link SessionManagementConfigurer}</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if present will be populated with
 * information from the configuration</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Shazin Sadakath
 * @since 3.2
 */
public final class FormLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, FormLoginConfigurer<H>, UsernamePasswordAuthenticationFilter> {

	/**
	 * Creates a new instance
	 * @see HttpSecurity#formLogin()
	 */
	public FormLoginConfigurer() {
		super(new UsernamePasswordAuthenticationFilter(), null);
		usernameParameter("username");
		passwordParameter("password");
	}

	/**
	 * <p>
	 * Specifies the URL to send users to if login is required. If used with
	 * {@link EnableWebSecurity} a default login page will be generated when this
	 * attribute is not specified.
	 * </p>
	 *
	 * <p>
	 * If a URL is specified or this is not being used in conjunction with
	 * {@link EnableWebSecurity}, users are required to process the specified URL to
	 * generate a login page. In general, the login page should create a form that submits
	 * a request with the following requirements to work with
	 * {@link UsernamePasswordAuthenticationFilter}:
	 * </p>
	 *
	 * <ul>
	 * <li>It must be an HTTP POST</li>
	 * <li>It must be submitted to {@link #loginProcessingUrl(String)}</li>
	 * <li>It should include the username as an HTTP parameter by the name of
	 * {@link #usernameParameter(String)}</li>
	 * <li>It should include the password as an HTTP parameter by the name of
	 * {@link #passwordParameter(String)}</li>
	 * </ul>
	 *
	 * <h2>Example login.jsp</h2>
	 *
	 * Login pages can be rendered with any technology you choose so long as the rules
	 * above are followed. Below is an example login.jsp that can be used as a quick start
	 * when using JSP's or as a baseline to translate into another view technology.
	 *
	 * <pre>
	 * <!-- loginProcessingUrl should correspond to FormLoginConfigurer#loginProcessingUrl. Don't forget to perform a POST -->
	 * &lt;c:url value="/login" var="loginProcessingUrl"/&gt;
	 * &lt;form action="${loginProcessingUrl}" method="post"&gt;
	 *    &lt;fieldset&gt;
	 *        &lt;legend&gt;Please Login&lt;/legend&gt;
	 *        &lt;!-- use param.error assuming FormLoginConfigurer#failureUrl contains the query parameter error --&gt;
	 *        &lt;c:if test="${param.error != null}"&gt;
	 *            &lt;div&gt;
	 *                Failed to login.
	 *                &lt;c:if test="${SPRING_SECURITY_LAST_EXCEPTION != null}"&gt;
	 *                  Reason: &lt;c:out value="${SPRING_SECURITY_LAST_EXCEPTION.message}" /&gt;
	 *                &lt;/c:if&gt;
	 *            &lt;/div&gt;
	 *        &lt;/c:if&gt;
	 *        &lt;!-- the configured LogoutConfigurer#logoutSuccessUrl is /login?logout and contains the query param logout --&gt;
	 *        &lt;c:if test="${param.logout != null}"&gt;
	 *            &lt;div&gt;
	 *                You have been logged out.
	 *            &lt;/div&gt;
	 *        &lt;/c:if&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="username"&gt;Username&lt;/label&gt;
	 *        &lt;input type="text" id="username" name="username"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="password"&gt;Password&lt;/label&gt;
	 *        &lt;input type="password" id="password" name="password"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;!-- if using RememberMeConfigurer make sure remember-me matches RememberMeConfigurer#rememberMeParameter --&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="remember-me"&gt;Remember Me?&lt;/label&gt;
	 *        &lt;input type="checkbox" id="remember-me" name="remember-me"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;div&gt;
	 *            &lt;button type="submit" class="btn"&gt;Log in&lt;/button&gt;
	 *        &lt;/div&gt;
	 *    &lt;/fieldset&gt;
	 * &lt;/form&gt;
	 * </pre>
	 *
	 * <h2>Impact on other defaults</h2>
	 *
	 * Updating this value, also impacts a number of other default values. For example,
	 * the following are the default values when only formLogin() was specified.
	 *
	 * <ul>
	 * <li>/login GET - the login form</li>
	 * <li>/login POST - process the credentials and if valid authenticate the user</li>
	 * <li>/login?error GET - redirect here for failed authentication attempts</li>
	 * <li>/login?logout GET - redirect here after successfully logging out</li>
	 * </ul>
	 *
	 * If "/authenticate" was passed to this method it update the defaults as shown below:
	 *
	 * <ul>
	 * <li>/authenticate GET - the login form</li>
	 * <li>/authenticate POST - process the credentials and if valid authenticate the user
	 * </li>
	 * <li>/authenticate?error GET - redirect here for failed authentication attempts</li>
	 * <li>/authenticate?logout GET - redirect here after successfully logging out</li>
	 * </ul>
	 * @param loginPage the login page to redirect to if authentication is required (i.e.
	 * "/login")
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	@Override
	public FormLoginConfigurer<H> loginPage(String loginPage) {
		return super.loginPage(loginPage);
	}

	/**
	 * The HTTP parameter to look for the username when performing authentication. Default
	 * is "username".
	 * @param usernameParameter the HTTP parameter to look for the username when
	 * performing authentication
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> usernameParameter(String usernameParameter) {
		getAuthenticationFilter().setUsernameParameter(usernameParameter);
		return this;
	}

	/**
	 * The HTTP parameter to look for the password when performing authentication. Default
	 * is "password".
	 * @param passwordParameter the HTTP parameter to look for the password when
	 * performing authentication
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> passwordParameter(String passwordParameter) {
		getAuthenticationFilter().setPasswordParameter(passwordParameter);
		return this;
	}

	/**
	 * Forward Authentication Failure Handler
	 * @param forwardUrl the target URL in case of failure
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> failureForwardUrl(String forwardUrl) {
		failureHandler(new ForwardAuthenticationFailureHandler(forwardUrl));
		return this;
	}

	/**
	 * Forward Authentication Success Handler
	 * @param forwardUrl the target URL in case of success
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> successForwardUrl(String forwardUrl) {
		successHandler(new ForwardAuthenticationSuccessHandler(forwardUrl));
		return this;
	}

	@Override
	public void init(H http) throws Exception {
		/**
		 * 1. 更新认证的默认信息，比如设置 登录路径、登录路径 这些
		 * 2. 设置访问权限，默认是为 loginPage、loginProcessingUrl、failureUrl 设置不需要鉴权
		 * 3. 获取 ExceptionHandlingConfigurer 为其注册 LoginUrlAuthenticationEntryPoint
		 * */
		super.init(http);
		// 初始化 DefaultLoginPageGeneratingFilter 的配置信息
		initDefaultLoginFilter(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}

	/**
	 * Gets the HTTP parameter that is used to submit the username.
	 * @return the HTTP parameter that is used to submit the username
	 */
	private String getUsernameParameter() {
		return getAuthenticationFilter().getUsernameParameter();
	}

	/**
	 * Gets the HTTP parameter that is used to submit the password.
	 * @return the HTTP parameter that is used to submit the password
	 */
	private String getPasswordParameter() {
		return getAuthenticationFilter().getPasswordParameter();
	}

	/**
	 * If available, initializes the {@link DefaultLoginPageGeneratingFilter} shared
	 * object.
	 * @param http the {@link HttpSecurityBuilder} to use
	 */
	private void initDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !isCustomLoginPage()) {
			loginPageGeneratingFilter.setFormLoginEnabled(true);
			loginPageGeneratingFilter.setUsernameParameter(getUsernameParameter());
			loginPageGeneratingFilter.setPasswordParameter(getPasswordParameter());
			loginPageGeneratingFilter.setLoginPageUrl(getLoginPage());
			loginPageGeneratingFilter.setFailureUrl(getFailureUrl());
			loginPageGeneratingFilter.setAuthenticationUrl(getLoginProcessingUrl());
		}
	}

}
