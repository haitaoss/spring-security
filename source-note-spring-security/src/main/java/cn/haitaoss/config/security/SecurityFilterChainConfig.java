package cn.haitaoss.config.security;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

@Component
public class SecurityFilterChainConfig {
	@Bean
	@Order(1)
	public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
		/**
		 * HttpSecurity 默认是使用了 AnonymousAuthenticationFilter，而这个Filter并没有认证的逻辑，只是简单的设置一个 SecurityContext 表示认证通过了。
		 * 所以下面的配置的含义是 request中有nb这个参数就算是认证通过。
		 *
		 * HttpSecurity Bean 定义的代码
		 * 		{@link org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity()}
		 *
		 * Tips：HttpSecurity 默认是没有设置鉴权的，所以只需要认证通过了，就能访问到Servlet。
		 * */
		return http
				/**
				 * 设置 requestMatcher 属性，这是用来匹配request的，为true才会执行这个 SecurityFilterChain
				 *
				 * Tips：SecurityFilterChain 的匹配是有优先级的，为true就直接使用。看
				 *        {@link org.springframework.security.web.FilterChainProxy#doFilterInternal}
				 * */
				.securityMatcher(new RequestMatcher() {
					@Override
					public boolean matches(HttpServletRequest request) {
						// 有 nb 参数就匹配
						return Optional.ofNullable(request.getParameter("nb"))
								.isPresent();
					}
				})
				.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
		http
				/**
				 * 设置鉴权逻辑。
				 * // 会注册 FilterSecurityInterceptor
				 * */
				.authorizeRequests(authorize -> authorize
						// 确保对我们应用程序的任何请求都需要对用户进行身份验证
						.anyRequest()
						.authenticated())
				// 指定 http 使用的 AuthenticationProvider,可以设置多个
				.authenticationProvider(new AuthenticationProvider() {
					@Override
					public Authentication authenticate(Authentication authentication) throws AuthenticationException {
						return null;
					}

					@Override
					public boolean supports(Class<?> authentication) {
						return false;
					}
				})
				// 允许用户使用基于表单的登录进行身份验证
				.formLogin(withDefaults())
				// 允许用户使用 HTTP 基本身份验证进行身份验证
				/**
				 * {@link org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal(HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)}
				 * */
				.httpBasic(withDefaults());
		return http.build();
	}


	//		@Order(1)
	//	@Bean
	public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
		http
				/**
				 * 设置 requestMatcher 属性，该属性是用来匹配request的，匹配了才执行这个Filter
				 * */.antMatcher("/api/**")
				.securityMatcher(antMatcher("/api/**"))
				.securityMatcher(regexMatcher("/admin/.*"))
				.securityMatcher(new MyCustomRequestMatcher())
				.securityMatcher("/admin/.*")
				.authenticationProvider(null)
				// 设置 鉴权信息
				.authorizeHttpRequests(authorize -> authorize.requestMatchers("/user/**")
						.hasRole("USER")
						.requestMatchers("/admin/**")
						.hasRole("ADMIN")
						.anyRequest()
						.hasRole("ADMIN") // 需要有角色
						.anyRequest()
						.authenticated() // 任何其他不符合上述规则的请求都需要身份验证
						.anyRequest()
						.permitAll() // 放行
						// 添加 ObjectPostProcessor
						.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
							public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
								fsi.setPublishAuthorizationSuccess(true);
								return fsi;
							}
						}))
				.authorizeHttpRequests(authorize -> authorize.requestMatchers("/resources/**", "/signup", "/about")
						.permitAll()
						.requestMatchers("/admin/**")
						.hasRole("ADMIN")
						.requestMatchers("/db/**")
						.access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasRole('DBA')"))
						// .requestMatchers("/db/**").access(AuthorizationManagers.allOf(AuthorityAuthorizationManager.hasRole("ADMIN"), AuthorityAuthorizationManager.hasRole("DBA")))
						.anyRequest()
						.denyAll() // 任何尚未匹配的 URL 都将被拒绝访问。如果您不想意外忘记更新您的授权规则，这是一个很好的策略。
				)
				.authorizeHttpRequests(authorize -> authorize.requestMatchers(antMatcher("/user/**"))
						.hasRole("USER")
						.requestMatchers(regexMatcher("/admin/.*"))
						.hasRole("ADMIN")
						// 自定义 MyCustomRequestMatcher
						.requestMatchers(new MyCustomRequestMatcher())
						.hasRole("SUPERVISOR")
						.anyRequest()
						.authenticated())
				// 添加认证方式
				.httpBasic(withDefaults())
				.formLogin(withDefaults());
		return http.build();
	}


	/**
	 * 虽然有充分的理由不直接公开每个属性，但用户可能仍需要更高级的配置选项。为了解决这个问题，Spring Security 引入了 ObjectPostProcessor 的概念，它可用于修改或替换由 Java 配置创建的许多对象实例。例如，如果您想在 FilterSecurityInterceptor 上配置 filterSecurityPublishAuthorizationSuccess 属性，您可以使用以下内容
	 * @return
	 * @throws Exception
	 */
	public class MyCustomRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return false;
		}
	}
}
