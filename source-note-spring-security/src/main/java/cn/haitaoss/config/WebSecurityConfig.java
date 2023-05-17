package cn.haitaoss.config;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-11 15:06
 *
 */
@EnableWebSecurity
public class WebSecurityConfig extends AbstractSecurityWebApplicationInitializer {
	/**
	 * 第一步是创建我们的 Spring Security Java 配置。该配置创建了一个称为 springSecurityFilterChain 的 Servlet 过滤器，它负责应用程序中的所有安全（保护应用程序 URL、验证提交的用户名和密码、重定向到登录表单等）。您可以在下面找到 Spring Security
	 *
	 * Spring Security 提供了一个基类 AbstractSecurityWebApplicationInitializer ，它将确保为您注册 springSecurityFilterChain 。我们使用 AbstractSecurityWebApplicationInitializer 的方式有所不同，这取决于我们是否已经在使用 Spring，或者 Spring Security 是否是我们应用程序中唯一的 Spring 组件。
	 * */

	@Bean
	public GrantedAuthorityDefaults grantedAuthorityDefaults() {
		// 设置 角色前缀
		return new GrantedAuthorityDefaults("HAITAO_");
	}


	/**
	 * 认证、鉴权的过程会使用这个发布事件
	 * @return
	 */
	@Bean
	public AuthenticationEventPublisher authenticationEventPublisher() {
		return new DefaultAuthenticationEventPublisher();
	}

	/**
	 * 使用的组件一般都会使用 ObjectPostProcessor 进行加工，所以
	 * 我们可以通过这个拦截
	 * @return
	 */
	@Bean
	public ObjectPostProcessor<Object> objectPostProcessor() {
		return new ObjectPostProcessor<Object>() {
			@Override
			public <O> O postProcess(O object) {
				System.out.println("ObjectPostProcessor#postProcess..." + object.getClass().getSimpleName());
				return object;
			}
		};
	}

//	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build());
		return manager;
	}

	/**
	 * 到目前为止，我们的 WebSecurityConfig 仅包含有关如何验证我们的用户的信息。 Spring Security 如何知道我们要要求所有用户都进行身份验证？ Spring Security 如何知道我们要支持基于表单的身份验证？实际上，有一个名为 SecurityFilterChain 的 bean 在后台被调用。它配置有以下默认实现：
	 *
	 * */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(authorize -> authorize
						// 确保对我们应用程序的任何请求都需要对用户进行身份验证
						.anyRequest().authenticated()
				)
				// 允许用户使用基于表单的登录进行身份验证
				.formLogin(withDefaults())
				// 允许用户使用 HTTP 基本身份验证进行身份验证
				/**
				 * {@link BasicAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
				 * */
				.httpBasic(withDefaults());
		return http.build();
	}


	@Order(1)
	//	@Bean
	public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
		http
				.antMatcher("/api/**")
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().hasRole("ADMIN")
				)
				.httpBasic(withDefaults());
		return http.build();
	}

//	@Bean
	public SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults());
		return http.build();
	}

	/**
	 * 虽然有充分的理由不直接公开每个属性，但用户可能仍需要更高级的配置选项。为了解决这个问题，Spring Security 引入了 ObjectPostProcessor 的概念，它可用于修改或替换由 Java 配置创建的许多对象实例。例如，如果您想在 FilterSecurityInterceptor 上配置 filterSecurityPublishAuthorizationSuccess 属性，您可以使用以下内容
	 * @param http
	 * @return
	 * @throws Exception
	 */
//	@Bean
	public SecurityFilterChain filterChain3(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(authorize -> authorize
						.anyRequest().authenticated()
						.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
							public <O extends FilterSecurityInterceptor> O postProcess(
									O fsi) {
								fsi.setPublishAuthorizationSuccess(true);
								return fsi;
							}
						})
				);
		return http.build();
	}

//	@Bean
	public SecurityFilterChain securityFilterChain6(HttpSecurity http) throws Exception {
		http
				.securityMatcher("/api/**")
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/user/**").hasRole("USER")
						.requestMatchers("/admin/**").hasRole("ADMIN")
						// 任何其他不符合上述规则的请求都需要身份验证
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults());
		return http.build();
	}

//	@Bean
	public SecurityFilterChain web(HttpSecurity http) throws Exception {
		http
				// ...
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/resources/**", "/signup", "/about").permitAll()
						.requestMatchers("/admin/**").hasRole("ADMIN")
						.requestMatchers("/db/**")
						.access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasRole('DBA')"))
						// .requestMatchers("/db/**").access(AuthorizationManagers.allOf(AuthorityAuthorizationManager.hasRole("ADMIN"), AuthorityAuthorizationManager.hasRole("DBA")))
						.anyRequest().denyAll() // 任何尚未匹配的 URL 都将被拒绝访问。如果您不想意外忘记更新您的授权规则，这是一个很好的策略。
				);

		return http.build();
	}

//	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.securityMatcher(antMatcher("/api/**"))
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers(antMatcher("/user/**")).hasRole("USER")
						.requestMatchers(regexMatcher("/admin/.*")).hasRole("ADMIN")
						// 自定义 MyCustomRequestMatcher
						.requestMatchers(new MyCustomRequestMatcher()).hasRole("SUPERVISOR")
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults());
		return http.build();
	}

	public class MyCustomRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return false;
		}
	}
}
