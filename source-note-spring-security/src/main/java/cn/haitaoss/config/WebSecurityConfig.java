package cn.haitaoss.config;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-11 15:06
 *
 */

/**
 * 第一步是创建我们的 Spring Security Java 配置。该配置创建了一个称为 springSecurityFilterChain 的 Servlet 过滤器，它负责应用程序中的所有安全（保护应用程序 URL、验证提交的用户名和密码、重定向到登录表单等）。您可以在下面找到 Spring Security
 *
 * Spring Security 提供了一个基类 AbstractSecurityWebApplicationInitializer ，它将确保为您注册 springSecurityFilterChain 。我们使用 AbstractSecurityWebApplicationInitializer 的方式有所不同，这取决于我们是否已经在使用 Spring，或者 Spring Security 是否是我们应用程序中唯一的 Spring 组件。
 * */

@EnableWebSecurity
public class WebSecurityConfig extends AbstractSecurityWebApplicationInitializer {

	//	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build());
		return manager;
	}

	@Component
	public static class OverrideDefaultConfig {


		/**
		 * TODOHAITAO: 2023/5/18 设置了这个 就不能注册  SecurityFilterChain 是互斥的
		 * 但是会设置一个默认的 WebSecurityConfigurerAdapter，可以定义 ObjectPostProcessor 来处理默认的
		 * WebSecurityConfigurerAdapter 实现扩展，而不是通过 @Bean 注册 WebSecurityConfigurer，
		 * 至于 SecurityFilterChain 可以使用 HttpSecurity.build() 构造
		 *
		 * {@link WebSecurityConfiguration#springSecurityFilterChain()}
		 * */
		//		@Bean
		public WebSecurityConfigurer myWebSecurityConfigurer() {
			return new WebSecurityConfigurer() {
				@Override
				public void init(SecurityBuilder builder) throws Exception {
					System.out.println("myWebSecurityConfigurer...init");
				}

				@Override
				public void configure(SecurityBuilder builder) throws Exception {
					System.out.println("myWebSecurityConfigurer...configure");
				}
			};
		}

		@Bean
		public WebSecurityCustomizer myWebSecurityCustomizer() {
			return new WebSecurityCustomizer() {
				@Override
				public void customize(WebSecurity web) {
					System.out.println("myWebSecurityCustomizer...");
				}
			};
		}
		/**
		 * AuthenticationConfiguration
		 * {@link AuthenticationConfiguration#getAuthenticationManager()}
		 * @return
		 */
		@Bean
		public GlobalAuthenticationConfigurerAdapter myGlobalAuthenticationConfigurerAdapter() {
			return new GlobalAuthenticationConfigurerAdapter() {
				@Override
				public void init(AuthenticationManagerBuilder auth) throws Exception {
					System.out.println("myGlobalAuthenticationConfigurerAdapter...init");
				}

				@Override
				public void configure(AuthenticationManagerBuilder auth) throws Exception {
					System.out.println("myGlobalAuthenticationConfigurerAdapter...configure");
				}
			};
		}

		/**
		 * 密码的解析器
		 * @return
		 */
		@Bean
		public PasswordEncoder passwordEncoder() {
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}

		/**
		 * 用来设置默认的角色名称前缀的
		 * @return
		 */
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
		@Primary
		public ObjectPostProcessor<Object> myObjectPostProcessor(ObjectPostProcessor<Object> delegate) {
			return new ObjectPostProcessor<Object>() {
				@Override
				public <O> O postProcess(O object) {
					System.out.println("ObjectPostProcessor#postProcess..." + object.getClass().getSimpleName());
					return delegate.postProcess(object);
				}
			};
		}
	}

	@Component
	public static class SecurityFilterChainConfig {
		@Bean
		public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
			return http.build();
		}

		//	@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http
					// 会注册 FilterSecurityInterceptor
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


		//		@Order(1)
		//	@Bean
		public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
			http
					/**
					 * 设置 requestMatcher 属性，该属性是用来匹配request的，匹配了才执行这个Filter
					 * */
					.antMatcher("/api/**")
					.securityMatcher(antMatcher("/api/**"))
					.securityMatcher(regexMatcher("/admin/.*"))
					.securityMatcher(new MyCustomRequestMatcher())
					.securityMatcher("/admin/.*")
					// 设置 鉴权信息
					.authorizeHttpRequests(authorize -> authorize
							.requestMatchers("/user/**").hasRole("USER")
							.requestMatchers("/admin/**").hasRole("ADMIN")
							.anyRequest().hasRole("ADMIN") // 需要有角色
							.anyRequest().authenticated() // 任何其他不符合上述规则的请求都需要身份验证
							.anyRequest().permitAll() // 放行
							// 添加 ObjectPostProcessor
							.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
								public <O extends FilterSecurityInterceptor> O postProcess(
										O fsi) {
									fsi.setPublishAuthorizationSuccess(true);
									return fsi;
								}
							})
					)
					.authorizeHttpRequests(authorize -> authorize
							.requestMatchers("/resources/**", "/signup", "/about").permitAll()
							.requestMatchers("/admin/**").hasRole("ADMIN")
							.requestMatchers("/db/**")
							.access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasRole('DBA')"))
							// .requestMatchers("/db/**").access(AuthorizationManagers.allOf(AuthorityAuthorizationManager.hasRole("ADMIN"), AuthorityAuthorizationManager.hasRole("DBA")))
							.anyRequest().denyAll() // 任何尚未匹配的 URL 都将被拒绝访问。如果您不想意外忘记更新您的授权规则，这是一个很好的策略。
					)
					.authorizeHttpRequests(authorize -> authorize
							.requestMatchers(antMatcher("/user/**")).hasRole("USER")
							.requestMatchers(regexMatcher("/admin/.*")).hasRole("ADMIN")
							// 自定义 MyCustomRequestMatcher
							.requestMatchers(new MyCustomRequestMatcher()).hasRole("SUPERVISOR")
							.anyRequest().authenticated()
					)
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

}
