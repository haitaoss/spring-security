package cn.haitaoss.config;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-11 10:33
 *
 */
public class authorize_http_requests {
	@Bean
	SecurityFilterChain web(HttpSecurity http) throws Exception {
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

	@Configuration
	@EnableWebSecurity
	public class SecurityConfig {

		@Bean
		public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
	}

	@Configuration
	@EnableWebSecurity
	public class SecurityConfig2 {

		@Bean
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
	}

	public class MyCustomRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return false;
		}
	}

}
