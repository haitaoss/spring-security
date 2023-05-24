package cn.haitaoss.config.security;

import lombok.extern.slf4j.Slf4j;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class OverrideDefaultConfig {


	/**
	 * TODOHAITAO: 2023/5/18
	 *  设置了 WebSecurityConfigurer 就不能注册 SecurityFilterChain 了俩者是互斥的。
	 *  不建议注册 WebSecurityConfigurer，建议使用 HttpSecurity.build() 生成 SecurityFilterChain。
	 *  若两个都不注册，默认会使用 WebSecurityConfigurerAdapter，此时可以定义 ObjectPostProcessor 来处理 WebSecurityConfigurerAdapter
	 *
	 * {@link WebSecurityConfiguration#springSecurityFilterChain()}
	 * */
	//		@Bean
	public WebSecurityConfigurer myWebSecurityConfigurer() {
		return new WebSecurityConfigurer() {
			@Override
			public void init(SecurityBuilder builder) throws Exception {
				log.info("myWebSecurityConfigurer...init");
			}

			@Override
			public void configure(SecurityBuilder builder) throws Exception {
				log.info("myWebSecurityConfigurer...configure");
			}
		};
	}

	/**
	 * 用来定制 WebSecurity。看 {@link WebSecurityConfiguration#springSecurityFilterChain()}
	 * @return
	 */
	@Bean
	public WebSecurityCustomizer myWebSecurityCustomizer() {
		return new WebSecurityCustomizer() {
			@Override
			public void customize(WebSecurity web) {
				log.info("myWebSecurityCustomizer...");
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
				log.info("myGlobalAuthenticationConfigurerAdapter...init");
			}

			@Override
			public void configure(AuthenticationManagerBuilder auth) throws Exception {
				log.info("myGlobalAuthenticationConfigurerAdapter...configure");
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
	 *
	 * 使用的地方举例：
	 * 		{@link org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer#ExpressionUrlAuthorizationConfigurer(org.springframework.context.ApplicationContext)}
	 *
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
				log.info("ObjectPostProcessor#postProcess..." + object.getClass()
						.getSimpleName());
				return delegate.postProcess(object);
			}
		};
	}

	/**
	 * 记录 SecurityContext 的工具
	 * @return
	 */
	@Bean
	public SecurityContextHolderStrategy securityContextHolderStrategy() {
		return SecurityContextHolder.getContextHolderStrategy();
	}
}
