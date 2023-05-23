package cn.haitaoss.config.security;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.stereotype.Component;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-23 21:28
 *
 * 方法鉴权的
 */
@Component
public class MethodSecurityConfig {
	@Bean
	public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
		return new DefaultMethodSecurityExpressionHandler();
	}

	@Bean
	public SecurityContextHolderStrategy securityContextHolderStrategy() {
		// 应当搞成和 Security Filter 中一样的
		return SecurityContextHolder.getContextHolderStrategy();
	}

	@Bean
	public GrantedAuthorityDefaults grantedAuthorityDefaults() {
		// 应当搞成和 Security Filter 中一样的
		return new GrantedAuthorityDefaults("HAITAO_");
	}

	@Bean
	public AuthorizationEventPublisher authorizationEventPublisher(ApplicationContext context) {
		return new SpringAuthorizationEventPublisher(context);
	}
}
