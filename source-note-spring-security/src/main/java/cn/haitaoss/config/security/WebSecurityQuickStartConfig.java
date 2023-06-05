package cn.haitaoss.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

import javax.servlet.DispatcherType;
import java.util.EnumSet;

/**
 * AbstractSecurityWebApplicationInitializer 它会注册 springSecurityFilterChain 到web容器中
 */
@EnableWebSecurity(debug = true)
@Slf4j
public class WebSecurityQuickStartConfig extends AbstractSecurityWebApplicationInitializer {
    @Override
    protected EnumSet<DispatcherType> getSecurityDispatcherTypes() {
        // 指定 Filter 拦截的方式
        EnumSet<DispatcherType> securityDispatcherTypes = super.getSecurityDispatcherTypes();
        securityDispatcherTypes.add(DispatcherType.FORWARD); // 增加拦截 forward
        return securityDispatcherTypes;
    }

    /**
     * 这是使用 SpringSecurity 的最低配置，有这个bean就会生成 DaoAuthenticationProvider ，会使用这个来完成认证逻辑。
     *
     * 配置逻辑在这里：
     *      {@link AuthenticationConfiguration#getAuthenticationManager()}
     *      {@link AuthenticationConfiguration#initializeUserDetailsBeanManagerConfigurer(ApplicationContext)}
     *
     * 使用(认证逻辑)在这里：
     *      {@link ProviderManager#authenticate(Authentication)}
     *
     * Tips：存在 UserDetailsService 就注册 DaoAuthenticationProvider，存在 AuthenticationProvider 就注册。AuthenticationProvider 的优先级比较高
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build());
        //		return manager;
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                log.info("加载用户信息--->{}", username);
                return manager.loadUserByUsername(username);
            }
        };

    }

    /**
     * 自定义 AuthenticationProvider 用来实现认证的
     *
     * 配置逻辑在这里：
     *      {@link AuthenticationConfiguration#getAuthenticationManager()}
     *      {@link AuthenticationConfiguration#initializeAuthenticationProviderBeanManagerConfigurer(ApplicationContext)}
     *
     * 使用(认证逻辑)在这里：
     *      {@link ProviderManager#authenticate(Authentication)}
     *
     * TODOHAITAO: 2023/5/19
     *     注册 UserDetailsService 或者 AuthenticationProvider 的意义在于指定兜底的 AuthenticationProvider
     *	   默认依赖注入的 HttpSecurity 只设置了 AnonymousAuthenticationProvider 这个并不会验证用户名密码，所以意义不是特别大。
     *     当然也可以直接为 HttpSecurity 设置 AuthenticationProvider
     * @return
     */
    // @Bean
    public AuthenticationProvider myAuthenticationProvider() {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                // 标记为认证过 提供了这个静态方法
                UsernamePasswordAuthenticationToken result = UsernamePasswordAuthenticationToken.authenticated(
                        authentication.getPrincipal(), authentication.getCredentials(),
                        authentication.getAuthorities()
                );
                log.info("result = " + result);
                return result;
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
            }
        };
    }
}
