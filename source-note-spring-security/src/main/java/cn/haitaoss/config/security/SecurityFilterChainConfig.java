package cn.haitaoss.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.Supplier;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;

@Component
@Slf4j
public class SecurityFilterChainConfig {
    @Bean
    @Order(1)
    public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
        /**
         * HttpSecurity 默认是使用了 AnonymousAuthenticationFilter，而这个Filter并没有认证的逻辑，只是简单的设置一个 SecurityContext 表示认证通过了。
         * 所以下面的配置的含义是 request中有nb这个参数就算是认证通过。
         *
         * HttpSecurity Bean 定义的代码
         *        {@link org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity()}
         *
         * Tips：HttpSecurity 默认是没有设置鉴权的，所以只需要认证通过了，就能访问到Servlet。
         */
        return http
                /**
                 * 设置 requestMatcher 属性，这是用来匹配request的，为true才会执行这个 SecurityFilterChain, 默认是匹配所有request
                 *
                 * Tips：SecurityFilterChain 的匹配是有优先级的，为true就直接使用。看
                 *        {@link org.springframework.security.web.FilterChainProxy#doFilterInternal}
                 */
                .securityMatcher(new RequestMatcher() {
                    @Override
                    public boolean matches(HttpServletRequest request) {
                        // 有 nb 参数就匹配
                        return Optional.ofNullable(request.getParameter("nb"))
                                .isPresent();
                    }
                })
                /**
                 * 1. 添加 RememberMeAuthenticationProvider
                 * 2. 添加 RememberMeAuthenticationFilter
                 *      作用：存在 remember-me cookie 就进行认证处理，认证失败说明cookie的信息不对，删除cookie而已，不会抛出异常
                 */
                .rememberMe()
                .and()
                /**
                 * 会间接注册 DaoAuthenticationProvider。它是用来完成认证的。
                 */
                .userDetailsService(new UserDetailsService() {
                    @Override
                    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                        return null;
                    }
                })
                /**
                 * 都没提供快速配置的configurer 说明不常用。
                 *
                 * 它属于认证 Filter，会根据请求头 Authorization=Digest xxx 的内容进行认证
                 */
                .addFilter(new DigestAuthenticationFilter())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
        http
                /**
                 * 设置 requestMatcher 属性，该属性是用来匹配request的，匹配了才执行这个Filter。默认不设置就匹配所有的request。
                 */
                .antMatcher("/f2/**")
                .securityMatcher(antMatcher("/f2/**"))
                .securityMatcher(regexMatcher("/f2/*"))
                .securityMatcher(new RequestMatcher() {
                    @Override
                    public boolean matches(HttpServletRequest request) {
                        return true;
                    }
                })
                .securityMatcher("/f2/**") // 建议使用这种方式配置，会集成SpringMVC配置的@RequestMapping的规则
                /**
                 * 注册 AuthenticationProvider。ProviderManager 会依赖 AuthenticationProvider 完成认证逻辑
                 */
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
                /**
                 * 配置鉴权规则。
                 * 会注册 AuthorizationFilter
                 */
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/f2/user/**").hasRole("USER")
                        .requestMatchers("/f2/x").authenticated() // 任何其他不符合上述规则的请求都需要身份验证
                        .requestMatchers("/f2/x").permitAll() // 放行
                        .requestMatchers("/f2/x").denyAll() // 任何尚未匹配的 URL 都将被拒绝访问。如果您不想意外忘记更新您的授权规则，这是一个很好的策略。
                        .requestMatchers("/f2/x").fullyAuthenticated()
                        .requestMatchers("/f2/db/**").access(AuthorizationManagers.allOf(
                                AuthorityAuthorizationManager.hasRole("ADMIN"),
                                AuthorityAuthorizationManager.hasRole("DBA")
                        ))
                        .anyRequest().rememberMe()
                        /**
                         * 添加 ObjectPostProcessor。将 AuthorizationFilter 注册到 http 之前，会使用 ObjectPostProcessor 做加工
                         * {@link org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer#configure}
                         */
                        .withObjectPostProcessor(new ObjectPostProcessor<AuthorizationFilter>() {
                            public <O extends AuthorizationFilter> O postProcess(O af) {
                                log.info("filterChain2....postProcess...{}", af);
                                return af;
                            }
                        }))
                // 添加认证方式
                .httpBasic(withDefaults())
                // 添加认证方式
                .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain filterChain3(HttpSecurity http) throws Exception {
        http
                /**
                 * 设置鉴权逻辑。
                 * 会注册 FilterSecurityInterceptor
                 *
                 * 会拼接成 SpEL 表达式，然后使用的 RootObject 是 SecurityExpressionRoot 类型的，所以才可以写 "hasRole('ADMIN') and hasRole('DBA')"
                 */
                .securityMatcher(/*"/login",*/ "/f3/**")
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/f3/xx").authenticated()
                        .requestMatchers("/f3/**").hasRole("xx")
                        .requestMatchers("/f3/xx2").access("hasRole('ADMIN') and hasRole('DBA')")
                        // 确保对我们应用程序的任何请求都需要对用户进行身份验证
                        .anyRequest().authenticated()
                )
                // 指定 http 使用的 AuthenticationProvider,可以设置多个
                .authenticationProvider(new AuthenticationProvider() {
                    @Override
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        return UsernamePasswordAuthenticationToken.authenticated(authentication.getPrincipal(),
                                authentication.getCredentials(), authentication.getAuthorities());
                    }

                    @Override
                    public boolean supports(Class<?> authentication) {
                        return true;
                    }
                })
                /**
                 * 1. 注册 UsernamePasswordAuthenticationFilter。request 匹配 配置的 loginProcessingUrl 才校验是否认证过
                 * 2.
                 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#doFilter(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)}
                 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#doFilter(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)}
                 */
                .formLogin(withDefaults())
                .formLogin(config -> config.loginProcessingUrl("/login"))
                /**
                 * 存在请求头 Authorization=BasicXxx 才需要判断是否认证过
                 * 注：匿名认证信息 不算认证过
                 * {@link org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)}
                 */
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    @Order(7)
    public SecurityFilterChain filterChain7(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/f7/**")
                /**
                 * 配置鉴权规则。
                 * 会注册 AuthorizationFilter
                 */
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/**").access(new AuthorizationManager<RequestAuthorizationContext>() {
                            @Override
                            public AuthorizationDecision check(Supplier authentication, RequestAuthorizationContext requestAuthorizationContext) {
                                log.info("自定义鉴权逻辑");
                                /**
                                 * 大致逻辑就根据请求的request路径、request method 查询权限表，得到权限对应的角色，然后判断当前认证的用户具备了角色 就算是有权限。
                                 */
                                return new AuthorizationDecision(true);
                            }
                        })
                )
                // 添加认证方式
                .httpBasic(withDefaults())
                // 添加认证方式
                .formLogin(withDefaults());
        return http.build();
    }
}
