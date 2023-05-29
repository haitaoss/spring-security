package cn.haitaoss.config.security.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.List;

import static org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;

@Component
@Import(MyOAuth2UserService.class)
@Slf4j
public class OAuth2LoginConfig {
    private String prefix = "/f4";
    //	private String prefix = "";
    private String host = "http://353b1af8.r9.cpolar.top";
    // private String host = "http://localhost:8080";

    public ObjectPostProcessor<Object> urlOpp(ObjectPostProcessor objectPostProcessor) {
        return new ObjectPostProcessor<Object>() {
            @Override
            public <O extends Object> O postProcess(O object) {
                String loginPageUrl = prefix + DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

                if (object instanceof DefaultLoginPageGeneratingFilter) {
                    // 默认登录页面的访问路径
                    DefaultLoginPageGeneratingFilter filter = (DefaultLoginPageGeneratingFilter) object;
                    filter.setLoginPageUrl(loginPageUrl);
                    filter.setLogoutSuccessUrl(loginPageUrl + "?logout");
                }
                if (object instanceof LoginUrlAuthenticationEntryPoint) {
                    /**
                     * 这是认证失败时，会使用 进入认证页面(说白了就是重定向到登录页面)，
                     * */
                    String loginFormUrl = ((LoginUrlAuthenticationEntryPoint) object).getLoginFormUrl();
                    log.warn("LoginUrlAuthenticationEntryPoint--->update before: {}", loginFormUrl);
                    try {
                        Field loginFormUrl1 = LoginUrlAuthenticationEntryPoint.class.getDeclaredField("loginFormUrl");
                        loginFormUrl1.setAccessible(true);
                        loginFormUrl1.set(object, loginPageUrl);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    log.warn("LoginUrlAuthenticationEntryPoint--->update after: {}", loginFormUrl);
                }

                return (O) objectPostProcessor.postProcess(object);
            }
        };
    }

    @Bean
    @Order(4)
    public SecurityFilterChain filterChain4(HttpSecurity http, ObjectPostProcessor objectPostProcessor) throws Exception {
        /**
         *
         * 访问 http://localhost:8080/security/f4/img/img.png
         * 因为该资源是需要认证才允许访问，所以重定向到登录页面   http://localhost:8080/security/f4/login
         * 点击登录页面生成的 GitHub超链接 http://localhost:8080/security/f4/oauth2/authorization/github
         * 会被 OAuth2AuthorizationRequestRedirectFilter 匹配授权地址，所以会设置重定向信息
         * 将重定向到 https://github.com/login/oauth/authorize?response_type=code&client_id=8117171eab928ac5e561&scope=read:user&state=pI5zlpURjAd9FYWfB_VHj7DZdr0kW0DmORj7ekdAbLM%3D&redirect_uri=http://localhost:8080/security/f4/login/oauth2/code/github
         * 在授权页面登录后，第三方会重定向回我们配置的 callBackUrl  http://localhost:8080/security/f4/login/oauth2/code/github?code=8853f32ea635770f6481&state=pI5zlpURjAd9FYWfB_VHj7DZdr0kW0DmORj7ekdAbLM%3D
         * 会被 OAuth2LoginAuthenticationFilter 匹配到 callBackUrl ，然后开始完成认证逻辑，
         * 认证逻辑其实就是 拿着code请求获取访问令牌的地址
         * */
        http
                .objectPostProcessor(urlOpp(objectPostProcessor))
                // 该Filter拦截的路径
                .securityMatcher(prefix + "/**")
                .authorizeHttpRequests(authorize -> authorize
                        // 所有请求都需要认证过才可以（匿名认证信息不算）
                        .anyRequest().authenticated())
                .apply(new DefaultLoginPageConfigurer<>())
                .and()
                .formLogin(config -> config
                        .loginProcessingUrl(prefix + "/login")

                        .failureUrl(prefix + "/login?error"))
                .logout(config -> config
                        .logoutRequestMatcher(new AntPathRequestMatcher(prefix + "/logout"))
                        .logoutSuccessUrl(prefix + "/login?logout"))
                /**
                 *
                 * 执行顺序：OAuth2AuthorizationRequestRedirectFilter -> OAuth2LoginAuthenticationFilter
                 *
                 * OAuth2LoginAuthenticationProvider
                 * OAuth2AuthorizationRequestRedirectFilter 用来根据地址重定向到登录 OAuth2 的授权页面的？
                 *      会使用 OAuth2AuthorizationRequestResolver 解析 request 对象，说白了就是构造出 第三方认证页面的url
                 *
                 * OAuth2LoginAuthenticationFilter 匹配的路径是 /login/oauth2/code/*
                 *
                 * Tips：OAuth2UserService、AuthorizationRequestCustomizer
                 *
                 * 授权时不需要 clientsecert 获取访问令牌时才需要
                 * {@link OAuth2RefreshTokenGrantRequestEntityConverter}
                 * */
                .oauth2Login(oAuth2LoginConfig -> oAuth2LoginConfig
                        // 设置 认证Filter 拦截的路径
                        .loginProcessingUrl(prefix + OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI)
                        // 设置认证失败要转发的地址
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler(prefix +
                                DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL
                                + "?" + ERROR_PARAMETER_NAME))
                        // 设置获取授权码的地址
                        .authorizationEndpoint(config -> config.baseUri(prefix
                                + OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI))
                )
        ;
        return http.build();
    }

    @Bean
    @Order(5)
    public SecurityFilterChain filterChain5(HttpSecurity http) throws Exception {
        http

                // 该Filter拦截的路径
                .securityMatcher("/f5" + "/**")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                /**
                 * OAuth2AuthorizationCodeAuthenticationProvider 授权码认证
                 * OAuth2AuthorizationRequestRedirectFilter 认证请求重定向
                 * OAuth2AuthorizationCodeGrantFilter 授权码
                 *
                 * 感觉没啥用啊，认证通过后也不会 设置 Authentication 到 SecurityContextHolder 中，只是会将
                 * 授权信息保存到 OAuth2AuthorizedClientRepository 而已。
                 * 而且它和 OAuth2LoginAuthenticationFilter 是互斥的，OAuth2LoginAuthenticationFilter 先执行，命中了 OAuth2LoginAuthenticationFilter
                 * 就不会执行 OAuth2LoginAuthenticationFilter 了
                 * */
                // .oauth2Client(Customizer.withDefaults())
                // 访问 http://localhost:8080/security/f5/oauth2/authorization/github 会重定向到 github 的授权页面
                .oauth2Client(config -> config.authorizationCodeGrant(authorizationCodeGrantConfigurer ->
                        authorizationCodeGrantConfigurer.authorizationRequestResolver(
                                new DefaultOAuth2AuthorizationRequestResolver(
                                        ((ApplicationContext) http.getSharedObjects().get(ApplicationContext.class)).getBean(ClientRegistrationRepository.class),
                                        // 授权重定向地址
                                        "/f5" + OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI)))
                )
                /**
                 * JwtAuthenticationProvider 或者 OpaqueTokenAuthenticationProvider
                 * BearerTokenAuthenticationFilter
                 *
                 * Tips：只是通过 JwtAuthenticationProvider 完成的 OAuth 的授权流程，其实可以直接使用 BearerTokenAuthenticationFilter 实现
                 * 单独的jwt的认证
                 *
                 *
                 * {@link JwtBearerTokenAuthenticationConverter#convert(Jwt)}
                 *
                 * 默认的行为好像只是负责将 token 解析成 Authentication 并不负责调第三方接口完成认证授权逻辑
                 * */
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .oauth2ResourceServer(config -> config
                        .jwt()
                        // 默认不设置就会从IOC容器中查找
                        .decoder(jwtDecoder()) // 用来解析 token 得到 Jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter()) // 将 Jwt 转成 认证信息
                )

        ;
        return http.build();
    }

    //	@Bean
    public JwtDecoder jwtDecoder() {
        return new JwtDecoder() {
            @Override
            public Jwt decode(String token) throws JwtException {
                return null;
            }
        };
    }

    //	@Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

	/*@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		// 配置 WebClient 。后续使用 WebClient 发送请求就会带上了访问令牌
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		oauth2Client.setDefaultOAuth2AuthorizedClient(true);
		return WebClient.builder()
				.apply(oauth2Client.oauth2Configuration())
				.build();
	}*/

    @Bean
    public ClientRegistration githubClientRegistration() {
        /**
         * ClientRegistration 是用来描述 服务方的信息。
         * 默认配置了的内容 {@link CommonOAuth2Provider#GITHUB}
         * */
        // https://github.com/settings/developers
        return CommonOAuth2Provider.GITHUB
                .getBuilder("github")
                /**
                 * 能写啥占位符看这里
                 *      {@link DefaultOAuth2AuthorizationRequestResolver#resolve(HttpServletRequest, String, String)}
                 * */
                .redirectUri(host + "{basePath}" + prefix + "/{action}/oauth2/code/{registrationId}")
                .clientId("8117171eab928ac5e561")
                .clientSecret("4df13fc394ca45ee3cfaa59c46cc44f8ffb780f0")
                .build();
    }

    @Bean
    public ClientRegistration giteeClientRegistration() {
        // https://gitee.com/api/v5/oauth_doc#/
        return ClientRegistration.withRegistrationId("gitee")
                .clientId("5f6822b7e20cd7a2cc36c73b377db9bccc4769a5f1bfd000b2930f6438108127")
                .clientSecret("be5d60e6cafb82321423df95f8acb99d0fcb7842d58cace423b9fd6d1a8fe11e")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 访问授权码的重定向地址参数
                // .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .redirectUri(host + "{basePath}" + prefix + "/{action}/oauth2/code/{registrationId}")
                // 表示权限范围
                .scope("user_info", "projects", "pull_requests", "issues", "notes", "keys", "hook", "groups", "gists", "enterprises")
                // 授权地址
                .authorizationUri("https://gitee.com/oauth/authorize")
                // 获取授权码地址
                .tokenUri("https://gitee.com/oauth/token")
                // 个人信息地址
                .userInfoUri("https://gitee.com/api/v5/user")
                // 个人信息地址 返回的报文中那个属性是用户的名字
                .userNameAttributeName("name")
                .clientName("Gitee")
                .build();
    }

    /**
     * 必要的
     *
     * @param clientRegistrations
     * @return
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(ObjectProvider<List<ClientRegistration>> clientRegistrations) {
        // ClientRegistrationRepository 是用来存储 ClientRegistration 的，用来检索出 ClientRegistration
        return new InMemoryClientRegistrationRepository(clientRegistrations.getIfAvailable());
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        /**
         * OAuth2AuthorizedClientService 用于存储、检索 OAuth2AuthorizedClient，
         * 其依赖 ClientRegistrationRepository 检索出 ClientRegistration 从而构造出 OAuth2AuthorizedClient
         * */
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    /**
     * 必要的
     *
     * @param authorizedClientService
     * @return
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        // OAuth2AuthorizedClientRepository 依赖 OAuth2AuthorizedClientService 完成具体的存储、查询逻辑
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }
}
