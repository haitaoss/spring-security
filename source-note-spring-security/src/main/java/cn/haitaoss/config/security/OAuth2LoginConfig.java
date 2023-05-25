package cn.haitaoss.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.List;

import static org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;

@Component
@Slf4j
public class OAuth2LoginConfig {

    private String prefix = "/f4";
    private String host = "http://51d891ab.r2.cpolar.cn";
    // private String host = "http://localhost:8080";

    @Bean
    public ObjectPostProcessor<Object> loginUrlOpp() {
        // TODOHAITAO: 2023/5/25 自定义登录错误页面，设置授权失败 AuthenticationFailureHandler 定义重定向到 f4/login?error
        return new ObjectPostProcessor<Object>() {
            @Override
            public <O extends Object> O postProcess(O object) {
                String loginPageUrl = prefix + DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

                if (object instanceof DefaultLoginPageGeneratingFilter) {
                    // 默认登录页面的访问路径
                    DefaultLoginPageGeneratingFilter filter = (DefaultLoginPageGeneratingFilter) object;
                    filter.setLoginPageUrl(loginPageUrl);
                    filter.setFailureUrl(loginPageUrl + "?" + ERROR_PARAMETER_NAME);
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
                    } finally {
                    }
                    log.warn("LoginUrlAuthenticationEntryPoint--->update after: {}", loginFormUrl);

                }
                return object;
            }
        };
    }

    @Bean
    @Order(4)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // http://localhost:8080/security/oauth/haitao
        // http://2e1388aa.r2.cpolar.cn/security/login/
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

                .securityMatcher(prefix + "/**")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                /**
                 *
                 * 执行顺序：OAuth2AuthorizationRequestRedirectFilter -> OAuth2LoginAuthenticationFilter
                 *
                 * OAuth2LoginAuthenticationProvider
                 * OAuth2AuthorizationRequestRedirectFilter 用来根据地址重定向到登录 OAuth2 的授权页面的？
                 * OAuth2LoginAuthenticationFilter 匹配的路径是 /login/oauth2/code/*
                 *
                 * Tips：OAuth2UserService
                 * */
                .oauth2Login(oAuth2LoginConfig ->
                        oAuth2LoginConfig
                                .loginProcessingUrl(
                                        prefix + OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI)
                                .authorizationEndpoint(config -> config.baseUri(prefix
                                                                                + OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI))
                )

        /**
         * OAuth2AuthorizationCodeAuthenticationProvider 授权码认证
         * OAuth2AuthorizationRequestRedirectFilter 认真请求重定向
         * OAuth2AuthorizationCodeGrantFilter 授权码
         * */
        // .oauth2Client()
        ;
        return http.build();
    }

    @Bean
    public ClientRegistration githubClientRegistration() {
        /**
         * ClientRegistration 是用来描述 服务方的信息。
         * */
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
    public ClientRegistration googleClientRegistration() {
        return CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("undefined")
                .clientSecret("undefined")
                .build();
    }


    /**
     * 必要的
     * @param clientRegistrations
     * @return
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(ObjectProvider<List<ClientRegistration>> clientRegistrations) {
        // ClientRegistrationRepository 是用来存储 ClientRegistration 的，可用来检索出 ClientRegistration
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
