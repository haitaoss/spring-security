package cn.haitaoss.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@EnableWebSecurity
@Component
public class OAuth2LoginConfig {

    @Bean
    @Order(4)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().authenticated()
				)
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
				.oauth2Login(Customizer.withDefaults())
				/**
				 * OAuth2AuthorizationCodeAuthenticationProvider 授权码认证
				 * OAuth2AuthorizationRequestRedirectFilter 认真请求重定向
				 * OAuth2AuthorizationCodeGrantFilter 授权码
				 * */
				.oauth2Client();
        return http.build();
    }

    private ClientRegistration[] clientRegistrationArray() {
        /**
         * ClientRegistration 是用来描述 服务方的信息。
         * */
        return new ClientRegistration[]{
                CommonOAuth2Provider.GITHUB.getBuilder("github")
                        .clientId("8117171eab928ac5e561")
                        .clientSecret("4df13fc394ca45ee3cfaa59c46cc44f8ffb780f0")
                        .build()};

        /*return ClientRegistration.withRegistrationId("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();*/
    }


    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        // ClientRegistrationRepository 是用来存储 ClientRegistration 的，可用来检索出 ClientRegistration
        return new InMemoryClientRegistrationRepository(this.clientRegistrationArray());
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

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        // OAuth2AuthorizedClientRepository 依赖 OAuth2AuthorizedClientService 完成具体的存储、查询逻辑
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }
}
