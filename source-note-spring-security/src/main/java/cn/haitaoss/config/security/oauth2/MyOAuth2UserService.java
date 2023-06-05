package cn.haitaoss.config.security.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-26 09:42
 *
 */
@Slf4j
public class MyOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 这是默认的逻辑。会访问第三方的个人用户信息接口
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(userRequest);
        log.info("MyOAuth2UserService.loadUser...accessToken is {}", userRequest.getAccessToken());
        return oAuth2User;
    }
}
