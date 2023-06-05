package cn.haitaoss.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-18 17:21
 */
@RestController
@Slf4j
public class IndexController {
    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private WebInvocationPrivilegeEvaluator webInvocationPrivilegeEvaluator;

    @Autowired
    private HttpServletRequest request;

    @RequestMapping("*/index")
    public Object index(@AuthenticationPrincipal String name, @CurrentSecurityContext SecurityContext securityContext) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("当前认证的用户信息", SecurityContextHolder.getContext());
        return map;
    }

    @RequestMapping("*/index2")
    public Object index2(@CurrentSecurityContext SecurityContext securityContext) {
        // 可以使用这个bean很方便的校验当前认证的用户是由具备访问 /haitao 的权限
        boolean allowed = webInvocationPrivilegeEvaluator.isAllowed("/haitao", securityContext.getAuthentication());
        return "ok...";
    }

    @RequestMapping("*/oauth")
    public Object callback(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("当前认证的用户信息", SecurityContextHolder.getContext());
        map.put("oAuth2AuthorizedClient", oAuth2AuthorizedClient);
        return map;
    }


}
