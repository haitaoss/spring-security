package cn.haitaoss.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-18 17:21
 *
 */
@RestController
@Slf4j
public class IndexController {
    @Autowired
    private ApplicationContext applicationContext;

    @RequestMapping("*/index")
    public Object index() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("当前认证的用户信息", SecurityContextHolder.getContext());
        return map;
    }

    @Autowired
    private HttpServletRequest request;

    @RequestMapping("*/oauth")
    public Object callback(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("当前认证的用户信息", SecurityContextHolder.getContext());
        map.put("oAuth2AuthorizedClient", oAuth2AuthorizedClient);
        return map;
    }
}
