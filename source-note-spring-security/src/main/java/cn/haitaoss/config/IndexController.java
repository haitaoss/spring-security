package cn.haitaoss.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

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

    @RequestMapping("index")
    public Object index() {
        SecurityContext context = SecurityContextHolder.getContext();
        log.info("当前认证的用户信息：{}", context);
        return "ok...";
    }

    @Autowired
    private HttpServletRequest request;
    @RequestMapping("callback")
    public Object callback() {
        SecurityContext context = SecurityContextHolder.getContext();
        log.info("当前认证的用户信息：{}", context);
        return "ok...";
    }
}
