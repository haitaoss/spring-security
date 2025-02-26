package cn.haitaoss.config.mvc;

import cn.haitaoss.Main;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-09 15:49
 *
 */
@EnableWebMvc
@Slf4j
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry
                // request 匹配 这个规则
                .addResourceHandler("/**/*.png")
                /**
                 * 资源的前缀
                 * 注：因为IDEA运行 {@link Main#main} 时，将 out/production/resources 添加到 -classpath 参数了，所以放在 resources 目录下面的资源是可以找到的
                 */
                .addResourceLocations("classpath:/");
    }

    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        /**
         * 开启后缀通配符匹配
         * 比如，访问 /index /index.html /index.xx 都是符合 @RequestMapping("/index") 的
         */
        configurer.setUseSuffixPatternMatch(true);
    }
}
