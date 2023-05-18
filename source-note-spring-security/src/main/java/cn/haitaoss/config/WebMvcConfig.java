package cn.haitaoss.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-09 15:49
 *
 */
@EnableWebMvc
@ComponentScan
public class WebMvcConfig extends AbstractAnnotationConfigDispatcherServletInitializer implements WebMvcConfigurer {

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		ResourceHandlerRegistration resourceHandlerRegistration = registry.addResourceHandler("/**");
		resourceHandlerRegistration.addResourceLocations("classpath:/");
	}

	@Override
	public void configurePathMatch(PathMatchConfigurer configurer) {
		/**
		 * 开启后缀通配符匹配
		 * 比如，访问 /index /index.html /index.xx 都是符合 @RequestMapping("/index") 的
		 * */
		configurer.setUseSuffixPatternMatch(true);
	}


	@Override
	protected Class<?>[] getRootConfigClasses() {
		return new Class[0];
	}

	@Override
	protected Class<?>[] getServletConfigClasses() {
		return new Class[] {WebMvcConfig.class};
	}

	@Override
	protected String[] getServletMappings() {
		return new String[] {"/"};
	}
}
