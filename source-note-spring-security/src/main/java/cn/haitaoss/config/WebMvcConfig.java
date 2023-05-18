package cn.haitaoss.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
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
		 * 过时了，可以改成这种写法，规定支持的后缀
		 * {@link #configureContentNegotiation}
		 * */
		configurer.setUseSuffixPatternMatch(true);
	}

	@Override
	public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
		configurer.mediaType("html", MediaType.TEXT_HTML);
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
