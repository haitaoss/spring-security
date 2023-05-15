package cn.haitaoss.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.ResourceResolver;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;
import org.springframework.web.servlet.support.AbstractDispatcherServletInitializer;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-09 15:49
 *
 */
@EnableWebMvc
@Controller
@Import(Demo.class)
public class MvcConfig extends AbstractAnnotationConfigDispatcherServletInitializer implements WebMvcConfigurer {
	@Autowired
	private ApplicationContext context;

	@GetMapping("/index")
	@ResponseBody
	public Object index(@RequestParam("po") MvcConfig mvcConfig) {
		System.out.println("===");
		return "ok";
	}

	@Override
	public void addFormatters(FormatterRegistry registry) {
		registry.addConverter(new Converter<String, MvcConfig>() {
			@Override
			public MvcConfig convert(String source) {
				System.out.println("source = " + source);
				return new MvcConfig();
			}
		});
	}

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		ResourceHandlerRegistration resourceHandlerRegistration = registry.addResourceHandler("/**");
		resourceHandlerRegistration.addResourceLocations("classpath:/");
	}

	@Override
	protected Class<?>[] getRootConfigClasses() {
		return new Class[0];
	}

	@Override
	protected Class<?>[] getServletConfigClasses() {
		return new Class[] {MvcConfig.class};
	}

	@Override
	protected String[] getServletMappings() {
		return new String[] {"/"};
	}
}
