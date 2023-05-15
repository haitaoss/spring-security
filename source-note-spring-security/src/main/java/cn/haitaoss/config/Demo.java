package cn.haitaoss.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
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
@Controller
public class Demo implements WebMvcConfigurer, A {

	@GetMapping("/index3")
	@ResponseBody
	public Object index(/*@RequestParam("xx")*/ Demo Demo) {
		System.out.println("===");
		return "ok";
	}

	@Override
	public void addFormatters(FormatterRegistry registry) {
		registry.addConverter(new Converter<String, Demo>() {
			@Override
			public Demo convert(String source) {
				System.out.println("source = " + source);
				return new Demo();
			}
		});
	}

	@GetMapping("/index22")
	@ResponseBody
	@Override
	public Object index2(Object obj) {
		System.out.println("Demo = " + obj);
		return null;
	}

}
