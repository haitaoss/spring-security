
package cn.haitaoss;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.acl.Permission;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.coyote.http11.Http11NioProtocol;
import sun.rmi.transport.proxy.HttpReceiveSocket;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.filter.DelegatingFilterProxy;

import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.COOKIES;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-05 10:44
 *
 */
public class Main /*extends AbstractSecurityWebApplicationInitializer*/ {
	/**
	 * AbstractSecurityWebApplicationInitializer 实现 WebApplicationInitializer 接口
	 *		注册 DelegatingFilterProxy 到 servletContext 中，注册的 filterName 是 springSecurityFilterChain。
	 *		DelegatingFilterProxy 是一个工具类，其 DelegatingFilterProxy.doFilter 是委托给 context.getName("springSecurityFilterChain",Filter.class) 执行
	 *
	 *		注：最终的目的是让name是 springSecurityFilterChain 的Filter生效。
	 *
	 * {@link org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext#createWebServer()
	 * 		SpringBoot的嵌入式和非嵌入式的Web容器都会找到IOC容器中类型是 ServletRegistrationBean、FilterRegistrationBean、ServletListenerRegistrationBean、Servlet、Filter、EventListener 的bean
	 * 		注册到 ServletContext 中。
	 *
	 * 		扩展：@ServletComponentScan 的作用是将标注了 @WebServlet、@WebFilter、@WebListener 的类映射成 ServletRegistrationBean、FilterRegistrationBean、ServletListenerRegistrationBean 类型的bean注册到容器中。
	 *
	 * {@link EnableWebSecurity}
	 * 		会注册名为 springSecurityFilterChain 到容器中
	 * */
	public static void main(String[] args) throws Exception {
		startTomcat();
	}

	public static void startTomcat() throws Exception {
		// 创建内嵌的Tomcat
		Tomcat tomcatServer = new Tomcat();

		// 设置Tomcat端口
		tomcatServer.setPort(8080);

		Connector connector = new Connector(Http11NioProtocol.class.getName());
		connector.setPort(8080);
		tomcatServer.getService()
				.addConnector(connector);
		tomcatServer.setConnector(connector);

		// 读取项目路径，加载项目资源
		StandardContext ctx = (StandardContext) tomcatServer.addWebapp(
				"/security", new File("source-note-spring-security/src/main/webapp").getAbsolutePath());

		// 不重新部署加载资源
		ctx.setReloadable(false);

		// 创建 WebRoot
		WebResourceRoot resources = new StandardRoot(ctx);

		// 指定编译后的 class 文件位置
		File additionalWebInfClasses = new File("source-note-spring-security/out/production/");

		// 添加web资源
		resources.addPreResources(new DirResourceSet(resources, "/", additionalWebInfClasses.getAbsolutePath(), "/"));
		// 启动内嵌的Tomcat
		tomcatServer.start();

		Thread thread = new Thread(() -> {
			// 堵塞，不退出程序
			tomcatServer.getServer()
					.await();
		});
		thread.setDaemon(false);
		thread.start();
	}
}
