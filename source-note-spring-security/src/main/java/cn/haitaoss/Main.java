package cn.haitaoss;

import java.io.File;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.coyote.http11.Http11NioProtocol;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractInterceptUrlConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-05 10:44
 *
 */
@Slf4j
public class Main {
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
	 *
	 * {@link EnableGlobalAuthentication}
	 * {@link AuthenticationConfiguration}
	 *
	 * 深入研究：
	 * 	1. 进行认证的Filter： FilterSecurityInterceptor、AuthorizationFilter
	 * 	2. AuthenticationManager 是什么时候注册的？？？？
	 *            {@link org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity()}
	 *
	 * {@link org.springframework.security.config.annotation.web.configurers.PermitAllSupport#permitAll(HttpSecurityBuilder, RequestMatcher...)}
	 * {@link ExpressionUrlAuthorizationConfigurer#ExpressionUrlAuthorizationConfigurer(ApplicationContext)}
	 *
	 * 认证
	 * XxxAuthenticationFilter
	 * {@link BasicAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
	 * {@link UsernamePasswordAuthenticationFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 * {@link AbstractAuthenticationProcessingFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 *
	 * {@link AuthenticationManager#authenticate(Authentication)}
	 *
	 * 鉴权
	 * {@link FilterSecurityInterceptor#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 * {@link AuthorizationFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 * {@link AccessDecisionManager#decide(Authentication, Object, Collection)}
	 *
	 * authenticationEntryPoint 是在认证失败时用来 决定作何种行为
	 * */
	/**
	 * AuthenticationManager 是用来实现认证逻辑的。根据request的信息构造出 Authentication 然后认证 Authentication 是否正确
	 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
	 * {@link org.springframework.security.authentication.ProviderManager#authenticate(org.springframework.security.core.Authentication)}
	 * {@link org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider#authenticate(org.springframework.security.core.Authentication)}
	 *
	 * 大致逻辑：
	 * 		1. 由 XxAuthenticationFilter 构造出 AuthenticationToken
	 * 		2. 调用 AuthenticationManager#authenticate 进行认证。默认是 ProviderManager 实例
	 * 		3. 遍历 AuthenticationProvider 使用适配 AuthenticationToken 的，进行认证 AuthenticationProvider#authenticate
	 * 		4. 没有符合的 AuthenticationProvider 委托给 parent 进行认证
	 **/
	/**
	 * AuthenticationEntryPoint 用户未认证但是访问了需要认证的页面，此时会通过 AuthenticationEntryPoint 让用户进入认证流程。比如 LoginUrlAuthenticationEntryPoint 是通过重定向或者转发的方式到登录页面让用户进行认证
	 *
	 * {@link ExceptionTranslationFilter#doFilter(HttpServletRequest, HttpServletResponse, FilterChain)}
	 * {@link org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
	 * {@link BasicAuthenticationFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
	 **/
	/**
	 * 鉴权逻辑
	 * AuthorizeHttpRequestsConfigurer (推荐)
	 * {@link AuthorizeHttpRequestsConfigurer#configure(HttpSecurityBuilder)}
	 * {@link AuthorizationFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 * {@link RequestMatcherDelegatingAuthorizationManager#check(Supplier, HttpServletRequest)}
	 *
	 * 校验逻辑
	 * AuthorityAuthorizationManager
	 * AuthenticatedAuthorizationManager
	 * DaoAuthenticationProviderd
	 *
	 * ExpressionUrlAuthorizationConfigurer（过时）
	 * {@link AbstractInterceptUrlConfigurer#configure(HttpSecurityBuilder)}
	 * FilterSecurityInterceptor、ExpressionBasedFilterInvocationSecurityMetadataSource
	 * {@link FilterSecurityInterceptor#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 *
	 * {@link AffirmativeBased#decide(Authentication, Object, Collection)}
	 * SecurityExpressionRoot、WebSecurityExpressionRoot
	 * */
	/**
	 * 请求被拦截，重定向到登录页面，登录后，会自动重定向到之前访问页面的原因
	 * TODOHAITAO: 2023/5/19
	 *
	 * requestCache 用以缓存原始request，比如认证通过后，就从 requestCache 中拿到原始请求，重定向到原来的页面
	 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
	 * {@link org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler#onAuthenticationSuccess(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.springframework.security.core.Authentication)}
	 * 		这个设置的重定向
	 *        {@link org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer#configure(org.springframework.security.config.annotation.web.HttpSecurityBuilder)}
	 * */


	/**
	 * @EnableGlobalMethodSecurity 过时了，用 @EnableMethodSecurity
	 * 1. @Secured Spring Security 的 @PreAuthorize 、 @PostAuthorize 、 @PreFilter 和 @PostFilter 附带了丰富的基于表达式的支持。
	 * 2. 动态的更新 鉴权数据
	 * */


	/**
	 * 关键的类
	 * DelegatingFilterProxy FilterChainProxy
	 * WebSecurity
	 * HttpSecurity SecurityFilterChain
	 * AuthenticationManagerBuilder
	 * AuthenticationManager
	 * 		ProviderManager
	 * 		AuthenticationProvider
	 * 		DaoAuthenticationProvider
	 * FilterSecurityInterceptor 即将被替换成 AuthorizationFilter
	 * AuthenticationEntryPoint
	 * WebSecurityConfigurer
	 * WebSecurityConfigurerAdapter
	 * */

	public static void main(String[] args) throws Exception {
		startTomcat();
//		test_spel();
	}

	private static void test_spel() {
		StandardEvaluationContext standardEvaluationContext = new StandardEvaluationContext();

		SecurityExpressionRoot root = new SecurityExpressionRoot(
				() -> new UsernamePasswordAuthenticationToken("", "")) { };

		standardEvaluationContext.setRootObject(root);
		SpelExpressionParser spelExpressionParser = new SpelExpressionParser();

		Consumer<String> consumer = exp -> {
			try {
				Expression expression = spelExpressionParser.parseExpression(exp);
				Boolean value = expression.getValue(standardEvaluationContext, Boolean.class);
				System.out.println("value = " + value);
			}
			catch (ParseException e) {

			}
		};

		//        consumer.accept("permitAll");
		//        consumer.accept("denyAll");
		//        consumer.accept("authenticated");
		//        consumer.accept("isAuthenticated");
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
		Consumer<String> consumer = filePath -> {
			File additionalWebInfClasses = new File(filePath);

			// 添加web资源
			resources.addPreResources(new DirResourceSet(resources, "/", additionalWebInfClasses.getAbsolutePath(), "/"));
		};
		/*consumer.accept("source-note-spring-security/out/production/classes");
		consumer.accept("source-note-spring-security/out/production/resources");*/


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
