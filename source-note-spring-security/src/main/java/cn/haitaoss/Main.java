package cn.haitaoss;

import cn.haitaoss.config.mvc.WebMvcConfig;
import cn.haitaoss.config.security.OverrideDefaultConfig;
import cn.haitaoss.config.security.SecurityFilterChainConfig;
import cn.haitaoss.config.security.WebSecurityQuickStartConfig;
import cn.haitaoss.config.security.oauth2.OAuth2LoginConfig;
import cn.haitaoss.controller.IndexController;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractInterceptUrlConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StopWatch;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.FilterChain;
import javax.servlet.Servlet;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebListener;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-05 10:44
 */
@Slf4j
public class Main extends AbstractAnnotationConfigDispatcherServletInitializer {
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[0];
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class[]{
                // WebMVC 的配置
                WebMvcConfig.class,
                // WebSecurity 的配置
                WebSecurityQuickStartConfig.class,
                // 覆盖 WebSecurity 的默认配置
                OverrideDefaultConfig.class,
                // 验证常用的配置项
                SecurityFilterChainConfig.class,
                // 验证集成 OAuth2
                OAuth2LoginConfig.class,
                // 测试用的
                IndexController.class,
        };
    }

    @Override
    protected String[] getServletMappings() {
        return new String[]{"/"};
    }

    /**
     * {@link org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext#createWebServer()
     * 		SpringBoot的嵌入式和非嵌入式的Web容器都会找到IOC容器中类型是 ServletRegistrationBean、FilterRegistrationBean、ServletListenerRegistrationBean、
    Servlet、Filter、EventListener 的bean
     * 		注册到 ServletContext 中。
     *
     * 		扩展：@ServletComponentScan 的作用是将标注了 @WebServlet、@WebFilter、@WebListener 的类映射成 ServletRegistrationBean、FilterRegistrationBean、ServletListenerRegistrationBean 类型的bean注册到容器中。
     *
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
     */
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
     * AuthenticationEntryPoint 用户未认证但是访问了需要认证的页面，此时会通过 AuthenticationEntryPoint 让用户进入认证流程。
     * 比如 LoginUrlAuthenticationEntryPoint 是通过重定向或者转发的方式到登录页面让用户进行认证
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
     */
    /**
     * 请求被拦截，重定向到登录页面，登录后，会自动重定向到之前访问页面的原因
     *
     * requestCache 用以缓存原始request，比如认证通过后，就从 requestCache 中拿到原始请求，重定向到原来的页面
     * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
     * {@link org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler#onAuthenticationSuccess(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.springframework.security.core.Authentication)}
     * 		这个设置的重定向
     *        {@link org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer#configure(org.springframework.security.config.annotation.web.HttpSecurityBuilder)}
     */
    /**
     * 关键的类
     *
     * OAuth2LoginAuthenticationProvider
     *      {@link OAuth2LoginAuthenticationProvider#authenticate(Authentication)}
     *      1. 委托给 OAuth2AuthorizationCodeAuthenticationProvider 得到 OAuth2AuthorizationCodeAuthenticationToken
     *          1.1 校验第三方系统回调本系统传递的参数是正确的（主要是有授权码）
     *          1.2 根据授权码请求第三方系统提供的接口，获取 访问令牌
     *
     *      2. 调用 OAuth2UserService 得到用户信息
     *          可以自定义 OAuth2UserService 决定应该访问那些 OAuth2 接口得到更多用户信息（默认是根据访问令牌请求第三方的个人信息接口获取用户信息）
     *
     *      3. 构造出 OAuth2LoginAuthenticationToken。
     *
     */
    /**
     *
     *
     * @RegisteredOAuth2AuthorizedClient、@AuthenticationPrincipal、@CurrentSecurityContext
     */

    public static void main(String[] args) throws Exception {
        startTomcat();
//        test_spel();
    }

    private static void test_spel() {
        System.out.println("旧版的鉴权");
        StandardEvaluationContext standardEvaluationContext = new StandardEvaluationContext();

        Supplier<Authentication> authenticationSupplier = () -> new UsernamePasswordAuthenticationToken("", "");
        standardEvaluationContext.setRootObject(new SecurityExpressionRoot(authenticationSupplier) {
        });
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();

        Consumer<String> consumer = exp -> {
            try {
                Expression expression = spelExpressionParser.parseExpression(exp);
                Boolean value = expression.getValue(standardEvaluationContext, Boolean.class);
                System.out.println("value = " + value);
            } catch (ParseException e) {

            }
        };

        //        consumer.accept("permitAll");
        //        consumer.accept("denyAll");
        //        consumer.accept("authenticated");
        //        consumer.accept("isAuthenticated");
        //        consumer.accept("hasRole('ADMIN') and hasRole('DBA')");
        consumer.accept("getAuthentication.isAuthenticated()");
        System.out.println("新版本的鉴权");
        System.out.println(authenticationSupplier.get().isAuthenticated());
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
