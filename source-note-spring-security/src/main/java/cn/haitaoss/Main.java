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
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractInterceptUrlConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
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
