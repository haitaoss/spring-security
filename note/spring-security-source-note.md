# 说明

Author: [haitaoss](https://github.com/haitaoss)

源码阅读仓库: [spring-security](https://github.com/haitaoss/spring-security)

参考资料和需要掌握的知识：

- [Spring Security 官方文档](https://docs.spring.io/spring-security/reference/5.8/)
- [官方示例代码：spring-security-samples](https://github.com/spring-projects/spring-security-samples/tree/5.8.x)
- [Spring 源码分析](https://github.com/haitaoss/spring-framework)

# Spring Security 介绍

Spring Security 是一个提供身份验证、授权和针对常见攻击的保护的框架。提供了对 Servlet 和 WebFlux 应用的支持。

Spring Security 通过使用标准 Servlet `Filter` 与 Servlet 容器集成。这意味着它适用于在 Servlet 容器中运行的任何应用程序。更具体地说，只要是 Servlet 应用程序就能使用 Spring Security，并不一定是 Spring 应用。

Spring Security 通过 `WebFilter` 实现对 Spring WebFlux  的支持。

**也就是说 Spring Security 只能在 Servlet应用 或 Spring WebFlux 应用中使用。**


## IDEA 编译运行源码
![img.png](.spring-security-source-note_imgs/img.png)

[IDEA 配置 Ajc 可以看这里](https://github.com/haitaoss/spring-framework/blob/source-v5.3.10/note/spring-source-note.md#aspectj-compiler-%E9%85%8D%E7%BD%AE)

![img_1.png](.spring-security-source-note_imgs/img_1.png)
![img_5.png](.spring-security-source-note_imgs/img_5.png)
![img_4.png](.spring-security-source-note_imgs/img_4.png)

## 核心的项目模块

> Core --- `spring-security-core.jar`

该模块包含核心身份验证和访问控制类和接口、远程处理支持和基本供应 API。任何使用 Spring Security 的应用程序都需要它。它支持独立应用程序、远程客户端、方法（服务层）安全和 JDBC 用户配置。

> Config --- `spring-security-config.jar`

该模块包含 security namespace 解析代码 和 Java 配置代码。如果您使用 Spring Security XML 命名空间进行配置或 Spring Security 的 Java 配置支持，则需要它。

> source-note-spring-security

验证 SpringSecurity 功能的demo

# 核心源码

## AbstractSecurityWebApplicationInitializer
```java
/**
 * AbstractSecurityWebApplicationInitializer 实现 WebApplicationInitializer 接口
 *		注册 DelegatingFilterProxy 到 servletContext 中，注册的 filterName 是 springSecurityFilterChain。
 *		DelegatingFilterProxy 是一个工具类，其 DelegatingFilterProxy.doFilter 是委托给 context.getName("springSecurityFilterChain",Filter.class) 执行
 *
 *		注：最终的目的是将请求交给 name是 springSecurityFilterChain 的Filter处理
 */
```
## @EnableWebSecurity

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
/**
 * WebSecurityConfiguration：
 * 		- 会注册 FilterChainProxy , 这是 Security 接入 Servlet 容器的 Filter
 *
 * SpringWebMvcImportSelector：
 * 		- 扩展 HandlerMethodArgumentResolver，支持 @AuthenticationPrincipal、@CurrentSecurityContext、CsrfToken
 * 		- 注册 CsrfRequestDataValueProcessor 到容器中
 *
 * OAuth2ImportSelector：
 * 		- 注册 OAuth2AuthorizedClientArgumentResolver，支持 @RegisteredOAuth2AuthorizedClient
 *
 * HttpSecurityConfiguration：
 * 		- 注册 HttpSecurity , 是用来build得到 SecurityFilterChain 的工具
 */
@Import({WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class})
/**
 * 会注册这两个类型的bean ObjectPostProcessor、AuthenticationConfiguration
 */
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

	/**
	 * 为 true 会使用 DebugFilter 代理最终的 SecurityFilter，DebugFilter 的作用是
	 * doFilter 之前输出命中的 Filter 信息
	 */
	boolean debug() default false;

}
```

## WebSecurityConfiguration

[AuthenticationConfiguration 会注册默认的 ObjectPostProcessor](#AuthenticationConfiguration)

[HttpSecurityConfiguration 会注册 HttpSecurity](#HttpSecurityConfiguration)

```java
/**
 * 通过 @Autowired 注入：ObjectPostProcessor<Object>、List<SecurityFilterChain>、List<WebSecurityCustomizer>
 *      - ObjectPostProcessor<Object> 会由 AuthenticationConfiguration 注册
 *      - SecurityFilterChain 可由  HttpSecurity.build() 构造出
 *      - WebSecurityCustomizer 给用户定制 WebSecurity 的机会
 */
```
```java
/**
 *  实例化 WebSecurity
 *      1. 通过 objectPostProcessor 加工出 WebSecurity
 *          this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
 *
 *      2. 从 BeanFactory 中获取 WebSecurityConfigurer 类型的bean 并排序
 *          List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = beanFactory.getBeansOfType(WebSecurityConfigurer.class);
 *          webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE); // 排序
 * 		    this.webSecurityConfigurers = webSecurityConfigurers; // 设置为属性
 *
 *      3. 将 webSecurityConfigurer 应用到 webSecurity
 *          for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
 *              this.webSecurity.apply(webSecurityConfigurer);
 *          }
 */
```
```java
/**
 * 通过 @Bean 注册 Filter（beanName 叫 springSecurityFilterChain）
 *    1. 校验 webSecurityConfigurer 和 securityFilterChains 只能设置一个
 *    2. 两个都没设置，就应用一个默认配置
 *          注册 WebSecurityConfigurerAdapter 这个 configurer。这是用来注册默认的 SecurityFilterChain，其默认是拦截所有请求。
 *          而认证逻辑 需要IOC容器中有且仅有一个 [ UserDetailsService | AuthenticationProvider] 类型的bean 才行。
 *
 *          WebSecurityConfigurerAdapter adapter = this.objectObjectPostProcessor
 * 					.postProcess(new WebSecurityConfigurerAdapter() { });
 *          this.webSecurity.apply(adapter);
 *
 *    3. 遍历 securityFilterChains 注册到 webSecurity 中
 *          for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
 * 	            // 添加 SecurityFilterChainBuilder
 * 	            this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
 *          }
 *
 *    4. 遍历 WebSecurityCustomizer 对 webSecurity 进行自定义
 *          for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
 * 			    customizer.customize(this.webSecurity);
 *          }
 *
 *    5. 执行 build 得到 Filter
 *          return this.webSecurity.build();
 *
 *          5.1 回调 SecurityConfigurer#init
 *              比如 WebSecurityConfigurerAdapter ，其 init 方法就是为 webSecurity 添加 SecurityFilterChainBuilder
 *          5.2 回调 SecurityConfigurer#configure
 *          5.3 执行构建 webSecurity#performBuild
 *              - 遍历 webSecurity.securityFilterChainBuilders 执行 build 得到 List<SecurityFilterChain>
 *              - 构造出 new FilterChainProxy(securityFilterChains);
 */
```
```java
/**
 * 通过 @Bean 注册 DelegatingApplicationListener
 *     实现了 ApplicationListener<ApplicationEvent> 接口，
 *     会将收到的事件广播给适配的 ApplicationListener (DelegatingApplicationListener 内部的 ApplicationListener)
 *     比如
 *       {@link SessionManagementConfigurer#configure(HttpSecurityBuilder)} 会往 DelegatingApplicationListener 注册 ApplicationListener
 *       {@link AuthorizationFilter#doFilter(ServletRequest, ServletResponse, FilterChain)} 会发布事件
 *
 */
```
```java
/**
 * 通过 @Bean 注册 SecurityExpressionHandler<FilterInvocation>
 *   是一个工具类，是用来生成 SpEL 表达式的 RootObject 和 EvaluationContext
 *
 * 通过 @Bean 注册 WebInvocationPrivilegeEvaluator
 *   是一个工具类，可以在代码中使用 WebInvocationPrivilegeEvaluator 来实现声明式的权限校验
 *
 * 通过 @Bean 注册 BeanFactoryPostProcessor
 *   是 BeanFactoryPostProcessor 接口的实现类，用来给 BeanFactory 设置 类型转换的组件
 * 		    String ---> RSAPrivateKey
 * 		    String ---> RSAPublicKey
 */
```
## SpringWebMvcImportSelector

```java
/**
 * SpringWebMvcImportSelector
 *   会注册三个HandlerMethodArgumentResolver：
 *      - 处理有 @AuthenticationPrincipal 注解的参数
 *      - 处理有 @CurrentSecurityContext 注解的参数
 *      - 处理 CsrfToken 类型的参数
 */
```
## OAuth2ImportSelector

```java
/**
 * OAuth2ImportSelector
 *    注册 OAuth2AuthorizedClientArgumentResolver 处理有 @RegisteredOAuth2AuthorizedClient 注解的参数
 */
```

## HttpSecurityConfiguration

- 注册 HttpSecurity 到 BeanFactory 中可用来快速构造出 SecurityFilterChain
- [关联 AuthenticationConfiguration 中的 AuthenticationManager 作为兜底的 认证管理器](#HttpSecurityConfiguration)

```java
/**
 * 通过 @Autowired 注入：ObjectPostProcessor<Object>、AuthenticationConfiguration、SecurityContextHolderStrategy、ContentNegotiationStrategy
 *      - ObjectPostProcessor<Object> 会由 AuthenticationConfiguration 注册
 *      - AuthenticationConfiguration 使用 @EnableGlobalAuthentication 就会注册
 *      - SecurityContextHolderStrategy 是用于在一次请求上下文中共享认证信息。默认是 SecurityContextHolder.getContextHolderStrategy()
 *      - ContentNegotiationStrategy 默认是 HeaderContentNegotiationStrategy
 */
```

```java
@Bean(HTTPSECURITY_BEAN_NAME)
@Scope("prototype") // 原型的
HttpSecurity httpSecurity() throws Exception {
    /** 
     * 从 BeanFactory 中获取 PasswordEncoder 类型的bean 或者 使用 {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
     */
    WebSecurityConfigurerAdapter.LazyPasswordEncoder passwordEncoder = new WebSecurityConfigurerAdapter.LazyPasswordEncoder(
            this.context);
    // 是用来实现认证逻辑的，密码的匹配是依赖 passwordEncoder 实现的
    AuthenticationManagerBuilder authenticationBuilder = new WebSecurityConfigurerAdapter.DefaultPasswordEncoderAuthenticationManagerBuilder(
            this.objectPostProcessor, passwordEncoder);
    /**
     * 设置 parentAuthenticationManager 其目的是指定兜底的认证方式。
     *
     * 默认会通过 authenticationConfiguration.getAuthenticationManager() 得到，特点是根据容器中存在 UserDetailsService 或者 AuthenticationProvider 类型的bean就设置默认的 AuthenticationProvider
     * 		{@link AuthenticationConfiguration#getAuthenticationManager()}
     */
    authenticationBuilder.parentAuthenticationManager(authenticationManager());
    /**
     * 从IOC容器中获取 AuthenticationEventPublisher 没有就默认用 AuthenticationEventPublisher
     */
    authenticationBuilder.authenticationEventPublisher(getAuthenticationEventPublisher());
    /**
     * new 一个 HttpSecurity
     *
     * 会设置 setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
     */
    HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
    // 是用来设置、清空 securityContextHolderStrategy 中记录的 context
    WebAsyncManagerIntegrationFilter webAsyncManagerIntegrationFilter = new WebAsyncManagerIntegrationFilter();
    webAsyncManagerIntegrationFilter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
    // @formatter:off
    http
        /**
         * 会添加 CsrfConfigurer 它的作用是添加 CsrfFilter
         * 		{@link CsrfConfigurer#configure( HttpSecurityBuilder)}
         */
        .csrf(withDefaults())
        /**
         * webAsyncManagerIntegrationFilter 作为默认的 filter
         *
         * 注：filter 的类型是有限定的，必须是内置的类型，否则会报错。
         * 	内置的Filter类型看这里 {@link org.springframework.security.config.annotation.web.builders.FilterOrderRegistration#FilterOrderRegistration()}
         */
        .addFilter(webAsyncManagerIntegrationFilter)
        /**
         * 会添加 ExceptionHandlingConfigurer 它的作用是添加 ExceptionTranslationFilter
         * 		{@link ExceptionHandlingConfigurer#configure( HttpSecurityBuilder)}
         */
        .exceptionHandling(withDefaults())
        /**
         * 会添加 HeadersConfigurer 它的作用是添加 HeaderWriterFilter
         * 		{@link HeadersConfigurer#configure( HttpSecurityBuilder)}
         */
        .headers(withDefaults())
        /**
         * 会添加 SessionManagementConfigurer 它的作用是添加 SessionManagementFilter
         * 		{@link SessionManagementConfigurer#init( HttpSecurityBuilder)}
         * 		{@link SessionManagementConfigurer#configure( HttpSecurityBuilder)}
         */
        .sessionManagement(withDefaults())
        /**
         * 会添加 SecurityContextConfigurer 它的作用是添加 SecurityContextHolderFilter 或者 SecurityContextPersistenceFilter
         * 		{@link SecurityContextConfigurer#configure( HttpSecurityBuilder)}
         */
        .securityContext(withDefaults())
        /**
         * 会添加 RequestCacheConfigurer 它的作用是添加 RequestCacheAwareFilter
         * 		{@link RequestCacheConfigurer#init( HttpSecurityBuilder)}
         * 		{@link RequestCacheConfigurer#configure( HttpSecurityBuilder)}
         */
        .requestCache(withDefaults())
        /**
         * 会添加 AnonymousConfigurer 它的作用是添加 AnonymousAuthenticationFilter
         * 		{@link AnonymousConfigurer#init( HttpSecurityBuilder)}
         *		{@link AnonymousConfigurer#configure( HttpSecurityBuilder)}
         *
         * Tips: 这个很关键，默认会设置 AnonymousAuthenticationProvider 是用来实现认证的，这是最简单的认证方式。
         * 		可以理解成没有认证，因为认证的信息是由 AnonymousAuthenticationFilter 生成的，肯定能认证通过。
         */
        .anonymous(withDefaults())
        /**
         * 会添加 ServletApiConfigurer 它的作用是添加 SecurityContextHolderAwareRequestFilter
         * 		{@link ServletApiConfigurer#configure( HttpSecurityBuilder)}
         */
        .servletApi(withDefaults())
        /**
         * 会添加 DefaultLoginPageConfigurer 它的作用是添加 DefaultLoginPageGeneratingFilter、DefaultLogoutPageGeneratingFilter
         * 		{@link DefaultLoginPageConfigurer#init( HttpSecurityBuilder)}
         * 		{@link DefaultLoginPageConfigurer#configure( HttpSecurityBuilder)}
         */
        .apply(new DefaultLoginPageConfigurer<>());
    /**
     * 会添加 LogoutConfigurer 它的作用是添加 LogoutFilter
     * 		{@link LogoutConfigurer#init( HttpSecurityBuilder)}
     * 		{@link LogoutConfigurer#configure( HttpSecurityBuilder)}
     */
    http.logout(withDefaults());
    // @formatter:on
    /**
     * 读取 META-INF/spring.factories 文件 key是 `AbstractHttpConfigurer.class.getName()`
     * 添加到 http 中
     */
    applyDefaultConfigurers(http);
    return http;
}
```

## @EnableGlobalAuthentication

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
/** 
 * AuthenticationConfiguration:
 *  - 会注册 AutowireBeanFactoryObjectPostProcessor、AuthenticationManagerBuilder、GlobalAuthenticationConfigurerAdapter
 */
@Import(AuthenticationConfiguration.class)
@Configuration
public @interface EnableGlobalAuthentication {}
```

## AuthenticationConfiguration

1. 注册 AutowireBeanFactoryObjectPostProcessor
2. 可以注册 GlobalAuthenticationConfigurerAdapter 用来配置 AuthenticationManagerBuilder
3. 注册 AuthenticationManagerBuilder，用来生成兜底的 AuthenticationManager

```java
/**
 * 类上标注了 @Import(ObjectPostProcessorConfiguration.class) 而 ObjectPostProcessorConfiguration 会注册 AutowireBeanFactoryObjectPostProcessor 到容器中
 * 通过 @Autowired 注入：List<GlobalAuthenticationConfigurerAdapter>、ObjectPostProcessor<Object>
 *      - GlobalAuthenticationConfigurerAdapter
 *      - ObjectPostProcessor<Object> 会由 AuthenticationConfiguration 注册
 */
```
```java
/**
 * 通过 @Bean 注册三个 GlobalAuthenticationConfigurerAdapter：
 *  - EnableGlobalAuthenticationAutowiredConfigurer：它的职责是 获取有 @EnableGlobalAuthentication 注解的bean，会进行 getBean 将bean实例化出来，也就是提前初始化
 *
 *  - InitializeUserDetailsBeanManagerConfigurer：它的职责是为  AuthenticationManagerBuilder 添加 InitializeUserDetailsManagerConfigurer
 *      这个 configurer 功能是若IOC容器中只有一个 UserDetailsService 类型的bean，就构造一个 DaoAuthenticationProvider 设置给 AuthenticationManagerBuilder
 *
 *  - InitializeAuthenticationProviderBeanManagerConfigurer：它的职责是为  AuthenticationManagerBuilder 添加 InitializeAuthenticationProviderManagerConfigurer
 *      这个 configurer 的功能是若IOC容器中只有一个 AuthenticationProvider 类型的bean，就将其设置给 AuthenticationManagerBuilder
 */
```
```java
@Bean
public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
        ApplicationContext context) {
    /**
     * 特点是从 BeanFactory 中获取 PasswordEncoder 类型的bean 或者 使用 {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
     */
    LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
    /**
     * 尝试从IOC容器中获取 AuthenticationEventPublisher，拿不到就new一个默认的
     */
    AuthenticationEventPublisher authenticationEventPublisher = getAuthenticationEventPublisher(context);
    // 构造出 DefaultPasswordEncoderAuthenticationManagerBuilder
    DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(
            objectPostProcessor, defaultPasswordEncoder);
    if (authenticationEventPublisher != null) {
        // 设置事件发布器
        result.authenticationEventPublisher(authenticationEventPublisher);
    }
    return result;
}
```

## AuthenticationConfiguration#getAuthenticationManager

```java
public AuthenticationManager getAuthenticationManager() throws Exception {
    // 已经初始化了
    if (this.authenticationManagerInitialized) {
        // 直接返回
        return this.authenticationManager;
    }
    /**
     * 从IOC容器中获取 AuthenticationManagerBuilder
     * Tips：本类的 {@link #authenticationManagerBuilder} 方法注册了
     */
    AuthenticationManagerBuilder authBuilder = this.applicationContext.getBean(AuthenticationManagerBuilder.class);
    // 默认是false
    if (this.buildingAuthenticationManager.getAndSet(true)) {
        return new AuthenticationManagerDelegator(authBuilder);
    }
    /**
     * 遍历 globalAuthConfigurers
     *
     * Tips：
     * 	1. globalAuthConfigurers 是通过依赖注入得到的
     * 	2. 本类的 {@link #enableGlobalAuthenticationAutowiredConfigurer}、
     * 		{@link #initializeAuthenticationProviderBeanManagerConfigurer}、
     * 		{@link #initializeUserDetailsBeanManagerConfigurer} 方法注册了。
     *
     * Tips：
     * 		initializeAuthenticationProviderBeanManagerConfigurer 先执行，会判断IOC容器中存在 AuthenticationProvider 就设置给 authBuilder ，
     * 		initializeUserDetailsBeanManagerConfigurer 会判断IOC容器中存在 UserDetailsService 就设置 DaoAuthenticationProvider 给 authBuilder。
     *		不会设置两个，因为设置之前会判断是否有 {@link AuthenticationManagerBuilder#authenticationProviders} ,所以可以理解成两者是互斥的
     */
    for (GlobalAuthenticationConfigurerAdapter config : this.globalAuthConfigurers) {
        // 添加 config
        authBuilder.apply(config);
    }
    /**
     * 生成实例。最关键是回调注册的 config
     *
     * {@link AbstractConfiguredSecurityBuilder#doBuild()}
     * 		1. 回调 GlobalAuthenticationConfigurerAdapter#init
     * 		2. 回调 GlobalAuthenticationConfigurerAdapter#configure
     * 		3. 构造出实例对象
     */
    this.authenticationManager = authBuilder.build();
    // 为空
    if (this.authenticationManager == null) {
        // 尝试从容器中获取 AuthenticationManager 类型的bean
        this.authenticationManager = getAuthenticationManagerBean();
    }
    // 标记为 true
    this.authenticationManagerInitialized = true;
    return this.authenticationManager;
}
```

## @EnableMethodSecurity

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
/**
 * 默认是注册 InfrastructureAdvisorAutoProxyCreator，是用来实现动态代理AOP的
 * 然后注册各种 Advisor ，是用来指定那些bean需要AOP、AOP的增强逻辑是啥
 */
@Import(MethodSecuritySelector.class)
@Configuration
public @interface EnableMethodSecurity {
	boolean prePostEnabled() default true;
	boolean securedEnabled() default false;
	boolean jsr250Enabled() default false;
	boolean proxyTargetClass() default false;
	AdviceMode mode() default AdviceMode.PROXY;
}
```

## MethodSecuritySelector

```java
final class MethodSecuritySelector implements ImportSelector {

	private final ImportSelector autoProxy = new AutoProxyRegistrarSelector();

	@Override
	public String[] selectImports(@NonNull AnnotationMetadata importMetadata) {
		// 没有 @EnableMethodSecurity
		if (!importMetadata.hasAnnotation(EnableMethodSecurity.class.getName())) {
			// 返回空数组，表示啥都不注册到 BeanFactory 中，这是Spring的知识
			return new String[0];
		}
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		/**
		 * 获取默认要注入的配置类 {@link AutoProxyRegistrarSelector#selectImports(AdviceMode)}
		 * 默认是注册这个 AutoProxyRegistrar 它的作用是会注册 InfrastructureAdvisorAutoProxyCreator 到BeanFactory中，
		 * 其作用是根据从 BeanFactory 中获取 @Role(BeanDefinition.ROLE_INFRASTRUCTURE) 的 Advisor 类型的bean，完成动态代理实现的AOP
		 */
		List<String> imports = new ArrayList<>(Arrays.asList(this.autoProxy.selectImports(importMetadata)));
		// 根据注解属性值决定是否添加配置类
		if (annotation.prePostEnabled()) {
			/**
			 * 默认是启用的。
			 *
			 * 其实就是注册4个 Advisor：
			 * 	- 有 @PreAuthorize 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：先鉴权在执行方法
			 * 	- 有 @PostAuthorize 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：先执行方法在鉴权
			 * 	- 有 @PreFilter 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：对方法的参数列表做修改
			 * 	- 有 @PostFilter 的bean（方法或者类上有）就为bean创建代理对象，增强逻辑是：对方法的返回值做修改
			 */
			imports.add(PrePostMethodSecurityConfiguration.class.getName());
		}
		if (annotation.securedEnabled()) {
			// 同上。对 @Secured 先鉴权在执行方法
			imports.add(SecuredMethodSecurityConfiguration.class.getName());
		}
		if (annotation.jsr250Enabled()) {
			// 同上 对 @RolesAllowed、@DenyAll、@PermitAll 先鉴权在执行方法
			imports.add(Jsr250MethodSecurityConfiguration.class.getName());
		}
		return imports.toArray(new String[0]);
	}
}
```

## @AuthenticationPrincipal

[SpringWebMvcImportSelector](#SpringWebMvcImportSelector)

## @CurrentSecurityContext

[SpringWebMvcImportSelector](#SpringWebMvcImportSelector)

## @RegisteredOAuth2AuthorizedClient

[OAuth2ImportSelector](#OAuth2ImportSelector)

# 重要的类

## FilterChainProxy

![FilterChainProxy](.spring-security-source-note_imgs/FilterChainProxy.png)

FilterChainProxy 是一个 Filter ，默认是将 FilterChainProxy 注册到 Web容器中，从而将 Spring Security 的认证鉴权逻辑 应用到 Web应用中。

FilterChainProxy 有一个非常重要的属性 `filterChains`，可由 [HttpSecurity](#HttpSecurityConfiguration) 方便的构造出来 [SecurityFilterChain](#DefaultSecurityFilterChain)

```java
// 伪代码
public class FilterChainProxy extends GenericFilterBean {
    private List<SecurityFilterChain> filterChains;

    private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        /**
         * 遍历 SecurityFilterChain , SecurityFilterChain.matches(request) 匹配就返回 SecurityFilterChain.getFilters()
         * 所以说 List<SecurityFilterChain> 的先后顺序很重要，先匹配就会被使用。
         */
        List<Filter> filters = null;
        for (SecurityFilterChain securityFilterChain : this.filterChains) {
            // 匹配
            if (securityFilterChain.matches(request)) {
                // 返回
                filters = securityFilterChain.getFilters();
            }
        }
        // 没有找到
        if (filters == null || filters.size() == 0) {
            // 直接放行
            chain.doFilter(request, response);
            return;
        }

        // chain + filters 装饰成 VirtualFilterChain
        VirtualFilterChain virtualFilterChain = new VirtualFilterChain(request, chain, filters);
        // 执行。先执行 filters 在执行 chain
        virtualFilterChain.doFilter(request, response);
    }
}
```

## WebSecurity & HttpSecurity & AuthenticationManagerBuilder

![AbstractConfiguredSecurityBuilder](.spring-security-source-note_imgs/AbstractConfiguredSecurityBuilder.png)

```java
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
        extends AbstractSecurityBuilder<O> {
    @Override
    protected final O doBuild() throws Exception {
        synchronized (this.configurers) {
            // 初始化
            this.buildState = BuildState.INITIALIZING;
            // 预留的模板方法
            beforeInit();
            /**
             * 遍历设置的 List<SecurityConfigurer> ,回调 {@link SecurityConfigurer#init(SecurityBuilder)} 用来配置 this
             */
            init();
            this.buildState = BuildState.CONFIGURING;
            /**
             * 预留的模板方法
             *
             * {@link HttpSecurity#beforeConfigure()}
             * 		设置 setSharedObject(AuthenticationManager.class, this.authenticationManager);
             * 		这个很重要，AuthenticationManager 是用来实现认证、鉴权的
             */
            beforeConfigure();
            /**
             * 遍历设置的 List<SecurityConfigurer> ,回调 {@link SecurityConfigurer#configure(SecurityBuilder)} 用来配置 this
             */
            configure();
            this.buildState = BuildState.BUILDING;
            /**
             * 生成实例。主要是有这三个子类：
             *    {@link HttpSecurity#performBuild()}
             * 			new DefaultSecurityFilterChain(this.requestMatcher, sortedFilters);
             *    {@link WebSecurity#performBuild()}
             *			new FilterChainProxy(List<SecurityFilterChain>);
             *    {@link AuthenticationManagerBuilder#performBuild()}
             * 			new ProviderManager(this.authenticationProviders,this.parentAuthenticationManager);
             */
            O result = performBuild();
            this.buildState = BuildState.BUILT;
            return result;
        }
    }
}
```

### HttpSecurity#performBuild

```java
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
        implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {

    @Override
    protected DefaultSecurityFilterChain performBuild() {
        // 获取 ExpressionUrlAuthorizationConfigurer 类型的 configurer
        ExpressionUrlAuthorizationConfigurer<?> expressionConfigurer = getConfigurer(
                ExpressionUrlAuthorizationConfigurer.class);
        // 获取 AuthorizeHttpRequestsConfigurer 类型的 configurer
        AuthorizeHttpRequestsConfigurer<?> httpConfigurer = getConfigurer(AuthorizeHttpRequestsConfigurer.class);
        // 设置了一个
        boolean oneConfigurerPresent = expressionConfigurer == null ^ httpConfigurer == null;
        // expressionConfigurer 和 httpConfigurer 都设置了 就报错
        Assert.state((expressionConfigurer == null && httpConfigurer == null) || oneConfigurerPresent,"error...");
        /**
         * 排序。这一点很关键,决定Filter执行的先后顺序
         */
        this.filters.sort(OrderComparator.INSTANCE);
        List<Filter> sortedFilters = new ArrayList<>(this.filters.size());
        for (Filter filter : this.filters) {
            //	filters 记录的时候是 OrderedFilter 类型，所以这里强转一下
            sortedFilters.add(((OrderedFilter) filter).filter);
        }
        /**
         * 构造出 DefaultSecurityFilterChain
         * requestMatcher 默认是 AnyRequestMatcher.INSTANCE，其 {@link AnyRequestMatcher#matches(HttpServletRequest)} 一直返回 true
         *
         * 可以通过这些方法修改默认的值
         * 	- {@link #antMatcher}
         * 	- {@link #mvcMatcher}
         */
        return new DefaultSecurityFilterChain(this.requestMatcher, sortedFilters);
    }
}
```

### WebSecurity#performBuild

```java
public final class WebSecurity extends AbstractConfiguredSecurityBuilder<Filter, WebSecurity>
        implements SecurityBuilder<Filter>, ApplicationContextAware, ServletContextAware {
    @Override
    protected Filter performBuild() throws Exception {
        // 校验 securityFilterChainBuilders 不能是空
        Assert.state(!this.securityFilterChainBuilders.isEmpty(),"error");
        int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
        List<SecurityFilterChain> securityFilterChains = new ArrayList<>(chainSize);
        List<RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>>> requestMatcherPrivilegeEvaluatorsEntries = new ArrayList<>();
        // 遍历 ignoredRequests
        for (RequestMatcher ignoredRequest : this.ignoredRequests) {
            // 装饰成 DefaultSecurityFilterChain
            SecurityFilterChain securityFilterChain = new DefaultSecurityFilterChain(ignoredRequest);
            // 记录起来
            securityFilterChains.add(securityFilterChain);
            // 根据 securityFilterChain.getFilters() 筛选出 FilterSecurityInterceptor、AuthorizationFilter 用来构造 RequestMatcherEntry
            requestMatcherPrivilegeEvaluatorsEntries
                    .add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain));
        }
        // 遍历 securityFilterChainBuilders
        for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
            // build
            SecurityFilterChain securityFilterChain = securityFilterChainBuilder.build();
            // 记录起来
            securityFilterChains.add(securityFilterChain);
            // 根据 securityFilterChain.getFilters() 筛选出 FilterSecurityInterceptor、AuthorizationFilter 用来构造 RequestMatcherEntry
            requestMatcherPrivilegeEvaluatorsEntries
                    .add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain));
        }
        if (this.privilegeEvaluator == null) {
            // 默认用这个
            this.privilegeEvaluator = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
                    requestMatcherPrivilegeEvaluatorsEntries);
        }
        // 装饰成 FilterChainProxy
        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        if (this.httpFirewall != null) {
            filterChainProxy.setFirewall(this.httpFirewall);
        }
        if (this.requestRejectedHandler != null) {
            filterChainProxy.setRequestRejectedHandler(this.requestRejectedHandler);
        }
        // 回调方法，默认是啥都没干
        filterChainProxy.afterPropertiesSet();

        Filter result = filterChainProxy;
        // 开启了 debug
        if (this.debugEnabled) {
            /**
             * 装饰成 DebugFilter。
             * 作用：先打印 info 日志输出命中的 Filter 信息，再委托给 filterChainProxy 执行
             */
            result = new DebugFilter(filterChainProxy);
        }
        // 回调方法
        this.postBuildAction.run();
        return result;
    }
}
```

### AuthenticationManagerBuilder#performBuild

```java
public class AuthenticationManagerBuilder
        extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
        implements ProviderManagerBuilder<AuthenticationManagerBuilder> {
    @Override
    protected ProviderManager performBuild() throws Exception {
        // parentAuthenticationManager 和 authenticationProviders 都是空
        if (!isConfigured()) {
            // 返回 null
            return null;
        }
        // 依赖 authenticationProviders + parentAuthenticationManager 构造出 ProviderManager           
        ProviderManager providerManager = new ProviderManager(this.authenticationProviders,
                this.parentAuthenticationManager);
        if (this.eraseCredentials != null) {
            providerManager.setEraseCredentialsAfterAuthentication(this.eraseCredentials);
        }
        if (this.eventPublisher != null) {
            // 认证成功、失败 会使用 eventPublisher 发布事件             
            providerManager.setAuthenticationEventPublisher(this.eventPublisher);
        }
        // 使用 ObjectPostProcessor 加工
        providerManager = postProcess(providerManager);
        return providerManager;
    }
}
```

## DefaultSecurityFilterChain

DefaultSecurityFilterChain 是 SecurityFilterChain 的实现类，由 `RequestMatcher + List<Filter>` 组成。[FilterChainProxy](#FilterChainProxy) 会通过 `SecurityFilterChain#matches 得到唯一的 SecurityFilterChain` 然后将执行 `SecurityFilterChain#getFilters` 中的所有 Filter

```java
public interface SecurityFilterChain {
	boolean matches(HttpServletRequest request);
	List<Filter> getFilters();
}

public final class DefaultSecurityFilterChain implements SecurityFilterChain {

	private final RequestMatcher requestMatcher;

	private final List<Filter> filters;
    
	@Override
	public List<Filter> getFilters() {
		return this.filters;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.requestMatcher.matches(request);
	}

}
```

## ProviderManager

> [AbstractAuthenticationProcessingFilter](#AbstractAuthenticationProcessingFilter ) 依赖 AuthenticationManager 来完成认证逻辑。
>
> ProviderManager 是 AuthenticationManager 默认会使用的实现类，它聚合 `List<AuthenticationProvider>` 由 AuthenticationProvider 完成具体的认证逻辑。	
>
> 常见的 AuthenticationProvider 的实现类有 DaoAuthenticationProvider 和 OAuth2LoginAuthenticationProvider。
>
> DaoAuthenticationProvider 会依赖 UserDetailsService 获取真正的用户信息 然后与登录的用户进行密码匹配。
>
> OAuth2LoginAuthenticationProvider 会依赖 OAuth2UserService 获取真正的用户信息。

![AuthenticationManager](.spring-security-source-note_imgs/AuthenticationManager.png)

```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {
    @Override
    public Authentication authenticate(Authentication authentication) {
        // 认证的类型
        Class<? extends Authentication> toTest = authentication.getClass();
      
        // 遍历 AuthenticationProvider
        for (AuthenticationProvider provider : getProviders()) {
            // 不支持
            if (!provider.supports(toTest)) {
                // 跳过
                continue;
            }

            try {
                /**
                 * 使用 provider 进行认证
                 *   {@link AbstractUserDetailsAuthenticationProvider#authenticate(Authentication)}
                 */
                result = provider.authenticate(authentication);
                if (result != null) {
                    // 将 authentication 的内容拷贝给 result
                    copyDetails(authentication, result);
                    break;
                }
            } catch (AccountStatusException | InternalAuthenticationServiceException ex) {
                // 发布事件
                prepareException(ex, authentication);
                // 抛出异常                
                throw ex;
            } catch (AuthenticationException ex) {
                lastException = ex;
            }
        }
        // 没有认证结果 且 存在parent
        if (result == null && this.parent != null) {
            try {
                /**
                 * 委托给 parent 进行认证。可以理解成递归，因为 parent 默认也是 ProviderManager 类型的
                 */
                parentResult = this.parent.authenticate(authentication);
                result = parentResult;
            } catch (AuthenticationException ex) {
                parentException = ex;
                lastException = ex;
            }
        }
        if (result != null) {
            // parentResult == null 才发布，因为如果是通过 parent 获取的认证信息，parent 会发布事件
            if (parentResult == null) {
                // 发布事件
                this.eventPublisher.publishAuthenticationSuccess(result);
            }

            return result;
        }
                
        // 抛出异常
        throw lastException;
    }

}
```

## AuthenticationProvider

### DaoAuthenticationProvider

```java
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private PasswordEncoder passwordEncoder; // 用于匹配用户输入的密码 与 真实用户信息记录的密码

    private UserDetailsService userDetailsService; // 用于获取真实的用户信息

    public DaoAuthenticationProvider() {
        setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // 凭证为空
        if (authentication.getCredentials() == null) {
            // 抛出异常
            throw new BadCredentialsException("error");
        }
        // 获取凭证
        String presentedPassword = authentication.getCredentials().toString();
        // 使用 passwordEncoder 校验凭证不一致
        if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            // 抛出异常
            throw new BadCredentialsException("error");
        }
    }

    @Override
    protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        try {
            // 通过 UserDetailsService 加载 User
            UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
            // 没加载到
            if (loadedUser == null) {
                // 抛出异常
                throw new InternalAuthenticationServiceException("error");
            }
            return loadedUser;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

}
```



```java
public abstract class AbstractUserDetailsAuthenticationProvider
        implements AuthenticationProvider, InitializingBean, MessageSourceAware {
    @Override
    public Authentication authenticate(Authentication authentication) {
        /**
         * authentication 必须是 UsernamePasswordAuthenticationToken 类型的.
         * 比如: UsernamePasswordAuthenticationFilter 构造的 Authentication 就是 UsernamePasswordAuthenticationToken 类型的
         */
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, "error");
        // 提取出 username
        String username = determineUsername(authentication);
        boolean cacheWasUsed = true;
        // 尝试从缓存中获取
        UserDetails user = this.userCache.getUserFromCache(username);
        if (user == null) {
            // 标记没有缓存
            cacheWasUsed = false;
            try {
                /**
                 * 根据 username 检索出 user，这是真正的用户信息
                 *        {@link DaoAuthenticationProvider#retrieveUser(String, UsernamePasswordAuthenticationToken)}
                 *        {@link UserDetailsService#loadUserByUsername(String)}
                 */
                user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            } catch (UsernameNotFoundException ex) {
                this.logger.debug("Failed to find user '" + username + "'");
                if (!this.hideUserNotFoundExceptions) {
                    throw ex;
                }
                throw new BadCredentialsException(this.messages
                        .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }
            // 为空就报错。说明用户名根本就不对
            Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
        }
        try {
            /**
             * 前置认证检查。默认是检验 凭证不是过期的
             *    {@link DefaultPostAuthenticationChecks#check(org.springframework.security.core.userdetails.UserDetails)}
             */
            this.preAuthenticationChecks.check(user);
            /**
             * 进行附加检查。这是抽象方法看具体的子类是如何写的。
             *
             * 比如：{@link DaoAuthenticationProvider#additionalAuthenticationChecks(org.springframework.security.core.userdetails.UserDetails, org.springframework.security.authentication.UsernamePasswordAuthenticationToken)}
             * 			1.  authentication.getCredentials() 不能是空
             * 			2. 	使用 PasswordEncoder 校验 user.getPassword() 和 authentication.getCredentials() 是一致的
             */
            additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
        } catch (AuthenticationException ex) {
            // 不是缓存的值
            if (!cacheWasUsed) {
                // 直接抛出异常
                throw ex;
            }
            // 缓存的值校验错误，那就获取最新的信息 重新进行检查
            // There was a problem, so try again after checking
            // we're using latest data (i.e. not from the cache)
            cacheWasUsed = false;
            // 检索 user
            user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            // 前置认证检查
            this.preAuthenticationChecks.check(user);
            additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
        }
        // 后置认证检查
        this.postAuthenticationChecks.check(user);
        // 不是缓存
        if (!cacheWasUsed) {
            // 设置缓存
            this.userCache.putUserInCache(user);
        }
        Object principalToReturn = user;
        if (this.forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }
        // 装饰成 Authentication
        return createSuccessAuthentication(principalToReturn, authentication, user);
    }
}
```

### OAuth2LoginAuthenticationProvider 

```java
public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider;

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
    
    @Override
    public Authentication authenticate(Authentication authentication) {
        OAuth2LoginAuthenticationToken loginAuthenticationToken = (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken;
        try {
            // 获取访问令牌
            authorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) this.authorizationCodeAuthenticationProvider
                    /**
                     * {@link OAuth2AuthorizationCodeAuthenticationProvider#authenticate(Authentication)}
                     */
                    .authenticate(new OAuth2AuthorizationCodeAuthenticationToken(
                            loginAuthenticationToken.getClientRegistration(),
                            loginAuthenticationToken.getAuthorizationExchange()));
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error oauth2Error = ex.getError();
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        }
        // 拿到访问令牌
        OAuth2AccessToken accessToken = authorizationCodeAuthenticationToken.getAccessToken();
        Map<String, Object> additionalParameters = authorizationCodeAuthenticationToken.getAdditionalParameters();
        /**
         * 获取用户信息
         *    {@link DefaultOAuth2UserService#loadUser(OAuth2UserRequest)}
         * 	其实就是根据设置的 用户个人信息url + 访问令牌 请求url得到用户基本信息 构造出 OAuth2User
         */
        OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
                loginAuthenticationToken.getClientRegistration(), accessToken, additionalParameters));

        // 转换一下权限信息
        Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper
                .mapAuthorities(oauth2User.getAuthorities());

        // 构造出 OAuth2LoginAuthenticationToken
        OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
                loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange(),
                oauth2User, mappedAuthorities, accessToken, authorizationCodeAuthenticationToken.getRefreshToken());
        authenticationResult.setDetails(loginAuthenticationToken.getDetails());
        // 返回
        return authenticationResult;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
```

## Authentication

用户输入的认证信息(用户名、密码) 会装饰成 Authentication 对象，认证通过后 会将用户对应的权限数据设置到 Authentication 中

```java
public interface Authentication extends Principal, Serializable {
	Collection<? extends GrantedAuthority> getAuthorities(); // 具备的权限
	Object getCredentials(); // 密码
	Object getDetails();
	Object getPrincipal(); // 用户名
	boolean isAuthenticated();
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

## SecurityContext

装饰 Authentication

```java
public interface SecurityContext extends Serializable {
	Authentication getAuthentication();
	void setAuthentication(Authentication authentication);
}
```

## SecurityContextHolderStrategy

用于存储 SecurityContext ，目的是在一次**请求**中共享 SecurityContext，一般是通过 ThreadLocal 来存储。

[AbstractAuthenticationProcessingFilter](#AbstractAuthenticationProcessingFilter) 会在认证成功后执行 `SecurityContextHolderStrategy#setContext` 设置认证信息

```java
public interface SecurityContextHolderStrategy {

	void clearContext();

	SecurityContext getContext();

	default Supplier<SecurityContext> getDeferredContext() {
		return () -> getContext();
	}

	void setContext(SecurityContext context);

	default void setDeferredContext(Supplier<SecurityContext> deferredContext) {
		setContext(deferredContext.get());
	}

	SecurityContext createEmptyContext();

}
```

## SecurityContextRepository

用于存储 SecurityContext ，目的是在一次 **会话** 中共享 SecurityContext，一般就是通过 Cookie 或者 Session 来存储。

[AbstractAuthenticationProcessingFilter](#AbstractAuthenticationProcessingFilter) 会在认证成功后执行 `SecurityContextRepository#saveContext` 持久化认证信息

```java
public interface SecurityContextRepository {

	@Deprecated
	SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

	@Deprecated
	default Supplier<SecurityContext> loadContext(HttpServletRequest request) {
		return loadDeferredContext(request);
	}

	default DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
		Supplier<SecurityContext> supplier = () -> loadContext(new HttpRequestResponseHolder(request, null));
		return new SupplierDeferredSecurityContext(SingletonSupplier.of(supplier),
				SecurityContextHolder.getContextHolderStrategy());
	}

	void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

	boolean containsContext(HttpServletRequest request);

}
```

## AuthenticationEntryPoint

[ExceptionTranslationFilter](#ExceptionTranslationFilter) 捕获到 AuthenticationException 会执行 `AuthenticationEntryPoint#commence`  让用户进入认证流程。比如 LoginUrlAuthenticationEntryPoint 是通过重定向或者转发的方式到登录页面让用户进行认证。

```java
public interface AuthenticationEntryPoint {

	void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException;

}
```

## AccessDeniedHandler

[ExceptionTranslationFilter](#ExceptionTranslationFilter) 捕获到 AccessDeniedException 且 认证的用户 不是匿名用户、不是rememberMe用户 会执行 `AccessDeniedHandler#handle` 来处理异常，比如往响应体设置异常信息 或者 重定向到错误页面。

[CsrfFilter](#CsrfFilter) 也依赖 `AccessDeniedHandler#handle` 来处理伪造请求

```java
public class AccessDeniedException extends RuntimeException {

	public AccessDeniedException(String msg) {
		super(msg);
	}

	public AccessDeniedException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
```

## RequestCache

[ExceptionTranslationFilter](#ExceptionTranslationFilter) 捕获到 AuthenticationException 会执行`RequestCache.saveRequest(request, response)` 将request、response信息进行持久化(比如存到session中)，其目的是用于后面认证通过后可以恢复现场，简单来说就是可以重定向会一开始的访问地址。

```java
public interface RequestCache {

	void saveRequest(HttpServletRequest request, HttpServletResponse response);

	SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response);

	HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response);

	void removeRequest(HttpServletRequest request, HttpServletResponse response);

}
```

## AuthenticationSuccessHandler

[AbstractAuthenticationProcessingFilter](#AbstractAuthenticationProcessingFilter) 依赖 AuthenticationSuccessHandler 。AbstractAuthenticationProcessingFilter 校验**正确**用户输入的用户信息，就会执行`AuthenticationSuccessHandler#onAuthenticationSuccess `。比如 SavedRequestAwareAuthenticationSuccessHandler 是从 [RequestCache](#RequestCache) 中获取原先的访问路径，然后设置重定向地址，让浏览器冲过来定向会用户一开始的访问页面。

```java
public interface AuthenticationSuccessHandler {

	default void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		onAuthenticationSuccess(request, response, authentication);
		chain.doFilter(request, response);
	}

	void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException;

}
```



## AuthenticationFailureHandler

[AbstractAuthenticationProcessingFilter](#AbstractAuthenticationProcessingFilter) 依赖 AuthenticationFailureHandler。AbstractAuthenticationProcessingFilter 校验**错误**用户输入的用户信息，就会执行`AuthenticationFailureHandler#onAuthenticationFailure `。比如 SimpleUrlAuthenticationFailureHandler 是往Response设置错误信息或者重定向到配置的失败url地址。

```java
public interface AuthenticationFailureHandler {

	void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException;

}
```

## LogoutHandler

 [LogoutFilter](#LogoutFilter) 处理登出请求会执行 `LogoutHandler#logout`。默认是 SecurityContextLogoutHandler，它功能是：

1. 将 session 设置为无效的
2. 从 [SecurityContextHolderStrategy](#SecurityContextHolderStrategy ) 中移除 SecurityContext
3. [SecurityContextRepository](#SecurityContextRepository) 保存空的认证信息，相当于清空持久化的认证信息

```java
public interface LogoutHandler {

	void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication);

}
```

## LogoutSuccessHandler

 [LogoutFilter](#LogoutFilter) 处理登出请求，在 [LogoutHandler](#LogoutHandler) 成功执行完后会执行 `LogoutSuccessHandler#onLogoutSuccess`。默认是 SimpleUrlLogoutSuccessHandler，它功能是设置重定向信息，重定向到登录页面。

```java
public interface LogoutSuccessHandler {

	void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException;

}
```

## SecurityMetadataSource

[FilterSecurityInterceptor](#FilterSecurityInterceptor) 依赖 SecurityMetadataSource 获取 Request 配置的权限信息，默认用的是 DefaultFilterInvocationSecurityMetadataSource

```java
public class DefaultFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) {
		final HttpServletRequest request = ((FilterInvocation) object).getRequest();
		// 遍历
		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : this.requestMap.entrySet()) {
			/**
			 * request 匹配
			 */
			if (entry.getKey().matches(request)) {
				// 返回配置的属性(就是这个 request 对应的权限信息)
				return entry.getValue();
			}
		}
        // 说明没有对request配置权限，可以理解成无需权限就
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

}
```

## AccessDecisionManager

[FilterSecurityInterceptor](#FilterSecurityInterceptor) 依赖 AccessDecisionManager ，用来校验 认证的用户是否具备为 request 配置的权限。

AccessDecisionManager  有一个抽象子类 AbstractAccessDecisionManager ，它聚合 `List<AccessDecisionVoter>` ，鉴权是委托给 [AccessDecisionVoter](#AccessDecisionVoter ) 完成，AbstractAccessDecisionManager  是汇总全部 AccessDecisionVoter 的鉴权结果。比如它的三个实现类：

- [AffirmativeBased](#AffirmativeBased)（这是默认值）：拒绝数 大于 零 就抛出 AccessDeniedException，表示鉴权不通过
- [ConsensusBased](#ConsensusBased)：拒绝数 大于 同意数 就抛出 AccessDeniedException，表示鉴权不通过
- [UnanimousBased](#UnanimousBased)：满足配置的所有权限才表示鉴权通过

**这个API已经被标记为过时的**

![AccessDecisionManager](.spring-security-source-note_imgs/AccessDecisionManager-1686210329388.png)

### AffirmativeBased

```java
@Deprecated
public class AffirmativeBased extends AbstractAccessDecisionManager {

	public AffirmativeBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}

	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException {
		// 拒绝
		int deny = 0;
		// 遍历 决策选民
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			/**
			 * 投票结果
			 * {@link org.springframework.security.web.access.expression.WebExpressionVoter#vote}
			 */
			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
			case AccessDecisionVoter.ACCESS_GRANTED:
				return;
			case AccessDecisionVoter.ACCESS_DENIED:
				// 加一
				deny++;
				break;
			default:
				break;
			}
		}
		// 拒绝计数大于0
		if (deny > 0) {
			// 抛出异常
			throw new AccessDeniedException("error");
		}
		// 模板方法
		checkAllowIfAllAbstainDecisions();
	}
}
```

### ConsensusBased

```java
@Deprecated
public class ConsensusBased extends AbstractAccessDecisionManager {

	private boolean allowIfEqualGrantedDeniedDecisions = true;

	public ConsensusBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}
    
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException {
		int grant = 0;
		int deny = 0;
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			/**
			 * 投票结果
			 * 		{@link WebExpressionVoter#vote(Authentication, FilterInvocation, Collection)}
			 */
			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
			case AccessDecisionVoter.ACCESS_GRANTED:
				// 同意数加一
				grant++;
				break;
			case AccessDecisionVoter.ACCESS_DENIED:
				// 拒绝数加一
				deny++;
				break;
			default:
				break;
			}
		}
		// 同意数 大于 拒绝数
		if (grant > deny) {
			return;
		}
		// 拒绝数 大于 同意数
		if (deny > grant) {
			// 抛出异常
			throw new AccessDeniedException("");
		}
		// 持平
		if ((grant == deny) && (grant != 0)) {
			// 默认是 true
			if (this.allowIfEqualGrantedDeniedDecisions) {
				return;
			}
			throw new AccessDeniedException("");
		}

		checkAllowIfAllAbstainDecisions();
	}
}

```

### UnanimousBased

```java
@Deprecated
public class UnanimousBased extends AbstractAccessDecisionManager {

	public UnanimousBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	} 
    
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> attributes)
			throws AccessDeniedException {
		int grant = 0;
		List<ConfigAttribute> singleAttributeList = new ArrayList<>(1);
		singleAttributeList.add(null);
		/**
		 * 遍历 ConfigAttribute，投票结果都不能是拒绝。
		 *
		 * 因为大部分的 vote 逻辑，都是只要 authentication具备的权限 包含了 attributes 中的一个就算同意，并不是匹配具备所有 attribute 才算同意
		 * 比如：
		 * 		{@link RoleVoter#vote(Authentication, Object, Collection)}
		 *		{@link org.springframework.security.web.access.expression.WebExpressionVoter#vote}
		 */
		for (ConfigAttribute attribute : attributes) {
			singleAttributeList.set(0, attribute);
			for (AccessDecisionVoter voter : getDecisionVoters()) {
				/**
				 * 投票结果
				 * {@link WebExpressionVoter#vote}
				 */
				int result = voter.vote(authentication, object, singleAttributeList);
				switch (result) {
				case AccessDecisionVoter.ACCESS_GRANTED:
					grant++;
					break;
				case AccessDecisionVoter.ACCESS_DENIED:
					// 有否定的直接抛出异常，说明 必须全部 voter 的投票结果不能是拒绝
					throw new AccessDeniedException("");
				default:
					break;
				}
			}
		}

		if (grant > 0) {
			return;
		}

		checkAllowIfAllAbstainDecisions();
	}

}
```

## AccessDecisionVoter 

[AbstractAccessDecisionManager](#AccessDecisionManager ) 会依赖 AccessDecisionVoter  得到鉴权结果。[FilterSecurityInterceptor](#FilterSecurityInterceptor) 中配置的 [AccessDecisionManager](#AccessDecisionManager) 默认是只使用 WebExpressionVoter 进行鉴权

```java
@Deprecated
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

	@Override
	public int vote(Authentication authentication, FilterInvocation filterInvocation,
			Collection<ConfigAttribute> attributes) {
		/**
		 * 获取配置的属性。
		 * 迭代 attributes 找到是 WebExpressionConfigAttribute 类型的就返回，也就是只会检验一个 ConfigAttribute
		 */
		WebExpressionConfigAttribute webExpressionConfigAttribute = findConfigAttribute(attributes);
		// 为空，说明没设置权限信息
		if (webExpressionConfigAttribute == null) {
			// 弃权
			return ACCESS_ABSTAIN;
		}
		/** 
		 * 构造 EvaluationContext。其 RootObject 是 SecurityExpressionRoot 类型的，
		 * 所以 SpEL 表达式才可以写 "hasRole('ADMIN') and hasRole('DBA')"
		 * */
		EvaluationContext ctx = webExpressionConfigAttribute.postProcess(
				this.expressionHandler.createEvaluationContext(authentication, filterInvocation), filterInvocation);
		// 计算 SpEL 表达式 得到结果
		boolean granted = ExpressionUtils.evaluateAsBoolean(webExpressionConfigAttribute.getAuthorizeExpression(), ctx);
		if (granted) {
			// 授权
			return ACCESS_GRANTED;
		}
		// 拒绝
		return ACCESS_DENIED;
	}

	private WebExpressionConfigAttribute findConfigAttribute(Collection<ConfigAttribute> attributes) {
		for (ConfigAttribute attribute : attributes) {
			// 适配类型直接 return，说明只会校验一个而已
			if (attribute instanceof WebExpressionConfigAttribute) {
				return (WebExpressionConfigAttribute) attribute;
			}
		}
		return null;
	}
}
```

## AuthorizationManager

[AuthorizationFilter](#AuthorizationFilter) 会依赖  AuthorizationManager 完成鉴权逻辑，默认使用的是  RequestMatcherDelegatingAuthorizationManager

```java
public final class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

	private final Log logger = LogFactory.getLog(getClass());

	private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

	private RequestMatcherDelegatingAuthorizationManager(
			List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be empty");
		this.mappings = mappings;
	}
 	
    @Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s", request));
		}
		// 遍历注册的权限数据
		for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
			RequestMatcher matcher = mapping.getRequestMatcher();
			MatchResult matchResult = matcher.matcher(request);
			// request 满足 matcher，说明 request 配置了权限规则
			if (matchResult.isMatch()) {
				// 获取配置的 AuthorizationManager
				AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Checking authorization on %s using %s", request, manager));
				}
				/**
				 * {@link AuthenticatedAuthorizationManager#check(Supplier, Object)}
				 * 		鉴权：校验是否认证过(细分成 匿名认证、RememberMe认证、其他认证)
				 *
				 * {@link AuthorityAuthorizationManager#check(Supplier, Object)}
				 * 		鉴权：认证过 且 认证信息包含权限
				 */
				return manager.check(authentication,
						new RequestAuthorizationContext(request, matchResult.getVariables()));
			}
		}
		return null;
	}
}
```



# Security Filter

就是 Filter 接口的实现类，只不过没有直接注册到Web容器中，而是注册到 [SecurityFilterChain](#DefaultSecurityFilterChain) 中，而  SecurityFilterChain 又注册到 [FilterChainProxy](#FilterChainProxy) 中，FilterChainProxy 才是注册到Web容器中的Filter。

以下是 Spring Security Filter 排序的完整列表（定义在 FilterOrderRegistration 中）：
- ForceEagerSessionCreationFilter
- ChannelProcessingFilter
- WebAsyncManagerIntegrationFilter
- SecurityContextPersistenceFilter
- HeaderWriterFilter
- CorsFilter
- CsrfFilter
- LogoutFilter
- OAuth2AuthorizationRequestRedirectFilter
- Saml2WebSsoAuthenticationRequestFilter
- X509AuthenticationFilter
- AbstractPreAuthenticatedProcessingFilter
- CasAuthenticationFilter
- OAuth2LoginAuthenticationFilter
- Saml2WebSsoAuthenticationFilter
- UsernamePasswordAuthenticationFilter
- OpenIDAuthenticationFilter
- DefaultLoginPageGeneratingFilter
- DefaultLogoutPageGeneratingFilter
- ConcurrentSessionFilter
- DigestAuthenticationFilter
- BearerTokenAuthenticationFilter
- BasicAuthenticationFilter
- RequestCacheAwareFilter
- SecurityContextHolderAwareRequestFilter
- JaasApiIntegrationFilter
- RememberMeAuthenticationFilter
- AnonymousAuthenticationFilter
- OAuth2AuthorizationCodeGrantFilter
- SessionManagementFilter
- ExceptionTranslationFilter
- FilterSecurityInterceptor
- AuthorizationFilter
- SwitchUserFilter

## CsrfFilter

CsrfFilter 优先级，很高会在 [认证Filter](#AbstractAuthenticationProcessingFilter)、[异常处理Filter](#ExceptionTranslationFilter)、[鉴权Filter](#AuthorizationFilter) 之前执行。主要目的是生成 csrfToken 存到Request域中保证后续的Filter能用到，比如 DefaultLoginPageGeneratingFilter 会将 csrfToken  写到生成登录页中。因为 CsrfFilter  拦截到不是 `{"GET", "HEAD", "TRACE", "OPTIONS"} ` 的请求，会检验request中是否携带正确的 csrfToken，正确才执行后续的Filter，不正确就使用 [AccessDeniedHandler](#AccessDeniedHandler) 处理异常。

**总之 CsrfFilter  的目的是设置一个会话的标识(csrfToken )，请求带上正确的标识才允许访问。**

标识是通过 CsrfTokenRepository  存储、查询的。默认是用的 HttpSessionCsrfTokenRepository ，它会生成一个随机字符串存到 session 中，并将 sessionID 设置到 cookie 中交由浏览器存储。之后浏览器执行请求时就会把 cookie 传到服务器，HttpSessionCsrfTokenRepository  就会根据cookie记录的sessionID拿到session再从session中拿到 csrfToken 这个作为**真实值**，再从 request 的**请求头**或者**请求参数**中获取 csrfToken 这个作为**输入值**，输入值与真实值一致才允许访问。

CsrfFilter 是 HttpSecurity 会设置的默认值，看 [HttpSecurityConfiguration](#) 就明白了

```java
public final class CsrfFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository tokenRepository;
    private RequestMatcher requireCsrfProtectionMatcher = DEFAULT_CSRF_MATCHER;
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private CsrfTokenRequestHandler requestHandler = new CsrfTokenRequestAttributeHandler();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return Boolean.TRUE.equals(request.getAttribute(SHOULD_NOT_FILTER));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 生成 或者 从cookie、session... 中拿到 csrfToken
        DeferredCsrfToken deferredCsrfToken = this.tokenRepository.loadDeferredToken(request, response);
        /**
         * 设置到 request 中。
         * 比如 {@link DefaultLoginPageGeneratingFilter#generateLoginPageHtml(HttpServletRequest, boolean, boolean)} 会使用这个属性，拼接出 登录页面，
         * 从而保证能通过 {@link this#doFilterInternal} 的验证
         */
        request.setAttribute(DeferredCsrfToken.class.getName(), deferredCsrfToken);
        /**
         *  执行 requestHandler。一般就是设置属性而已，看具体的实现
         * {@link CsrfTokenRequestAttributeHandler#handle(HttpServletRequest, HttpServletResponse, Supplier)}
         */
        this.requestHandler.handle(request, response, deferredCsrfToken::get);
        /**
         * request 不满足规则，默认就是校验 requestMethod 是 {"GET", "HEAD", "TRACE", "OPTIONS"} 就放行
         * {@link DefaultRequiresCsrfMatcher#matches(HttpServletRequest)}
         */
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Did not protect against CSRF since request did not match "
                        + this.requireCsrfProtectionMatcher);
            }
            // 放行
            filterChain.doFilter(request, response);
            return;
        }
        CsrfToken csrfToken = deferredCsrfToken.get();
        /**
         * 拿到 token 。根据那么从请求头或者请求参数中
         * {@link CsrfTokenRequestHandler#resolveCsrfTokenValue(HttpServletRequest, CsrfToken)}
         */
        String actualToken = this.requestHandler.resolveCsrfTokenValue(request, csrfToken);
        // token 不一致
        if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
            boolean missingToken = deferredCsrfToken.isGenerated();
            this.logger.debug(
                    LogMessage.of(() -> "Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request)));
            AccessDeniedException exception = (!missingToken) ? new InvalidCsrfTokenException(csrfToken, actualToken)
                    : new MissingCsrfTokenException(actualToken);
            // 执行 accessDeniedHandler
            this.accessDeniedHandler.handle(request, response, exception);
            return;
        }
        // 放行
        filterChain.doFilter(request, response);
    }

}
```

## SessionManagementFilter

目的：通过 SecurityContextRepository 将 SecurityContext 进行持久化。比如存到Cookie、Session

SessionManagementFilter 是 HttpSecurity 会设置的默认值，看 [HttpSecurityConfiguration](#) 就明白了

```java
public class SessionManagementFilter extends GenericFilterBean {

    // 用于一次Request中存储认证信息的
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    // 用于一次会话中存储认证信息的
    private final SecurityContextRepository securityContextRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // 存在标记
        if (request.getAttribute(FILTER_APPLIED) != null) {
            // 放行
            chain.doFilter(request, response);
            return;
        }
        // 设置标记
        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
        // 不存在
        if (!this.securityContextRepository.containsContext(request)) {
            // 获取认证信息
            Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
            /**
             * 认证信息不为空 且 不是匿名用户认证信息。
             * 说明是认证通过了
             */
            if (authentication != null && !this.trustResolver.isAnonymous(authentication)) {
                // The user has been authenticated during the current request, so call the
                // session strategy
                try {
                    // 回调 sessionAuthenticationStrategy
                    this.sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
                }
                catch (SessionAuthenticationException ex) {
                    this.securityContextHolderStrategy.clearContext();
                    this.failureHandler.onAuthenticationFailure(request, response, ex);
                    return;
                }
                // 持久化 认证信息（存到session或者cookie中）
                this.securityContextRepository.saveContext(this.securityContextHolderStrategy.getContext(), request,
                        response);
            }
            else {
                // 无效的 RequestedSessionId
                if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()){
                    if (this.invalidSessionStrategy != null) {
                        // 回调
                        this.invalidSessionStrategy.onInvalidSessionDetected(request, response);
                        // return，不在执行后续的filter
                        return;
                    }
                }
            }
        }
        // 放行
        chain.doFilter(request, response);
    }
}
```

## LogoutFilter

目的：拦截登出请求，就清除缓存的 SecurityContext 信息 并 重定向到登出页面

```java
public class LogoutFilter extends GenericFilterBean {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    private RequestMatcher logoutRequestMatcher;

    private final LogoutHandler handler;

    private final LogoutSuccessHandler logoutSuccessHandler;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // request 匹配配置的 logout 路径
        if (this.logoutRequestMatcher.matches(request)) {
            // 从上下文中获取 认证信息
            Authentication auth = this.securityContextHolderStrategy.getContext().getAuthentication();
            /**
             * 回调 LogoutHandler
             *
             * 比如 {@link SecurityContextLogoutHandler#logout(HttpServletRequest, HttpServletResponse, Authentication)}
             *      1. 将 session 设置为无效的
             *      2. 从 SecurityContextHolderStrategy 中移除 SecurityContext
             *      3. SecurityContextRepository 保存空的认证信息，相当于清空持久化的认证信息
             * */
            this.handler.logout(request, response, auth);
            /**
             * 回调 LogoutSuccessHandler。
             * 
             * 比如 {@link SimpleUrlLogoutSuccessHandler#onLogoutSuccess(HttpServletRequest, HttpServletResponse, Authentication)}
             * 会重定向到登录页地址
             */
            this.logoutSuccessHandler.onLogoutSuccess(request, response, auth);
            return;
        }
        // 放行
        chain.doFilter(request, response);
    }
}
```

## OAuth2AuthorizationRequestRedirectFilter

目的：

1. 默认是处理 `/oauth2/authorization/{registrationId}` 请求，根据 registrationId 拿到配置的第三方OAuth2的配置信息，根据信息拼接出授权url，然后设置重定向信息，告诉浏览器重定向到第三方服务的授权页面，让用户进行授权。
2. 捕获到 ClientAuthorizationRequiredException 异常，处理逻辑同上，都是重定向第三方授权页面。

可以通过这种方式注册 OAuth2AuthorizationRequestRedirectFilter

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            /**
             * 会注册两个Filter：OAuth2AuthorizationRequestRedirectFilter、OAuth2LoginAuthenticationFilter
             * 会注册一个AuthenticationProvider： OAuth2LoginAuthenticationProvider
             */
            .oauth2Login();
    return http.build();
}
```
```java
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {

    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";

    private RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            /**
             * 能解析出 OAuth2AuthorizationRequest。
             * 1. request 匹配了 authorizationRequestMatcher
             * 2. 从 request 中提取出 registrationId
             * 3. clientRegistrationRepository.findByRegistrationId(registrationId) 得到 ClientRegistration
             * 4. 根据 ClientRegistration 构造出 OAuth2AuthorizationRequest。其实就是重定向地址、clientId、clientSecret等信息
             *
             * {@link DefaultOAuth2AuthorizationRequestResolver#resolve(HttpServletRequest)}
             */
            OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
            // 不为空
            if (authorizationRequest != null) {
                /**
                 * 设置重定向信息。
                 *
                 * 1. 使用 authorizationRequestRepository 保存 authorizationRequest
                 * 2. 重定向到第三方应用的授权页面
                 */
                this.sendRedirectForAuthorization(request, response, authorizationRequest);
                // 结束方法
                return;
            }
        } catch (Exception ex) {
            // 往响应体写入异常信息
            this.unsuccessfulRedirectForAuthorization(request, response, ex);
            return;
        }
        try {
            // 放行
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
            // 有 ClientAuthorizationRequiredException
            ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException) this.throwableAnalyzer
                    .getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
            if (authzEx != null) {
                try {
                    // 解析出 authorizationRequest
                    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request,
                            authzEx.getClientRegistrationId());
                    if (authorizationRequest == null) {
                        throw authzEx;
                    }
                    // 缓存request
                    this.requestCache.saveRequest(request, response);
                    // 设置重定向信息
                    this.sendRedirectForAuthorization(request, response, authorizationRequest);
                } catch (Exception failed) {
                    // 往响应体写入异常信息
                    this.unsuccessfulRedirectForAuthorization(request, response, failed);
                }
                return;
            }
            throw new RuntimeException(ex);
        }
    }

}
```

## AbstractAuthenticationProcessingFilter

通过模板方法定义认证的流程：尝试认证(子类实现该逻辑) -> 执行 SessionAuthenticationStrategy -> 认证结束执行：SecurityContextHolderStrategy、SecurityContextRepository、RememberMeServices、（AuthenticationSuccessHandler | AuthenticationFailureHandler）

![AbstractAuthenticationProcessingFilter](.spring-security-source-note_imgs/AbstractAuthenticationProcessingFilter.png)

```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean
        implements ApplicationEventPublisherAware, MessageSourceAware {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    
    private AuthenticationManager authenticationManager;

    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    private RequestMatcher requiresAuthenticationRequestMatcher;

    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();

    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    private SecurityContextRepository securityContextRepository = new NullSecurityContextRepository();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        /**
         * 不是需要认证的
         *
         * {@link UsernamePasswordAuthenticationFilter}
         * 		其实就是判断不是 /login
         * {@link org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter}
         * 		其实就是判断不是 第三方服务回调的地址，默认是 /login/oauth2/code/*。
         * 		若是第三方服务回调的地址，一般会返回授权码，有了授权码就算是成功认证了
         */
        if (!this.requiresAuthenticationRequestMatcher.matches(request)) {
            // 放行
            chain.doFilter(request, response);
            return;
        }
        try {
            /**
             * 尝试认证，这是一个抽象方法，由子类实现认证逻辑，返回认证结果信息
             * 	{@link UsernamePasswordAuthenticationFilter#attemptAuthentication}
             *		1. 从request参数中提取 username 和 password 构造出 UsernamePasswordAuthenticationToken
             *		2. 使用 AuthenticationManager 认证 UsernamePasswordAuthenticationToken
             *
             * 	{@link OAuth2LoginAuthenticationFilter#attemptAuthentication}
             *      1. 从 authorizationRequest 获取配置的第三方服务OAuth2配置信息(配置了访问令牌url、个人信息url)
             *      2. 使用 AuthenticationManager 进行认证 (其实就是拿着 code(授权码) 访问第三方服务拿到访问令牌，再根据访问令牌请求第三方系统的个人信息接口获取个人信息)
             */
            Authentication authenticationResult = attemptAuthentication(request, response);
            if (authenticationResult == null) {
                return;
            }
            // 回调 sessionStrategy
            this.sessionStrategy.onAuthentication(authenticationResult, request, response);
            /**
             * 1. 保存 SecurityContext
             * 2. 回调 RememberMeService#loginSuccess
             * 3. 发布事件 InteractiveAuthenticationSuccessEvent
             * 4. 回调 SuccessHandler#onAuthenticationSuccess
             * 		默认是注册了 SavedRequestAwareAuthenticationSuccessHandler，这是用来设置 重定向到之前访问的路径
             * 		比如：未登录 -> 需要认证的页面 -> 重定向到登录页面 -> 认证通过 -> 重定向到之前的页面
             */
            successfulAuthentication(request, response, chain, authenticationResult);
        }
        catch (InternalAuthenticationServiceException failed) {
            /**
             * 1. 清除 SecurityContext
             * 2. 回调 RememberMeService#loginFail
             * 3. 回调 AuthenticationFailureHandler#onAuthenticationFailure
             */
            unsuccessfulAuthentication(request, response, failed);
        }
    }
}
```

## OAuth2LoginAuthenticationFilter

目的：拦截OAuth2第三方服务回调本系统的请求，从请求中拿到授权码去调用第三方服务获取访问令牌，再拿着访问令牌调第三方服务的个人信息接口，拿到个人信息封装成 Authentication 就算是认证通过了。

认证的实现看 [OAuth2LoginAuthenticationProvider](#OAuth2LoginAuthenticationProvider)

可以通过这种方式注册 OAuth2LoginAuthenticationFilter

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            /**
             * 会注册两个Filter：OAuth2AuthorizationRequestRedirectFilter、OAuth2LoginAuthenticationFilter
             * 会注册一个AuthenticationProvider： OAuth2LoginAuthenticationProvider
             */
            .oauth2Login();
    return http.build();
}
```

```java
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";

    private ClientRegistrationRepository clientRegistrationRepository;

    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());

        // 不是 OAuth2 服务方回调的请求（因为OAuth2回调时会传递一些参数，根据是否有这些参数来判断的）
        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            // 抛出异常
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        /**
         * 获取 authorizationRequest
         *
         * 在跳转到第三方系统认证页面之前会设置 OAuth2AuthorizationRequest
         * 		{@link OAuth2AuthorizationRequestRedirectFilter#sendRedirectForAuthorization(HttpServletRequest, HttpServletResponse, OAuth2AuthorizationRequest)}
         */
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
                .removeAuthorizationRequest(request, response);

        // 不存在说明并发起过第三方认证请求
        if (authorizationRequest == null) {
            OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
            // 抛出异常
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        // 拿到
        String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        // 根据 registrationId 获取 ClientRegistration
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        // 为空，说明没配置过
        if (clientRegistration == null) {
            OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
                    "Client Registration not found with Id: " + registrationId, null);
            // 抛出异常
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        // @formatter:off
        String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replaceQuery(null)
                .build()
                .toUriString();
        // @formatter:on
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
                redirectUri);
        Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);

        // 构造出 OAuth2LoginAuthenticationToken
        OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        authenticationRequest.setDetails(authenticationDetails);
        /**
         * 使用 AuthenticationManager 进行认证。
         * 主要是通过 code(授权码) 访问第三方系统拿到访问令牌，再根据访问令牌请求第三方系统的个人信息接口获取个人信息，
         * 有了个人信息就算是 认证通过了
         * 
         * 认证的代码 {@link OAuth2LoginAuthenticationProvider#authenticate}
         */
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this
                .getAuthenticationManager().authenticate(authenticationRequest);
        /**
         * 转换成 OAuth2AuthenticationToken
         * {@link OAuth2LoginAuthenticationFilter#createAuthenticationResult(OAuth2LoginAuthenticationToken)}
         */
        OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter
                .convert(authenticationResult);
        Assert.notNull(oauth2Authentication, "authentication result cannot be null");
        oauth2Authentication.setDetails(authenticationDetails);

        // 构造出 OAuth2AuthorizedClient
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
                authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());

        // 将 OAuth2AuthorizedClient 存起来
        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
        return oauth2Authentication;
    }
}
```

## UsernamePasswordAuthenticationFilter

目的：拦截登录请求，从请求中输入的用户名密码构造出UsernamePasswordAuthenticationToken，然后委托给 AuthenticationManager 进行认证。

认证的实现看 [DaoAuthenticationProvider](#DaoAuthenticationProvider)

可以通过这种方式注册 UsernamePasswordAuthenticationFilter

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            /**
             * UsernamePasswordAuthenticationFilter
             */
            ..formLogin(withDefaults());
    return http.build();
}
```

```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";

    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
            "POST");

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        // 设置了postOnly 但不是POST 请求
        if (this.postOnly && !request.getMethod().equals("POST")) {
            // 抛出异常
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        // 从request的参数中拿到 username
        String username = obtainUsername(request);
        // 去除空格
        username = (username != null) ? username.trim() : "";
        // 从request的参数中拿到 password
        String password = obtainPassword(request);
        password = (password != null) ? password : "";
        // 构造出 UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
                password);
        // 模板方法。默认是将 request 暴露给 UsernamePasswordAuthenticationToken
        setDetails(request, authRequest);
        /**
         * 使用 AuthenticationManager 进行认证。具体如何认证看 AuthenticationProvider
         * {@link org.springframework.security.authentication.ProviderManager#authenticate(org.springframework.security.core.Authentication)}
         */
        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
```

## ExceptionTranslationFilter

[FilterSecurityInterceptor](#FilterSecurityInterceptor)、[AuthorizationFilter](#AuthorizationFilter ) 是 Spring Security 完成鉴权逻辑的过滤器，就叫做**鉴权Filter**吧，FilterSecurityInterceptor 已经过时了，建议使用 AuthorizationFilter。

ExceptionTranslationFilter 优先于 FilterSecurityInterceptor、AuthorizationFilter 之前执行，所以能捕获到他俩里面抛出的异常。它只处理 AuthenticationException 、 AccessDeniedException 这两种异常，因为鉴权Filter会根据情况抛出这两种异常。顾名思义，鉴权Filter 判断用户未认证过就抛出 AuthenticationException，判断用户不具备 Request配置的权限就抛出 AccessDeniedException。

ExceptionTranslationFilter  捕获到 AuthenticationException 就使用 [RequestCache](#RequestCache) 缓存当前request信息，用于后面认证，然后调用 [AuthenticationEntryPoint](#AuthenticationEntryPoint ) 开始认证（比如往响应体设置异常信息 或者 重定向到登录页面 或者 转发到登录页面）

ExceptionTranslationFilter  捕获到 AccessDeniedException 就委托给 AccessDeniedHandler 处理。比如往响应体设置错误信息。

ExceptionTranslationFilter 是 HttpSecurity 会设置的默认值，看 [HttpSecurityConfiguration](#) 就明白了

```java
public class ExceptionTranslationFilter extends GenericFilterBean implements MessageSourceAware {
    
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            // 放行
            chain.doFilter(request, response);
        }
        catch (IOException ex) {
            throw ex;
        }
        catch (Exception ex) {
            /**
             * 构造出 causeChain。其实就是遍历异常调用栈，收集期望的异常对象
             */
            // Try to extract a SpringSecurityException from the stacktrace
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
            // 遍历 causeChain 拿到 AuthenticationException 类型的异常对象
            RuntimeException securityException = (AuthenticationException) this.throwableAnalyzer
                    .getFirstThrowableOfType(AuthenticationException.class, causeChain);
            if (securityException == null) {
                // 补偿策略，获取 AccessDeniedException
                securityException = (AccessDeniedException) this.throwableAnalyzer
                        .getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            }
            // 为空，说明抛出的异常不是我们关注的异常
            if (securityException == null) {
                // 直接抛出异常
                rethrow(ex);
            }
            /**
             * 处理 SpringSecurityException
             * 1. 是 AuthenticationException 异常
             * 		1.1 往 SecurityContextHolderStrategy 记录一个空的 SecurityContext
             * 		1.2 使用 RequestCache 缓存当前request信息，用于后面认证通过后可以恢复现场
             * 		1.3 调用 AuthenticationEntryPoint 开始认证（往响应体设置异常信息 或者 重定向到登录页面 或者 转发到登录页面）
             *
             * 2. 是 AccessDeniedException 异常：
             * 		2.1 是匿名用户 或者 是rememberMe 就开始认证(执行步骤1的逻辑)
             * 		2.2 调用 AccessDeniedHandler 处理访问拒绝异常（往响应体设置异常信息 或者 重定向到错误页面）
             */
            handleSpringSecurityException(request, response, chain, securityException);
        }
    }
}
```

## FilterSecurityInterceptor

FilterSecurityInterceptor 已经过时了建议使用 [AuthorizationFilter](#AuthorizationFilter)。

FilterSecurityInterceptor 的优先级很低是在末尾执行的Filter的，它根据 request 作为参数调用 [SecurityMetadataSource](#SecurityMetadataSource) 获取配置的权限数据，在调用 [AccessDecisionManager](#AccessDecisionManager) 鉴定认证的用户是否具备配置的权限。

可以通过这种方式注册 FilterSecurityInterceptor。

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            /**
             * 设置鉴权逻辑。会注册 FilterSecurityInterceptor
             *
             * 写的规则会拼接成 SpEL 表达式，然后使用的 RootObject 是 SecurityExpressionRoot 类型的，所以才可以写 "hasRole('ADMIN') and hasRole('DBA')"
             * 鉴权是否通过，是执行 SpEL 表达式得到 boolean 值，为true就是通过
             */
            .authorizeRequests(authorize -> authorize
                    .requestMatchers("/f3/xx").authenticated()
                    .requestMatchers("/f3/**").hasRole("xx")
                    .requestMatchers("/f3/xx2").access("hasRole('ADMIN') and hasRole('DBA')")
                    .anyRequest().authenticated()
            );
    return http.build();
}
```

```java
@Deprecated
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {
    
    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        // 是适配的（其实就是有标记）
        if (isApplied(filterInvocation)) {
            // 放行
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            return;
        }
        if (filterInvocation.getRequest() != null) {
            // 设置标记
            filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
        }
        /**
         * 执行前（会进行认证和鉴权）
         * 1. 根据 request 获取为 request 配置的权限信息
         * 2. 未认证过就进行认证。	AuthenticationManager#authenticate
         * 2. 校验认证信息是否具备配置的权限	AccessDecisionManager#decide
         */
        InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
        try {
            // 放行
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        }
        finally {
            /**
             * 执行完(完成调用)。
             * 根据 token.isContextHolderRefreshRequired() 决定是否更新 securityContextHolderStrategy 记录的 SecurityContext。
             *
             * 比如 {@link AbstractSecurityInterceptor#beforeInvocation(Object)} 会构造新的SecurityContext, 并将原来的SecurityContext
             * 记录到 token 中，finallyInvocation 就是判断是否构造了新的SecurityContext，若是新的执行完之后 应当在这一步恢复SecurityContext
             */
            super.finallyInvocation(token);
        }
        /**
         * 执行后。
         *
         * 回调 afterInvocationManager#decide 对返回值进行鉴权，但是 FilterSecurityInterceptor 没设置这个属性所以没有这个步骤。
         */
        super.afterInvocation(token, null);
    }
}
```

## AuthorizationFilter

AuthorizationFilter 的优先级很低是在末尾执行的Filter的，它依赖 [AuthorizationManager](#AuthorizationManager) 得到鉴权结果。

可以通过这种方式注册 AuthorizationFilter 。

```java
 @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                /**
                 * 配置鉴权规则。
                 * 会注册 AuthorizationFilter
                 */
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/f2/user/**").hasRole("USER")
                        .requestMatchers("/f2/x").authenticated()
                        .requestMatchers("/f2/x").permitAll()
                        .requestMatchers("/f2/x").denyAll()
                        .requestMatchers("/f2/db/**").access(
                                AuthorizationManagers.allOf(
                                        AuthorityAuthorizationManager.hasRole("ADMIN"),
                                        AuthorityAuthorizationManager.hasRole("DBA")
                                ))
                );
        return http.build();
    }
```

```java
public class AuthorizationFilter extends GenericFilterBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final AuthorizationManager<HttpServletRequest> authorizationManager;

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws ServletException, IOException {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		// 存在标记
		if (this.observeOncePerRequest && isApplied(request)) {
			// 放行
			chain.doFilter(request, response);
			return;
		}

		// 是跳过的转发类型
		if (skipDispatch(request)) {
			// 放行
			chain.doFilter(request, response);
			return;
		}

		String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
		// 设置标记
		request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
		try {
			/**
			 * 使用 authorizationManager 检查权限
			 * 	{@link RequestMatcherDelegatingAuthorizationManager#check(Supplier, HttpServletRequest)}
			 * 	1. 遍历配置的权限集合，找到匹配request的	AuthorizationManager
			 * 	2. 回调 AuthorizationManager#check 得到鉴权结果
			 */
			AuthorizationDecision decision = this.authorizationManager.check(this::getAuthentication, request);
			// 发布事件
			this.eventPublisher.publishAuthorizationEvent(this::getAuthentication, request, decision);
			// 没有权限
			if (decision != null && !decision.isGranted()) {
				// 抛出异常
				throw new AccessDeniedException("Access Denied");
			}
			// 放行
			chain.doFilter(request, response);
		}
		finally {
			// 移除标记
			request.removeAttribute(alreadyFilteredAttributeName);
		}
	}

}
```

