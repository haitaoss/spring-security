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



## 重要的类

这是基于Servlet应用的场景分析 Spring Security 的源码

Principal：主角、当事人、委托人

GrantedAuthority：授权机构

credentials：资格证书

Explicit：明确的、清楚的

restrict：限制、限定

commence：开始

entryPoint：入口点

permit：允许

attempt：尝试

decide：决定

erase：清除

AccessDecisionManager：访问决策管理器

