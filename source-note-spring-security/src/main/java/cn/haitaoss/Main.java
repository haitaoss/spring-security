
package cn.haitaoss;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-05 10:44
 *
 */
public class Main {
	/**
	 * {@link EnableWebSecurity}
	 * {@link DefaultSecurityFilterChain}
	 * */
	/** Spring Boot Auto Configuration 做了什么
	 Spring Boot Auto Configuration：
	 1. 启用 Spring Security 的默认配置，它创建一个 servlet Filter 作为一个名为 springSecurityFilterChain 的 bean。这个 bean 负责应用程序中的所有安全（保护应用程序 URL、验证提交的用户名和密码、重定向到登录表单等）。
	 2. 使用用户名 user 和随机生成的密码创建一个 UserDetailsService bean 并记录到控制台。
	 3. 为每个请求向 Servlet 容器注册一个名为 springSecurityFilterChain 的 bean 的 Filter 。

	 Spring Boot 配置不多，但是做的很多。功能总结如下：

	 1. 需要经过身份验证的用户才能与应用程序进行任何交互
	 2. 为您生成默认登录表单
	 3. 让用户名 user 和登录到控制台的密码的用户使用基于表单的身份验证进行身份验证（在前面的示例中，密码是 8e557245-73e2-4286-969a-ff57fe326336 ）
	 4. 使用 BCrypt 保护密码存储
	 5. 让用户注销
	 6. CSRF攻击预防
	 7. Session Fixation protection  会话固定保护
	 8. Security Header integration
	 用于安全请求的 HTTP 严格传输安全
	 X-Content-Type-Options
	 Cache Control（稍后可以被您的应用程序覆盖以允许缓存您的静态资源）
	 X-XSS-Protection
	 X-Frame-Options 集成有助于防止点击劫持
	 注：反正就是一些特殊的 header

	 9.与以下 Servlet API 方法集成：
	 - HttpServletRequest#getRemoteUser()
	 - HttpServletRequest.html#getUserPrincipal()
	 - HttpServletRequest.html#isUserInRole(java.lang.String)
	 - HttpServletRequest.html#login(java.lang.String, java.lang.String)
	 - HttpServletRequest.html#logout()
	 * */
	/**
	 * DelegatingFilterProxy
	 * 		Spring 提供了一个名为 DelegatingFilterProxy 的 Filter 实现，它允许在 Servlet 容器的生命周期和 Spring 的 ApplicationContext 之间架起桥梁。
	 * 		Servlet 容器允许使用自己的标准注册 Filter ，但它不知道 Spring 定义的 Bean。 DelegatingFilterProxy 可以通过标准的 Servlet 容器机制注册，
	 * 		但将所有工作委托给实现 Filter 的 Spring Bean
	 *
	 *		也就是说，可以不需要将 Filter 类型的bean 注册到 Servlet 容器中也能生效。
	 *		因为没有将 Filter 类型的bean注册到 Servlet 容器中，所以可以实现延时初始化的效果，用到 Filter 类型的bean 时才会初始化
	 *
	 *		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/architecture/delegatingfilterproxy.png
	 *
	 * FilterChainProxy
	 * 		Spring Security 的 Servlet 支持包含在 FilterChainProxy 中。 FilterChainProxy 是 Spring Security 提供的一个特殊的 Filter ，
	 * 		它允许通过 SecurityFilterChain 委托给许多 Filter 实例。因为 FilterChainProxy 是一个 Bean，所以它通常被包裹在一个 DelegatingFilterProxy 中。
	 *		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/architecture/filterchainproxy.png
	 *
	 * SecurityFilterChain
	 * 		SecurityFilterChain 中的 Security Filter 通常是 Bean，但它们是使用 FilterChainProxy 而不是 DelegatingFilterProxy 注册的。
	 * 		FilterChainProxy 为直接向 Servlet 容器或 DelegatingFilterProxy 注册提供了许多优势。
	 * 		首先，它为所有 Spring Security 的 Servlet 支持提供了一个起点。出于这个原因，如果您正在尝试对 Spring Security 的 Servlet 支持进行故障排除，
	 * 		那么在 FilterChainProxy 中添加调试点是一个很好的起点。
	 *
	 * 		其次，由于 FilterChainProxy 是 Spring Security 使用的核心，它可以执行不被视为可选的任务。例如，它会清除 SecurityContext 以避免内存泄漏。
	 * 		它还应用 Spring Security 的 HttpFirewall 来保护应用程序免受某些类型的攻击。
	 *
	 * 		此外，它在确定何时应调用 SecurityFilterChain 方面提供了更大的灵活性。在 Servlet 容器中， Filter 仅根据 URL 被调用。但是，
	 * 		FilterChainProxy 可以通过利用 RequestMatcher 接口来确定基于 HttpServletRequest 中的任何内容的调用。
	 *
	 * 		事实上， FilterChainProxy 可以用来确定应该使用哪个 SecurityFilterChain 。这允许为应用程序的不同部分提供完全独立的配置。
	 *
	 * 		SecurityFilterChain		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/architecture/securityfilterchain.png
	 * 		多个 SecurityFilterChain https://docs.spring.io/spring-security/reference/5.8/_images/servlet/architecture/multi-securityfilterchain.png
	 *
	 * Security Filters
	 * 		Security Filter 通过 SecurityFilterChain API 插入到 FilterChainProxy 中。 Filter 的顺序很重要。
	 * 		通常不需要知道 Spring Security 的 Filter 的顺序。但是，有时了解顺序是有益的
	 *
	 * 		以下是 Spring Security Filter 排序的完整列表：
	 * 			- ForceEagerSessionCreationFilter
	 * 			- ChannelProcessingFilter
	 * 			- WebAsyncManagerIntegrationFilter
	 * 			- SecurityContextPersistenceFilter
	 * 			- HeaderWriterFilter
	 * 			- CorsFilter
	 * 			- CsrfFilter
	 * 			- LogoutFilter
	 * 			- OAuth2AuthorizationRequestRedirectFilter
	 * 			- Saml2WebSsoAuthenticationRequestFilter
	 * 			- X509AuthenticationFilter
	 * 			- AbstractPreAuthenticatedProcessingFilter
	 * 			- CasAuthenticationFilter
	 * 			- OAuth2LoginAuthenticationFilter
	 * 			- Saml2WebSsoAuthenticationFilter
	 * 			- UsernamePasswordAuthenticationFilter
	 * 			- OpenIDAuthenticationFilter
	 * 			- DefaultLoginPageGeneratingFilter
	 * 			- DefaultLogoutPageGeneratingFilter
	 * 			- ConcurrentSessionFilter
	 * 			- DigestAuthenticationFilter
	 * 			- BearerTokenAuthenticationFilter
	 * 			- BasicAuthenticationFilter
	 * 			- RequestCacheAwareFilter
	 * 			- SecurityContextHolderAwareRequestFilter
	 * 			- JaasApiIntegrationFilter
	 * 			- RememberMeAuthenticationFilter
	 * 			- AnonymousAuthenticationFilter
	 * 			- OAuth2AuthorizationCodeGrantFilter
	 * 			- SessionManagementFilter
	 * 			- ExceptionTranslationFilter
	 * 			- FilterSecurityInterceptor
	 * 			- SwitchUserFilter
	 * */
	/**
	 * Handling Security Exceptions
	 * 		ExceptionTranslationFilter 允许将 AccessDeniedException 和 AuthenticationException 转换为 HTTP 响应。
	 * 		ExceptionTranslationFilter 作为 Security Filter 之一插入到 FilterChainProxy 中。
	 *
	 * 		大致流程（后面再看代码细究）：
	 * 			1. 首先， ExceptionTranslationFilter 调用 FilterChain.doFilter(request, response) 来调用应用程序的其余部分。
	 * 			2. 如果用户未通过身份验证或者是 AuthenticationException ，则开始身份验证。
	 * 				SecurityContextHolder 被清除
	 * 				HttpServletRequest 已保存，以便在身份验证成功后可用于重播原始请求。
	 * 				AuthenticationEntryPoint 用于从客户端请求凭据。例如，它可能会重定向到登录页面或发送 WWW-Authenticate 标头
	 *			3. 否则，如果它是 AccessDeniedException ，则访问被拒绝。 AccessDeniedHandler 被调用来处理拒绝访问
	 * 		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/architecture/exceptiontranslationfilter.png
	 * */
	/**
	 * Saving Requests Between Authentication（在身份验证之间保存请求）
	 * 		如处理安全异常中所述，当请求没有鉴权，并且是针对需要鉴权的资源时，需要保存请求，供鉴权成功后重新请求。在 Spring Security 中，
	 * 		这是通过使用 RequestCache 实现保存 HttpServletRequest 来完成的。
	 *
	 * 	RequestCache
	 * 		HttpServletRequest 保存在 RequestCache 中。当用户成功通过身份验证时， RequestCache 用于重放原始请求。
	 * 		RequestCacheAwareFilter 是使用 RequestCache 来保存 HttpServletRequest 的东西。
	 *
	 * 		默认情况下，使用 HttpSessionRequestCache 。下面的代码演示了如何自定义 RequestCache 实现，如果存在名为 continue 的参数，
	 * 		该实现用于检查 HttpSession 是否已保存请求。
	 *
	 *                @Bean
	 * 					DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
	 * 						HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
	 * 						requestCache.setMatchingRequestParameterName("continue");
	 * 						http
	 * 							// ...
	 * 							.requestCache((cache) -> cache
	 * 								.requestCache(requestCache)
	 * 							);
	 * 						return http.build();
	 * 					}
	 *
	 * 		Prevent the Request From Being Saved（防止请求被保存）
	 * 			您可能出于多种原因不想在会话中存储用户未经身份验证的请求。您可能希望将该存储卸载到用户的浏览器上或将其存储在数据库中。
	 * 			或者您可能希望关闭此功能，因为您总是希望将用户重定向到主页而不是他们在登录前尝试访问的页面。
	 * 			为此，您可以使用 NullRequestCache 实现。
	 *
	 *                        @Bean
	 * 						SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
	 * 						    RequestCache nullRequestCache = new NullRequestCache();
	 * 						    http
	 * 						        // ...
	 * 						        .requestCache((cache) -> cache
	 * 						            .requestCache(nullRequestCache)
	 * 						        );
	 * 						    return http.build();
	 * 						}
	 *
	 * RequestCacheAwareFilter
	 * 		RequestCacheAwareFilter 使用 RequestCache 来保存 HttpServletRequest 。
	 * */
	/**
	 * Authentication（认证）
	 * Authentication Mechanisms （认证机制）
	 * 		- Username and Password - how to authenticate with a username/password
	 *		- OAuth 2.0 Login - OAuth 2.0 Log In with OpenID Connect and non-standard OAuth 2.0 Login (i.e. GitHub)
	 * 		- SAML 2.0 Login - SAML 2.0 Log In
	 * 		- Central Authentication Server (CAS) - Central Authentication Server (CAS) Support
	 * 		- Remember Me - how to remember a user past session expiration
	 * 		- JAAS Authentication - authenticate with JAAS
	 * 		- OpenID - OpenID Authentication (not to be confused with OpenID Connect)
	 * 		- Pre-Authentication Scenarios(预身份验证场景) - authenticate with an external mechanism such as SiteMinder or Java EE security but still use Spring Security for authorization and protection against common exploits.
	 * 		- X509 Authentication - X509 Authentication
	 *
	 * */
	/**
	 * Servlet Authentication Architecture（ Servlet 认证架构 ）
	 * 		此讨论扩展了 Servlet 安全性：大图来描述 Spring Security 在 Servlet 身份验证中使用的主要架构组件。
	 * 		如果您需要解释这些部分如何组合在一起的具体流程，请查看身份验证机制特定部分。
	 *
	 *		关键的几个组件：
	 * 			- SecurityContextHolder ： SecurityContextHolder 是 Spring Security 存储谁被认证的详细信息的地方。
	 * 			- SecurityContext ： 从 SecurityContextHolder 获取并包含当前已验证用户的 Authentication 。
	 * 			- Authentication ： 可以是 AuthenticationManager 的输入以提供用户提供的凭据以进行身份验证或来自 SecurityContext 的当前用户。
	 * 			- GrantedAuthority（授权机构） ： 在 Authentication 上授予委托人的权限（即角色、范围等）
	 * 			- AuthenticationManager ： 定义 Spring Security 的过滤器如何执行身份验证的 API。
	 * 			- ProviderManager ： AuthenticationManager 最常见的实现。
	 * 			- AuthenticationProvider ： ProviderManager 使用它来执行特定类型的身份验证。
	 * 			- Request Credential with AuthenticationEntryPoint （使用 AuthenticationEntryPoint 请求凭据） ：用于从客户端请求凭据（即重定向到登录页面、发送 WWW-Authenticate 响应等）
	 * 			- AbstractAuthenticationProcessingFilter ： 用于身份验证的基础 Filter 。这也很好地了解了身份验证的高级流程以及各部分如何协同工作。
	 *
	 * SecurityContextHolder
	 * 		Spring Security 身份验证模型的核心是 SecurityContextHolder 。它包含 SecurityContext 。
	 * 		SecurityContextHolder 是 Spring Security 存储谁被认证的详细信息的地方。 Spring Security 不关心 SecurityContextHolder 是如何填充的。如果它包含一个值，则将其用作当前经过身份验证的用户。
	 * 		指示用户已通过身份验证的最简单方法是直接设置 SecurityContextHolder 。
	 *			SecurityContext context = SecurityContextHolder.createEmptyContext();
	 * 			Authentication authentication = new TestingAuthenticationToken("username", "password", "ROLE_USER");
	 * 			context.setAuthentication(authentication);
	 * 			SecurityContextHolder.setContext(context);
	 *
	 *		如果您希望获得有关经过身份验证的主体的信息，您可以通过访问 SecurityContextHolder 来实现。
	 *			访问当前经过身份验证的用户
	 *			SecurityContext context = SecurityContextHolder.getContext();
	 * 			Authentication authentication = context.getAuthentication();
	 * 			String username = authentication.getName();
	 * 			Object principal = authentication.getPrincipal();
	 * 			Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
	 *
	 *		默认情况下， SecurityContextHolder 使用 ThreadLocal 来存储这些细节，这意味着 SecurityContext 始终可用于同一线程中的方法，即使 SecurityContext 未作为参数显式传递给这些方法.如果注意在处理当前主体的请求后清除线程，
	 *		以这种方式使用 ThreadLocal 是非常安全的。 Spring Security 的 FilterChainProxy 确保 SecurityContext 始终被清除。
	 *
	 *		某些应用程序并不完全适合使用 ThreadLocal ，因为它们使用线程的特定方式。例如，Swing 客户端可能希望 Java 虚拟机中的所有线程都使用相同的安全上下文。 SecurityContextHolder 可以在启动时配置一个策略来指定你希望如何存储上下文。对于独立应用程序，您可以使用 SecurityContextHolder.MODE_GLOBAL 策略。
	 *		其他应用程序可能希望安全线程生成的线程也采用相同的安全标识。这是通过使用 SecurityContextHolder.MODE_INHERITABLETHREADLOCAL 实现的。您可以通过两种方式更改默认的 SecurityContextHolder.MODE_THREADLOCAL 模式。
	 *		第一个是设置系统属性，第二个是在 SecurityContextHolder 上调用静态方法。大多数应用程序不需要更改默认设置，但如果需要更改，请查看 SecurityContextHolder 的 Javadoc 以了解更多信息。
	 *
	 * 		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/authentication/architecture/securitycontextholder.png
	 *
	 * SecurityContext
	 * 		SecurityContext 是从 SecurityContextHolder 获得的。 SecurityContext 包含一个 Authentication 对象。
	 *
	 * Authentication
	 * 		Authentication 在 Spring Security 中有两个主要目的：
	 * 			- AuthenticationManager 的输入，用于提供用户提供的用于身份验证的凭据。在这种情况下使用时， isAuthenticated() 返回 false 。
	 * 			- 表示当前经过身份验证的用户。当前的 Authentication 可以从 SecurityContext 中获取。
	 *
	 * 		Authentication 包含：
	 * 			- principal : 标识用户。当使用用户名/密码进行身份验证时，这通常是 UserDetails 的一个实例。
	 * 			- credentials : 通常是密码。在许多情况下，这将在用户通过身份验证后被清除，以确保它不会泄露。
	 * 			- authorities : GrantedAuthority 是授予用户的高级权限。一些示例是角色或范围。
	 *
	 * GrantedAuthority
	 * 		GrantedAuthority 是授予用户的高级权限。一些示例是角色或范围。
	 * 		GrantedAuthority 可以通过 Authentication.getAuthorities() 方法获取。此方法提供 Collection 个 GrantedAuthority 对象。毫不奇怪， GrantedAuthority 是授予委托人的权限。此类权限通常是“角色”，例如 ROLE_ADMINISTRATOR 或 ROLE_HR_SUPERVISOR 。这些角色稍后会针对 Web 授权、方法授权和域对象授权进行配置。 Spring Security 的其他部分能够解释这些权限，并期望它们存在。当使用基于用户名/密码的身份验证时， GrantedAuthority 通常由 UserDetailsService 加载。
	 * 		通常 GrantedAuthority 对象是应用程序范围的权限。它们不特定于给定的域对象。因此，您不太可能有一个 GrantedAuthority 来表示对 Employee 对象编号 54 的许可，因为如果有数千个这样的权限，您将很快耗尽内存（或者，至少，导致应用程序需要很长时间来验证用户）。当然，Spring Security 明确设计用于处理这种常见需求，但您需要为此目的使用项目的域对象安全功能。
	 *
	 * AuthenticationManager 认证管理器
	 * 		AuthenticationManager 是定义 Spring Security 的过滤器如何执行身份验证的 API。然后，调用 AuthenticationManager 的控制器（即 Spring Security 的 Filters s）在 SecurityContextHolder 上设置返回的 Authentication 。如果你不与 Spring Security 的 Filters 集成，你可以直接设置 SecurityContextHolder 而不需要使用 AuthenticationManager 。
	 * 		虽然 AuthenticationManager 的实现可以是任何东西，但最常见的实现是 ProviderManager 。
	 *
	 * ProviderManager
	 * 		ProviderManager 是 AuthenticationManager 最常用的实现。 ProviderManager 委托给 AuthenticationProvider 中的 List 。每个 AuthenticationProvider 都有机会表明身份验证应该成功、失败，或者表明它不能做出决定并允许下游的 AuthenticationProvider 来决定。如果配置的 AuthenticationProvider 都不能进行身份验证，则身份验证将失败并返回 ProviderNotFoundException ，这是一个特殊的 AuthenticationException ，表示 ProviderManager 未配置为支持传递给它的 Authentication 类型.
	 * 		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/authentication/architecture/providermanager.png
	 *
	 * 		实际上，每个 AuthenticationProvider 都知道如何执行特定类型的身份验证。例如，一个 AuthenticationProvider 可能能够验证用户名/密码，而另一个可能能够验证 SAML 断言。这允许每个 AuthenticationProvider 执行非常特定类型的身份验证，同时支持多种类型的身份验证并且仅公开单个 AuthenticationManager bean。
	 * 		ProviderManager 还允许配置一个可选的父 AuthenticationManager ，在没有 AuthenticationProvider 可以执行身份验证的情况下，它会被查询。父级可以是任何类型的 AuthenticationManager ，但它通常是 ProviderManager 的一个实例。
	 * 		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/authentication/architecture/providermanager-parent.png
	 *
	 * 		事实上，多个 ProviderManager 实例可能共享同一个父 AuthenticationManager 。这在多个 SecurityFilterChain 实例具有一些共同的身份验证（共享父 AuthenticationManager ）但也有不同的身份验证机制（不同的 ProviderManager 实例）的场景中有些常见。
	 * 		https://docs.spring.io/spring-security/reference/5.8/_images/servlet/authentication/architecture/providermanagers-parent.png
	 *
	 * 		默认情况下， ProviderManager 将尝试从成功的身份验证请求返回的 Authentication 对象中清除任何敏感的凭据信息。这可以防止密码等信息在 HttpSession 中的保留时间超过必要时间。
	 * 		当您使用用户对象的缓存时，这可能会导致问题，例如，为了提高无状态应用程序的性能。如果 Authentication 包含对缓存中对象的引用（例如 UserDetails 实例）并且其凭据已删除，则将不再可能根据缓存值进行身份验证。如果您使用缓存，则需要考虑这一点。一个明显的解决方案是首先在缓存实现中或在创建返回的 Authentication 对象的 AuthenticationProvider 中创建对象的副本。或者，您可以禁用 ProviderManager 上的 eraseCredentialsAfterAuthentication 属性。有关详细信息，请参阅 Javadoc。
	 *
	 * 看到这里：
	 * 		https://docs.spring.io/spring-security/reference/5.8/servlet/authentication/architecture.html#servlet-authentication-authenticationprovider
	 * */
	public static void main(String[] args) {
		System.out.println("---");
	}
}
