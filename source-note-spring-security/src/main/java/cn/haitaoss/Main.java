
package cn.haitaoss;

import java.io.File;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.acl.Permission;
import java.util.List;

import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.coyote.http11.Http11NioProtocol;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.COOKIES;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-05 10:44
 *
 */
@ComponentScan
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
	 *                    DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
	 * 						HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
	 * 						requestCache.setMatchingRequestParameterName("continue");
	 * 						http
	 * 							// ...
	 * 							.requestCache((cache) -> cache
	 * 								.requestCache(requestCache)
	 * 							);
	 * 						return http.build();
	 *                    }
	 *
	 * 		Prevent the Request From Being Saved（防止请求被保存）
	 * 			您可能出于多种原因不想在会话中存储用户未经身份验证的请求。您可能希望将该存储卸载到用户的浏览器上或将其存储在数据库中。
	 * 			或者您可能希望关闭此功能，因为您总是希望将用户重定向到主页而不是他们在登录前尝试访问的页面。
	 * 			为此，您可以使用 NullRequestCache 实现。
	 *
	 *                        @Bean
	 *                        SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
	 * 						    RequestCache nullRequestCache = new NullRequestCache();
	 * 						    http
	 * 						        // ...
	 * 						        .requestCache((cache) -> cache
	 * 						            .requestCache(nullRequestCache)
	 * 						        );
	 * 						    return http.build();
	 *                        }
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
	 * AuthenticationProvider 身份验证提供者
	 *		可以将多个 AuthenticationProvider 注入到 ProviderManager 中。每个 AuthenticationProvider 执行特定类型的身份验证。例如， DaoAuthenticationProvider 支持基于用户名/密码的身份验证，而 JwtAuthenticationProvider 支持对 JWT 令牌进行身份验证。
	 *
	 * Request Credentials with AuthenticationEntryPoint 使用 AuthenticationEntryPoint 请求凭据
	 * 		AuthenticationEntryPoint 用于发送从客户端请求凭据的 HTTP 响应。
	 * 		有时，客户端会主动包含凭据（例如用户名/密码）来请求资源。在这些情况下，Spring Security 不需要提供从客户端请求凭据的 HTTP 响应，因为它们已经包含在内。
	 * 		在其他情况下，客户端将向他们无权访问的资源发出未经身份验证的请求。在这种情况下， AuthenticationEntryPoint 的实现用于从客户端请求凭据。 AuthenticationEntryPoint 实现可能会执行重定向到登录页面，使用 WWW-Authenticate 标头进行响应等。
	 *
	 * AbstractAuthenticationProcessingFilter
	 *		AbstractAuthenticationProcessingFilter 用作验证用户凭据的基础 Filter 。在可以验证凭据之前，Spring Security 通常使用 AuthenticationEntryPoint 请求凭据。
	 *		接下来， AbstractAuthenticationProcessingFilter 可以对提交给它的任何身份验证请求进行身份验证。
	 * */
	/**
	 * Username/Password Authentication 用户名/密码认证
	 * 		验证用户身份的最常见方法之一是验证用户名和密码。因此，Spring Security 为使用用户名和密码进行身份验证提供了全面的支持。
	 *		Reading the Username & Password 读取用户名和密码
	 *			Spring Security 提供了以下内置机制，用于从 HttpServletRequest 读取用户名和密码：From、Basic、Digest
	 *
	 *			From 表单登录
	 *			Spring Security 支持通过 html 表单提供的用户名和密码。本节提供有关基于表单的身份验证如何在 Spring Security 中工作的详细信息。
	 *			默认启用 Spring Security 表单登录。但是，一旦提供了任何基于 servlet 的配置，就必须明确提供基于表单的登录。可以在下面找到最小的显式 Java 配置：
	 *				public SecurityFilterChain filterChain(HttpSecurity http) {
	 * 					http
	 * 						.formLogin(withDefaults());
	 * 					// ...
	 *                }
	 * 				在此配置中，Spring Security 将呈现默认登录页面。大多数生产应用程序都需要自定义登录表单。
	 * 				public SecurityFilterChain filterChain(HttpSecurity http) {
	 * 					http
	 * 						.formLogin(form -> form
	 * 							.loginPage("/login")
	 * 							.permitAll()
	 * 						);
	 * 					// ...
	 *                }
	 *
	 *			Basic Authentication 基本认证
	 *				本节提供有关 Spring Security 如何为基于 servlet 的应用程序提供基本 HTTP 身份验证支持的详细信息。
	 *				默认情况下启用 Spring Security 的 HTTP 基本身份验证支持。但是，一旦提供了任何基于 servlet 的配置，就必须显式提供 HTTP Basic。
	 *                                @Bean
	 *                            public SecurityFilterChain filterChain(HttpSecurity http) {
	 * 								http
	 * 									// ...
	 * 									.httpBasic(withDefaults());
	 * 								return http.build();
	 *                            }
	 *			Digest 过时了，也是一种认证方式
	 *
	 *		Password Storage 密码存储
	 *			- Simple Storage with In-Memory Authentication
	 *				Spring Security 的 InMemoryUserDetailsManager 实现了 UserDetailsS​​ervice 以提供对存储在内存中的基于用户名/密码的身份验证的支持。 InMemoryUserDetailsManager 通过实现 UserDetailsManager 接口来提供对 UserDetails 的管理。当配置为接受用户名/密码进行身份验证时，Spring Security 使用基于 UserDetails 的身份验证。
	 *                                @Bean
	 *                                    public UserDetailsService users() {
	 * 										// The builder will ensure the passwords are encoded before saving in memory
	 * 										UserBuilder users = User.withDefaultPasswordEncoder();
	 * 										UserDetails user = users
	 * 											.username("user")
	 * 											.password("password")
	 * 											.roles("USER")
	 * 											.build();
	 * 										UserDetails admin = users
	 * 											.username("admin")
	 * 											.password("password")
	 * 											.roles("USER", "ADMIN")
	 * 											.build();
	 * 										return new InMemoryUserDetailsManager(user, admin);
	 *                                    }
	 * 			- Relational Databases with JDBC Authentication（需要配置数据源，固定要查询的表明和字段名了）
	 *                                @Bean
	 *                                    UserDetailsManager users(DataSource dataSource) {
	 * 										UserDetails user = User.builder()
	 * 											.username("user")
	 * 											.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
	 * 											.roles("USER")
	 * 											.build();
	 * 										UserDetails admin = User.builder()
	 * 											.username("admin")
	 * 											.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
	 * 											.roles("USER", "ADMIN")
	 * 											.build();
	 * 										JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
	 * 										users.createUser(user);
	 * 										users.createUser(admin);
	 * 										return users;
	 *                                    }
	 * 			- Custom data stores with UserDetailsService
	 * 				UserDetailsService 由 DaoAuthenticationProvider 用于检索用户名、密码和其他属性，以使用用户名和密码进行身份验证。 Spring Security 提供 UserDetailsService 的内存和 JDBC 实现。
	 * 				您可以通过将自定义 UserDetailsService 公开为 bean 来定义自定义身份验证。例如，以下将自定义身份验证，假设 CustomUserDetailsService 实现了 UserDetailsService ：
	 *                                        @Bean
	 *                                            CustomUserDetailsService customUserDetailsService() {
	 * 												return new CustomUserDetailsService();
	 *                                            }
	 * 			- LDAP storage with LDAP Authentication
	 *				是一种认证方式，不了解，不细看了
	 * */
	/**
	 * UserDetails
	 * 		UserDetails 由 UserDetailsService 返回。 DaoAuthenticationProvider 验证 UserDetails ，然后返回一个 Authentication ，该 Authentication 的主体是配置的 UserDetailsService 返回的 UserDetails 。
	 * PasswordEncoder
	 * 		Spring Security 的 servlet 支持通过与 PasswordEncoder 集成来安全地存储密码。自定义 Spring Security 使用的 PasswordEncoder 实现可以通过公开一个 PasswordEncoder Bean 来完成。
	 * DaoAuthenticationProvider
	 * 		让我们来看看 DaoAuthenticationProvider 在 Spring Security 中是如何工作的。该图详细说明了阅读用户名和密码中图中 AuthenticationManager 的工作原理。
	 * */
	/**
	 * Persisting Authentication	持久身份验证
	 * 	SecurityContextRepository：在 Spring Security 中，用户与未来请求的关联是使用 SecurityContextRepository 进行的。
	 * 	HttpSecurityContextRepository：SecurityContextRepository 的默认实现是 HttpSessionSecurityContextRepository ，它将 SecurityContext 关联到 HttpSession 。如果用户希望以其他方式或根本不将用户与后续请求相关联，则可以将 HttpSessionSecurityContextRepository 替换为 SecurityContextRepository 的另一种实现。
	 * 	NullSecurityContextRepository：如果不希望将 SecurityContext 关联到 HttpSession （即使用 OAuth 进行身份验证时），则 NullSecurityContextRepository 是不执行任何操作的 SecurityContextRepository 的实现。
	 * 	RequestAttributeSecurityContextRepository：RequestAttributeSecurityContextRepository 将 SecurityContext 保存为 request属性，以确保 SecurityContext 可用于跨越可能清除 SecurityContext 的 dispatch 类型发生的单个请求。
	 * 		例如，假设客户端发出请求，经过身份验证，然后发生错误。根据 servlet 容器的实现，错误意味着任何已建立的 SecurityContext 都被清除，然后进行错误分派。进行错误调度时，没有建立 SecurityContext 。这意味着错误页面不能使用 SecurityContext 进行授权或显示当前用户，除非以某种方式保留 SecurityContext 。
	 * 		public SecurityFilterChain filterChain(HttpSecurity http) {
	 * 			http
	 * 				// ...
	 * 				.securityContext((securityContext) -> securityContext
	 * 					.securityContextRepository(new RequestAttributeSecurityContextRepository())
	 * 				);
	 * 			return http.build();
	 *        }
	 *	DelegatingSecurityContextRepository
	 *		DelegatingSecurityContextRepository 将 SecurityContext 保存到多个 SecurityContextRepository 委托，并允许以指定顺序从任何委托中检索。
	 *		最有用的安排是使用以下示例配置的，它允许同时使用 RequestAttributeSecurityContextRepository 和 HttpSessionSecurityContextRepository 。
	 *                        @Bean
	 *                public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	 * 					http
	 * 						// ...
	 * 						.securityContext((securityContext) -> securityContext
	 * 							.securityContextRepository(new DelegatingSecurityContextRepository(
	 * 								new RequestAttributeSecurityContextRepository(),
	 * 								new HttpSessionSecurityContextRepository()
	 * 							))
	 * 						);
	 * 					return http.build();
	 *                }
	 *	SecurityContextPersistenceFilter
	 *		SecurityContextPersistenceFilter 负责使用 SecurityContextRepository 在请求之间保留 SecurityContext 。
	 *	SecurityContextHolderFilter
	 *		SecurityContextHolderFilter 负责使用 SecurityContextRepository 在请求之间加载 SecurityContext 。
	 *		与 SecurityContextPersistenceFilter 不同， SecurityContextHolderFilter 仅加载 SecurityContext 而不会保存 SecurityContext 。这意味着当使用 SecurityContextHolderFilter 时，需要显式保存 SecurityContext 。
	 *		public SecurityFilterChain filterChain(HttpSecurity http) {
	 * 			http
	 * 				// ...
	 * 				.securityContext((securityContext) -> securityContext
	 * 					.requireExplicitSave(true) // 显式保存 SecurityContext
	 * 				);
	 * 			return http.build();
	 *        }
	 * */
	/**
	 * Authentication Persistence and Session Management
	 *		一旦您获得了对请求进行身份验证的应用程序，重要的是要考虑如何在未来的请求中保留和恢复生成的身份验证。
	 *		默认情况下这是自动完成的，因此不需要额外的代码，但您应该考虑一些步骤。第一个是在 HttpSecurity 中设置 requireExplicitSave 属性。你可以这样做：
	 *		http
	 *         // ...
	 *         .securityContext((context) -> context
	 *             .requireExplicitSave(true)
	 *         );
	 *
	 * Remember-Me Authentication 记住我身份验证
	 * 		记住我或持久登录身份验证是指网站能够记住会话之间主体的身份。这通常是通过向浏览器发送一个 cookie 来完成的，该 cookie 在未来的会话中被检测到并导致自动登录发生。 Spring Security 为这些操作的发生提供了必要的钩子，并且有两个具体的 remember-me 实现。一种使用哈希来保护基于 cookie 的令牌的安全性，另一种使用数据库或其他持久存储机制来存储生成的令牌。
	 * 		请注意，这两种实现都需要 UserDetailsService 。如果您正在使用不使用 UserDetailsService 的身份验证提供程序（例如，LDAP 提供程序），那么它将无法工作，除非您的应用程序上下文中也有一个 UserDetailsService bean。
	 *
	 * Anonymous Authentication 匿名认证
	 * 		换句话说，有时候说 ROLE_SOMETHING 默认是必需的并且只允许此规则的某些例外情况是很好的，例如应用程序的登录、注销和主页。您也可以从过滤器链中完全忽略这些页面，从而绕过访问控制检查，但由于其他原因，这可能是不可取的，特别是如果页面对经过身份验证的用户的行为不同时。
	 * 		这就是我们所说的匿名身份验证的意思。请注意，“匿名身份验证”的用户和未经身份验证的用户之间在概念上没有真正的区别。 Spring Security 的匿名身份验证只是为您提供了一种更方便的方式来配置您的访问控制属性。例如，调用 servlet API（例如 getCallerPrincipal ）仍将返回 null，即使 SecurityContextHolder 中实际上有一个匿名身份验证对象。
	 * 		在其他情况下匿名身份验证也很有用，例如当审计拦截器查询 SecurityContextHolder 以确定哪个主体负责给定操作时。如果类知道 SecurityContextHolder 总是包含一个 Authentication 对象，而从不包含 null ，那么类可以被编写得更健壮。
	 *
	 *		在其他情况下匿名身份验证也很有用，例如当审计拦截器查询 SecurityContextHolder 以确定哪个主体负责给定操作时。如果类知道 SecurityContextHolder 总是包含一个 Authentication 对象，而从不包含 null ，那么类可以被编写得更健壮。
	 *
	 * Run-As Authentication Replacement
	 * 		AbstractSecurityInterceptor 能够在安全对象回调阶段临时替换 SecurityContext 和 SecurityContextHolder 中的 Authentication 对象。只有当 AuthenticationManager 和 AccessDecisionManager 成功处理了原始的 Authentication 对象时才会发生这种情况。 RunAsManager 将指示替换 Authentication 对象（如果有）应在 SecurityInterceptorCallback 期间使用。
	 * 		通过在安全对象回调阶段临时替换 Authentication 对象，安全调用将能够调用需要不同身份验证和授权凭据的其他对象。它还将能够对特定的 GrantedAuthority 对象执行任何内部安全检查。因为 Spring Security 提供了许多帮助程序类，可以根据 SecurityContextHolder 的内容自动配置远程协议，所以这些运行方式替换在调用远程 Web 服务时特别有用。
	 * 		RunAsManager
	 *
	 * Handling Logouts
	 * 		注入 HttpSecurity bean 时，会自动应用注销功能。默认情况下，访问 URL /logout 将通过以下方式注销用户：
	 * 			- Invalidating the HTTP Session
	 * 			- Cleaning up any RememberMe authentication that was configured
	 * 			- Clearing the SecurityContextHolder
	 * 			- Clearing the SecurityContextRepository
	 * 			- Redirect to /login?logout
	 * 		http
	 *         .logout(logout -> logout
	 *             .logoutUrl("/my/logout")
	 *             .logoutSuccessUrl("/my/index")
	 *             .logoutSuccessHandler(logoutSuccessHandler)
	 *             .invalidateHttpSession(true)
	 *             .addLogoutHandler(logoutHandler)
	 *             .deleteCookies(cookieNamesToClear)
	 *         )
	 *
	 *      LogoutHandler、LogoutSuccessHandler 、
	 *
	 * Authentication Events
	 *		对于成功或失败的每个身份验证，分别触发 AuthenticationSuccessEvent 或 AbstractAuthenticationFailureEvent 。
	 *		要侦听这些事件，您必须首先发布一个 AuthenticationEventPublisher 。 Spring Security 的 DefaultAuthenticationEventPublisher 可能会很好：
	 *                        @Bean
	 *                        public AuthenticationEventPublisher authenticationEventPublisher
	 * 						        (ApplicationEventPublisher applicationEventPublisher) {
	 * 						    return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
	 *                        }
	 *		然后，您可以使用 Spring 的 @EventListener 支持：
	 *                        @Component
	 *            public class AuthenticationEvents {    * 	@EventListener
	 * 			    public void onSuccess(AuthenticationSuccessEvent success) {
	 * 					// ...
	 *                }
	 *
	 *                @EventListener
	 *                public void onFailure(AbstractAuthenticationFailureEvent failures) {
	 * 					// ...
	 *                }
	 *            }
	 *		虽然类似于 AuthenticationSuccessHandler 和 AuthenticationFailureHandler ，但它们很好，因为它们可以独立于 servlet API 使用。
	 *		为此，您可能希望通过 setAdditionalExceptionMappings 方法向发布者提供额外的映射：
	 *                        @Bean
	 *                            public AuthenticationEventPublisher authenticationEventPublisher
	 * 							        (ApplicationEventPublisher applicationEventPublisher) {
	 * 							    Map<Class<? extends AuthenticationException>,
	 * 							        Class<? extends AbstractAuthenticationFailureEvent>> mapping =
	 * 							            Collections.singletonMap(FooException.class, FooEvent.class);
	 * 							    AuthenticationEventPublisher authenticationEventPublisher =
	 * 							        new DefaultAuthenticationEventPublisher(applicationEventPublisher);
	 * 							    authenticationEventPublisher.setAdditionalExceptionMappings(mapping);
	 * 							    return authenticationEventPublisher;
	 *                            }
	 * */
	/**
	 * Authorization
	 * 		Spring Security 中的高级授权功能是其流行的最引人注目的原因之一。无论您选择如何进行身份验证 - 无论是使用 Spring Security 提供的机制和提供者，还是与容器或其他非 Spring Security 身份验证机构集成 - 您都会发现授权服务可以在您的应用程序中以一致且简单的方式使用方式。
	 * 		在这一部分中，我们将探索在第一部分中介绍的不同的 AbstractSecurityInterceptor 实现。然后我们继续探索如何通过使用域访问控制列表来微调授权。
	 *
	 * Authorization Architecture 授权架构
	 * 		Authentication ，讨论了所有 Authentication 实现如何存储 GrantedAuthority 对象的列表。这些代表已授予委托人的权限。 GrantedAuthority 对象由 AuthenticationManager 插入到 Authentication 对象中，随后在做出授权决定时由 AuthorizationManager 读取。
	 *
	 * 		Pre-Invocation Handling 调用前处理
	 * 			Spring Security 提供拦截器来控制对安全对象（例如方法调用或 Web 请求）的访问。关于是否允许调用继续的调用前决定由 AccessDecisionManager 做出。
	 *
	 * 		The AuthorizationManager 授权管理器
	 *			AuthorizationManager 取代了 AccessDecisionManager 和 AccessDecisionVoter 。
	 *			鼓励自定义 AccessDecisionManager 或 AccessDecisionVoter 的应用程序更改为使用 AuthorizationManager 。
	 *			AuthorizationManager 由 AuthorizationFilter 调用并负责做出最终的访问控制决策。 AuthorizationManager 接口包含两个方法：
	 *				AuthorizationDecision check(Supplier<Authentication> authentication, Object secureObject);
	 * 				default AuthorizationDecision verify(Supplier<Authentication> authentication, Object secureObject)
	 * 				        throws AccessDeniedException {
	 * 				    // ...
	 *                }
	 * 			实际安全对象调用中的那些参数。例如，假设安全对象是 MethodInvocation 。在 MethodInvocation 中查询任何 Customer 参数很容易，然后在 AuthorizationManager 中实施某种安全逻辑以确保允许委托人对该客户进行操作。如果授予访问权限，实现应返回正值 AuthorizationDecision ，如果访问被拒绝，则返回负值 AuthorizationDecision ，如果放弃做出决定，则返回空值 AuthorizationDecision 。
	 * 			verify 调用 check ，随后在 AuthorizationDecision 为负数的情况下抛出 AccessDeniedException 。
	 *
	 * 		Delegate-based AuthorizationManager Implementations
	 * 			虽然用户可以实现自己的 AuthorizationManager 来控制授权的所有方面，但 Spring Security 附带了一个委托 AuthorizationManager 可以与个人 AuthorizationManager 协作。
	 * 			RequestMatcherDelegatingAuthorizationManager 会将请求与最合适的 Delegate AuthorizationManager 匹配。对于方法安全，您可以使用 AuthorizationManagerBeforeMethodInterceptor 和 AuthorizationManagerAfterMethodInterceptor 。
	 * 			使用这种方法，可以轮询 AuthorizationManager 实现的组合以做出授权决定。
	 * 			Authorization Manager Implementations https://docs.spring.io/spring-security/reference/5.8/_images/servlet/authorization/authorizationhierarchy.png
	 *
	 *		AuthorityAuthorizationManager 权限授权管理器
	 *			Spring Security 提供的最常见的 AuthorizationManager 是 AuthorityAuthorizationManager 。它配置了一组给定的权限以在当前 Authentication 上查找。如果 Authentication 包含任何已配置的权限，它将返回肯定的 AuthorizationDecision 。否则它将返回负值 AuthorizationDecision 。
	 *
	 *		AuthenticatedAuthorizationManager
	 *			另一位 manager 是 AuthenticatedAuthorizationManager 。它可用于区分匿名用户、完全身份验证用户和记住我身份验证用户。许多站点允许在记住我身份验证的情况下进行某些有限的访问，但要求用户通过登录来确认其身份以获得完全访问权限。
	 *
	 *		Custom Authorization Managers 自定义授权管理器
	 *			显然，您还可以实现一个自定义的 AuthorizationManager ，您可以在其中放入您想要的任何访问控制逻辑。它可能特定于您的应用程序（与业务逻辑相关），或者它可能实现一些安全管理逻辑。例如，您可以创建一个可以查询 Open Policy Agent 或您自己的授权数据库的实现。
	 *
	 *		Hierarchical Roles 分层角色
	 *			应用程序中的特定角色应该自动“包含”其他角色是一个常见的要求。例如，在具有“管理员”和“用户”角色概念的应用程序中，您可能希望管理员能够执行普通用户可以执行的所有操作。为此，您可以确保所有管理员用户也被分配了“用户”角色。或者，您可以修改每个需要“用户”角色的访问约束，以同时包含“管理员”角色。如果您的应用程序中有很多不同的角色，这可能会变得非常复杂。
	 *			角色层次结构的使用允许您配置哪些角色（或权限）应包括其他角色。 Spring Security 的 RoleVoter 的扩展版本， RoleHierarchyVoter 配置了 RoleHierarchy ，它从中获取分配给用户的所有“可达权限”。典型的配置可能如下所示：
	 *
	 *
	 * */
	/**
	 * 可以看到权限的配置方式，没细看。 https://docs.spring.io/spring-security/reference/5.8/servlet/authorization/authorize-http-requests.html
	 * Authorize HttpServletRequests with AuthorizationFilter
	 * 		AuthorizationFilter 取代 FilterSecurityInterceptor 。为了保持向后兼容， FilterSecurityInterceptor 保持默认。本节讨论 AuthorizationFilter 的工作原理以及如何覆盖默认配置。
	 * 		AuthorizationFilter 为 HttpServletRequest 提供授权。它作为安全过滤器之一插入到 FilterChainProxy 中。
	 * 		您可以在声明 SecurityFilterChain 时覆盖默认值。不要使用 authorizeRequests ，而是使用 authorizeHttpRequests ，如下所示：
	 *                        @Bean
	 *                            SecurityFilterChain web(HttpSecurity http) throws AuthenticationException {
	 * 							    http
	 * 							        .authorizeHttpRequests((authorize) -> authorize
	 * 							            .anyRequest().authenticated();
	 * 							        )
	 * 							        // ...
	 *
	 * 							    return http.build();
	 *                            }
	 *		当使用 authorizeHttpRequests 代替 authorizeRequests 时，则使用 AuthorizationFilter 代替 FilterSecurityInterceptor
	 *		我们可以通过按优先顺序添加更多规则来配置 Spring Security 以具有不同的规则。
	 *                        @Bean
	 *                        SecurityFilterChain web(HttpSecurity http) throws Exception {
	 * 							http
	 * 								// ...
	 * 								.authorizeHttpRequests(authorize -> authorize
	 * 									.requestMatchers("/resources/**", "/signup", "/about").permitAll()
	 * 									.requestMatchers("/admin/**").hasRole("ADMIN")
	 * 									.requestMatchers("/db/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasRole('DBA')"))
	 * 									// .requestMatchers("/db/**").access(AuthorizationManagers.allOf(AuthorityAuthorizationManager.hasRole("ADMIN"), AuthorityAuthorizationManager.hasRole("DBA")))
	 * 									.anyRequest().denyAll()
	 * 								);
	 *
	 * 							return http.build();
	 *                        }
	 *		您可以通过构建自己的 RequestMatcherDelegatingAuthorizationManager 来采用基于 bean 的方法
	 *                        @Bean
	 *                        SecurityFilterChain web(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> access)
	 * 						        throws AuthenticationException {
	 * 						    http
	 * 						        .authorizeHttpRequests((authorize) -> authorize
	 * 						            .anyRequest().access(access)
	 * 						        )
	 * 						        // ...
	 *
	 * 						    return http.build();
	 *                        }
	 *
	 *                        @Bean
	 *                        AuthorizationManager<RequestAuthorizationContext> requestMatcherAuthorizationManager(HandlerMappingIntrospector introspector) {
	 * 						    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
	 * 						    RequestMatcher permitAll =
	 * 						            new AndRequestMatcher(
	 * 						                    mvcMatcherBuilder.pattern("/resources/**"),
	 * 						                    mvcMatcherBuilder.pattern("/signup"),
	 * 						                    mvcMatcherBuilder.pattern("/about"));
	 * 						    RequestMatcher admin = mvcMatcherBuilder.pattern("/admin/**");
	 * 						    RequestMatcher db = mvcMatcherBuilder.pattern("/db/**");
	 * 						    RequestMatcher any = AnyRequestMatcher.INSTANCE;
	 * 						    AuthorizationManager<HttpServletRequest> manager = RequestMatcherDelegatingAuthorizationManager.builder()
	 * 						            .add(permitAll, (context) -> new AuthorizationDecision(true))
	 * 						            .add(admin, AuthorityAuthorizationManager.hasRole("ADMIN"))
	 * 						            .add(db, AuthorityAuthorizationManager.hasRole("DBA"))
	 * 						            .add(any, new AuthenticatedAuthorizationManager())
	 * 						            .build();
	 * 						    return (context) -> manager.check(context.getRequest());
	 *                        }
	 *		默认情况下， AuthorizationFilter 不适用于 DispatcherType.ERROR 和 DispatcherType.ASYNC 。我们可以使用 shouldFilterAllDispatcherTypes 方法配置 Spring Security 以将授权规则应用于所有调度程序类型：
	 *                        @Bean
	 *                        SecurityFilterChain web(HttpSecurity http) throws Exception {
	 * 						    http
	 * 						        .authorizeHttpRequests((authorize) -> authorize
	 * 						            .shouldFilterAllDispatcherTypes(true)
	 * 						            .anyRequest.authenticated()
	 * 						        )
	 * 						        // ...
	 *
	 * 						    return http.build();
	 *                        }
	 * 		现在，由于授权规则适用于所有调度程序类型，您可以更好地控制它们的授权。例如，您可能希望将 shouldFilterAllDispatcherTypes 配置为 true 但不对调度程序类型为 ASYNC 或 FORWARD 的请求应用授权。
	 *                        @Bean
	 *                            SecurityFilterChain web(HttpSecurity http) throws Exception {
	 * 							    http
	 * 							        .authorizeHttpRequests((authorize) -> authorize
	 * 							            .shouldFilterAllDispatcherTypes(true)
	 * 							            .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.FORWARD).permitAll()
	 * 							            .anyRequest().authenticated()
	 * 							        )
	 * 							        // ...
	 *
	 * 							    return http.build();
	 *                            }
	 *
	 *		如果您想使用特定的 RequestMatcher ，只需将实现传递给 securityMatcher 和/或 requestMatcher 方法：
	 *			import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher; (1)
	 * import static org.springframework.security.web.util.matcher.RegexRequestMatcher.regexMatcher;
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 *
	 * */
	/**
	 * Authorize HttpServletRequest with FilterSecurityInterceptor
	 *
	 * 	FilterSecurityInterceptor 正在被 AuthorizationFilter 替换。了解即可
	 *                @Bean
	 *                public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	 * 					http
	 * 						// ...
	 * 						.authorizeRequests(authorize -> authorize
	 * 							.anyRequest().authenticated()
	 * 						);
	 * 					return http.build();
	 *                }
	 * */
	/**
	 * Expression-Based Access Control 基于表达式的访问控制
	 * 		Spring Security 使用 Spring EL 来支持表达式，根对象是 SecurityExpressionRoot，看根对象就知道 SpEL 表达式支持那些内置属性和方法了
	 *
	 * 		如果您希望扩展可用的表达式，您可以轻松地引用您公开的任何 Spring Bean。例如，假设您有一个名为 webSecurity 的 Bean，其中包含以下方法签名：
	 * 		http
	 *     .authorizeHttpRequests(authorize -> authorize
	 *         .requestMatchers("/user/**").access(new WebExpressionAuthorizationManager("@webSecurity.check(authentication,request)"))
	 *         ...
	 *     )
	 *
	 *     http
	 * 		.authorizeHttpRequests(authorize -> authorize
	 * 			.requestMatchers("/user/{userId}/**").access(new WebExpressionAuthorizationManager("@webSecurity.checkUserId(authentication,#userId)"))
	 * 			...
	 * 		);
	 *
	 *        @PreAuthorize 、 @PreFilter 、 @PostAuthorize 和 @PostFilter
	 * 		主体的使用demo 看官方文档把：https://docs.spring.io/spring-security/reference/5.8/servlet/authorization/expression-based.html
	 * */
	/**
	 * Method Security
	 * 	从 2.0 版开始，Spring Security 大大改进了对向服务层方法添加安全性的支持。它支持 JSR-250 注释安全性以及框架的原始 @Secured 注释。从 3.0 开始，您还可以使用新的基于表达式的注释。您可以将安全性应用于单个 bean，使用 intercept-methods 元素来装饰 bean 声明，或者您可以使用 AspectJ 样式切入点保护整个服务层中的多个 bean
	 *
	 *    @EnableMethodSecurity 和 @EnableGlobalMethodSecurity
	 * 	在 Spring Security 5.6 中，我们可以在任何 @Configuration 实例上使用 @EnableMethodSecurity 注解来启用基于注解的安全性。这在很多方面改进了 @EnableGlobalMethodSecurity：
	 *
	 * 	Spring Security 的 @PreAuthorize 、 @PostAuthorize 、 @PreFilter 和 @PostFilter 附带了丰富的基于表达式的支持。
	 * 	如果您需要自定义处理表达式的方式，您可以公开一个自定义的 MethodSecurityExpressionHandler
	 *        @Bean
	 *             static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
	 *			 	DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
	 *			 	handler.setTrustResolver(myCustomTrustResolver);
	 *			 	return handler;
	 *             }
	 *		注：我们使用 static 方法公开 MethodSecurityExpressionHandler 以确保Spring 在它初始化Spring Security 的方法安全 @Configuration 类之前发布它
	 *
	 *	您可以通过公开 GrantedAuthorityDefaults bean 将授权规则配置为使用不同的前缀，如下所示：
	 *        @Bean
	 *         static GrantedAuthorityDefaults grantedAuthorityDefaults() {
	 *		 	return new GrantedAuthorityDefaults("MYPREFIX_");
	 *         }
		 * */
	/**
	 * Authorization Events 授权事件
	 * 	对于每个被拒绝的授权，都会触发一个 AuthorizationDeniedEvent 。此外，可以为授予的授权触发和 AuthorizationGrantedEvent 。
	 * 	要侦听这些事件，您必须首先发布一个 AuthorizationEventPublisher 。
	 * 	Spring Security 的 SpringAuthorizationEventPublisher 可能会很好。它使用 Spring 的 ApplicationEventPublisher 来发布授权事件：
	 *                @Bean
	 * 					public AuthorizationEventPublisher authorizationEventPublisher
	 * 					        (ApplicationEventPublisher applicationEventPublisher) {
	 * 					    return new SpringAuthorizationEventPublisher(applicationEventPublisher);
	 * 					}
	 * 然后，您可以使用 Spring 的 @EventListener 支持：
	 *                @Component
	 * 				public class AuthenticationEvents {
	 *
	 * 				    @EventListener
	 * 				    public void onFailure(AuthorizationDeniedEvent failure) {
	 * 						// ...
	 * 				    }
	 * 				}
	 * */
	/**
	 * 没有细看的内容，用到再说吧，先了解整体框架的实现逻辑，后面的内容只是锦上添花而已
	 *
	 * Spring Security 提供全面的 OAuth 2 支持。本节讨论如何将 OAuth 2 集成到基于 servlet 的应用程序中。
	 * Spring Security 提供全面的 SAML 2 支持。本节讨论如何将 SAML 2 集成到基于 servlet 的应用程序中。
	 * 本节讨论 Spring Security 对 servlet 环境的跨站请求伪造 (CSRF) 支持。
	 * */
	/**
	 * Spring MVC Integration
	 * 从 Spring Security 4.0 开始，不推荐使用 @EnableWebMvcSecurity 。替换为 @EnableWebSecurity ，它将根据类路径确定添加 Spring MVC 功能。
	 * 要启用 Spring Security 与 Spring MVC 的集成，请将 @EnableWebSecurity 注释添加到您的配置中。
	 * 		注：Spring Security 使用 Spring MVC 的 WebMvcConfigurer 提供配置。这意味着如果您使用更高级的选项，比如直接与 WebMvcConfigurationSupport 集成，那么您将需要手动提供 Spring Security 配置。
	 *
	 * MvcRequestMatcher
	 * 		Spring Security 提供了与 Spring MVC 如何匹配带有 MvcRequestMatcher 的 URL 的深度集成。这有助于确保您的安全规则与用于处理您的请求的逻辑相匹配。
	 * 		使用 Spring MVC 时的一个常见要求是指定 servlet 路径属性，因为您可以使用 MvcRequestMatcher.Builder 创建多个共享相同 servlet 路径的 MvcRequestMatcher 实例：
	 *                        @Bean
	 * 						public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
	 * 							MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector).servletPath("/path");
	 * 							http
	 * 								.authorizeHttpRequests((authorize) -> authorize
	 * 									.requestMatchers(mvcMatcherBuilder.pattern("/admin")).hasRole("ADMIN")
	 * 									.requestMatchers(mvcMatcherBuilder.pattern("/user")).hasRole("USER")
	 * 								);
	 * 							return http.build();
	 * 						}
	 *
	 *		SpringMVC 这么写。访问 /admin 和 /admin.html 都可以，所以如果写起来会很费劲，这时候就可以使用 MvcRequestMatcher 来解决这个问题
	 *		幸运的是，当使用 requestMatchers DSL 方法时，如果 Spring Security 检测到 Spring MVC 在类路径中可用，它会自动创建一个 MvcRequestMatcher 。因此，它将通过使用 Spring MVC 匹配 URL 来保护 Spring MVC 将匹配的相同 URL。
	 *
	 *                @RequestMapping("/admin")
	 * 				 public String admin() {}
	 *
	 * Spring Security 提供 AuthenticationPrincipalArgumentResolver 可以自动解析当前 Authentication.getPrincipal() 的Spring MVC 参数。通过使用 @EnableWebSecurity ，您将自动将其添加到您的 Spring MVC 配置中。如果您使用基于 XML 的配置，则必须
	 * 		import org.springframework.security.core.annotation.AuthenticationPrincipal;
	 * 		@RequestMapping("/messages/inbox")
	 * 		public ModelAndView findMessagesForUser(@AuthenticationPrincipal CustomUser customUser) {
	 * 		}
	 *
	 * Spring Security 提供 CsrfTokenArgumentResolver 可以自动解析当前 CsrfToken 的Spring MVC 参数。通过使用 @EnableWebSecurity ，您将自动将其添加到您的 Spring MVC 配置中。如果您使用基于 XML 的配置，则必须自己添加。
	 * 		@RestController
	 * 		public class CsrfController {
	 *
	 * 		       @RequestMapping("/csrf")
	 * 		   public CsrfToken csrf(CsrfToken token) {
	 * 				return token;
	 * 		   }
	 * 		}
	 * */
	public static interface TestSecurityAnnotation {
		public interface BankService {

			@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
			public Account readAccount(Long id);

			@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
			public Account[] findAccounts();

			@Secured("ROLE_TELLER")
			public Account post(Account account, double amount);

			class Account { }
		}

		@PreAuthorize("hasRole('USER')")
		public void create(Contact contact);

		@PreAuthorize("hasPermission(#contact, 'admin')")
		public void deletePermission(Contact contact, String recipient, Permission permission);

		@PreAuthorize("#c.name == authentication.name")
		public void doSomething(@P("c") Contact contact);

		@PreAuthorize("#contact.name == authentication.name")
		public void doSomething2(Contact contact);

		@PreAuthorize("hasRole('USER')")
		@PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, 'admin')")
		public List<Contact> getAll();

		@Retention(RetentionPolicy.RUNTIME)
		@PreAuthorize("#contact.name == authentication.name")
		public @interface ContactPermission { }

		public class Contact { }
	}

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

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http

				.sessionManagement((session) -> session
								// 如果您不想创建会话，可以使用 SessionCreationPolicy.STATELESS
								.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
						//	自定义无效会话策略
						//.invalidSessionStrategy(new MyCustomInvalidSessionStrategy())
				)
				// 将 HTTP Basic 身份验证存储在 HttpSession (以上内容也适用于其他身份验证机制，例如 Bearer Token Authentication )
				.httpBasic((basic) -> basic
						.addObjectPostProcessor(new ObjectPostProcessor<BasicAuthenticationFilter>() {
							@Override
							public <O extends BasicAuthenticationFilter> O postProcess(O filter) {
								filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
								return filter;
							}
						})
				)
				// 配置并发会话控制
				.sessionManagement(session -> session
						.maximumSessions(1) // 这将防止用户多次登录 - 第二次登录将导致第一次登录无效。
						.maxSessionsPreventsLogin(true)     // 您通常希望阻止第二次登录，
				)
				//				会话会自行过期，无需执行任何操作即可确保删除安全上下文。也就是说，Spring Security 可以检测会话何时过期并采取您指示的特定操作。例如，当用户使用已过期的会话发出请求时，您可能希望重定向到特定端点。这是通过 HttpSecurity 中的
				.sessionManagement(session -> session
						.invalidSessionUrl("/invalidSession")
				)
				// 您可以在注销时显式删除 JSESSIONID cookie，例如通过在注销处理程序中使用 Clear-Site-Data 标头：
				.logout((logout) -> logout
						.addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(COOKIES)))
				)
		;

		return http.build();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
//		如果您希望限制单个用户登录到您的应用程序的能力，Spring Security 通过以下简单的添加支持开箱即用。首先，您需要将以下侦听器添加到您的配置中，以保持 Spring Security 更新有关会话生命周期事件的信息：
		return new HttpSessionEventPublisher();
	}
}
