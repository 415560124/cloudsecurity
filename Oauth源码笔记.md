# Oauth源码笔记

## class - AbstractAuthenticationProcessingFilter - 登录验证处理类 

### action - doFilter - 登录验证逻辑

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);

			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Request is to process authentication");
		}

		Authentication authResult;

		try {
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				// authentication
				return;
			}
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		catch (InternalAuthenticationServiceException failed) {
			logger.error(
					"An internal error occurred while trying to authenticate the user.",
					failed);
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		catch (AuthenticationException failed) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, failed);

			return;
		}

		// Authentication success
		if (continueChainBeforeSuccessfulAuthentication) {
			chain.doFilter(request, response);
		}

		successfulAuthentication(request, response, chain, authResult);
	}
```

***

## class - ClientCredentialsTokenEndpointFilter - OAuth2令牌端点的筛选器和身份验证端点。允许客户端使用请求参数进行身份验证(如果包含作为安全过滤器)，这是规范允许的(但不推荐)。规范建议您允许客户端使用HTTP基本身份验证，并且完全不使用此筛选器。

### action - attemptAuthentication - 客户端信息封装

```java
@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (allowOnlyPost && !"POST".equalsIgnoreCase(request.getMethod())) {
			throw new HttpRequestMethodNotSupportedException(request.getMethod(), new String[] { "POST" });
		}

		String clientId = request.getParameter("client_id");
		String clientSecret = request.getParameter("client_secret");

		// If the request is already authenticated we can assume that this
		// filter is not needed
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.isAuthenticated()) {
			return authentication;
		}

		if (clientId == null) {
			throw new BadCredentialsException("No client credentials presented");
		}

		if (clientSecret == null) {
			clientSecret = "";
		}

		clientId = clientId.trim();
        //将clientId和clientSecret构造成UsernamePasswordAuthenticationToken
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId,
				clientSecret);

		return this.getAuthenticationManager().authenticate(authRequest);

	}
```

***



## class - ProviderManager - 验证前后逻辑

### action - authenticate - 验证管理，寻找执行验证的真正方法

```java
public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		AuthenticationException parentException = null;
		Authentication result = null;
		Authentication parentResult = null;
		boolean debug = logger.isDebugEnabled();

		for (AuthenticationProvider provider : getProviders()) {
			if (!provider.supports(toTest)) {
				continue;
			}

			if (debug) {
				logger.debug("Authentication attempt using "
						+ provider.getClass().getName());
			}

			try {
				result = provider.authenticate(authentication);

				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException | InternalAuthenticationServiceException e) {
				prepareException(e, authentication);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw e;
			} catch (AuthenticationException e) {
				lastException = e;
			}
		}

		if (result == null && parent != null) {
			// Allow the parent to try.
			try {
				result = parentResult = parent.authenticate(authentication);
			}
			catch (ProviderNotFoundException e) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException e) {
				lastException = parentException = e;
			}
		}

		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}

			// If the parent AuthenticationManager was attempted and successful than it will publish an AuthenticationSuccessEvent
			// This check prevents a duplicate AuthenticationSuccessEvent if the parent AuthenticationManager already published it
			if (parentResult == null) {
				eventPublisher.publishAuthenticationSuccess(result);
			}
			return result;
		}

		// Parent was null, or didn't authenticate (or throw an exception).

		if (lastException == null) {
			lastException = new ProviderNotFoundException(messages.getMessage(
					"ProviderManager.providerNotFound",
					new Object[] { toTest.getName() },
					"No AuthenticationProvider found for {0}"));
		}

		// If the parent AuthenticationManager was attempted and failed than it will publish an AbstractAuthenticationFailureEvent
		// This check prevents a duplicate AbstractAuthenticationFailureEvent if the parent AuthenticationManager already published it
		if (parentException == null) {
			prepareException(lastException, authentication);
		}

		throw lastException;
	}
```



***



## class - AuthorizationEndpoint - 它是与用户交互的端点，用户在此进行为客户端应用授权的操作，即authorization grant

### action - authorize - 授权界面

```java
@RequestMapping(value = "/oauth/authorize")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters,
			SessionStatus sessionStatus, Principal principal) {

		// 首先使用OAuth2RequestFactory提取授权请求。所有进一步的逻辑都应该查询授权请求，而不是引用参数映射。一旦创建了AuthorizationRequest对象，参数映射的内容将被存储，而无需更改。
		AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);

		Set<String> responseTypes = authorizationRequest.getResponseTypes();
		// /oauth/authorize这个请求只支持授权码code模式和Implicit隐式模式
		if (!responseTypes.contains("token") && !responseTypes.contains("code")) {
            //不允许的响应类型 就是response_type参数
			throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
		}
		//客户端id是否为null
		if (authorizationRequest.getClientId() == null) {
			throw new InvalidClientException("A client id must be provided");
		}

		try {
			//Oauth2授权的第一步就是要确保用户是否已经登陆，然后才会授权
            //这里体现的是SecurityContext中是否包涵了已经授权的Authentication身份
            //principal对象是 UsernamePasswordAuthenticationToken
			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
                //在完成授权之前，必须使用Spring Security对用户进行身份验证
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}
			//客户端信息
			ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());

			// 解析后的重定向URI要么是来自参数的redirect_uri，要么是来自clientDetails的redirect_uri。无论哪种方式，我们都需要将其存储在AuthorizationRequest中。
			String redirectUriParameter = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, client);
			if (!StringUtils.hasText(resolvedRedirect)) {
            	//redirectUri必须在客户中提供或预先配置
				throw new RedirectMismatchException(
						"A redirectUri must be either supplied or preconfigured in the ClientDetails");
			}
            //设置重定向
			authorizationRequest.setRedirectUri(resolvedRedirect);

			// 我们故意只验证客户端请求的参数(忽略可能已经被添加到请求中的任何数据).
			oauth2RequestValidator.validateScope(authorizationRequest, client);

			// 有些系统可能允许默认地记住或批准批准决策。在这里检查这样的逻辑，并相应地在授权请求上设置approved标记。
			authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest,
					(Authentication) principal);
			//  用户批准处理程序，通过查阅现有的批准来记住批准决策
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
			authorizationRequest.setApproved(approved);

			// 验证已经完成，所以我们可以检查自动批准…
			if (authorizationRequest.isApproved()) {
				if (responseTypes.contains("token")) {
					return getImplicitGrantResponse(authorizationRequest);
				}
				if (responseTypes.contains("code")) {
					return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest,
							(Authentication) principal));
				}
			}

			// 在会话中存储authorizationRequest和一个不可变的authorizationRequest映射，用于验证approveOrDeny()  传给MVC在页面存储，用于下一个方法
			model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
			model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, unmodifiableMap(authorizationRequest));
			
			return getUserApprovalPageResponse(model, authorizationRequest, (Authentication) principal);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}
```

### action - authorize - 表单提交授权后访问

```java
//此方法必输参数 USER_OAUTH_APPROVAL  否则执行上面方法
@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = OAuth2Utils.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal) {
		//在授权访问令牌之前，必须使用Spring Security对用户进行身份验证  检测是否已验证
		if (!(principal instanceof Authentication)) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}
		//获得身份内容
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get(AUTHORIZATION_REQUEST_ATTR_NAME);

		if (authorizationRequest == null) {
			sessionStatus.setComplete();
			throw new InvalidRequestException("Cannot approve uninitialized authorization request.");
		}

		// 检查以确保在用户批准步骤中没有修改授权请求
		@SuppressWarnings("unchecked")
		Map<String, Object> originalAuthorizationRequest = (Map<String, Object>) model.get(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME);
		if (isAuthorizationRequestModified(authorizationRequest, originalAuthorizationRequest)) {
			throw new InvalidRequestException("Changes were detected from the original authorization request.");
		}

		try {
            //获得响应类型
			Set<String> responseTypes = authorizationRequest.getResponseTypes();
			//页面输入的授权参数写入request
			authorizationRequest.setApprovalParameters(approvalParameters);
			//设置授权相关信息
            authorizationRequest = userApprovalHandler.updateAfterApproval(authorizationRequest,
					(Authentication) principal);
            //取出是否存在授权域（上一步已验证）
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
			authorizationRequest.setApproved(approved);

			if (authorizationRequest.getRedirectUri() == null) {
				sessionStatus.setComplete();
				throw new InvalidRequestException("Cannot approve request when no redirect URI is provided.");
			}

			if (!authorizationRequest.isApproved()) {
				return new RedirectView(getUnsuccessfulRedirect(authorizationRequest,
						new UserDeniedAuthorizationException("User denied access"), responseTypes.contains("token")),
						false, true, false);
			}

			if (responseTypes.contains("token")) {
				return getImplicitGrantResponse(authorizationRequest).getView();
			}

			return getAuthorizationCodeResponse(authorizationRequest, (Authentication) principal);
		}
		finally {
			sessionStatus.setComplete();
		}

 }
```



***

## class - TokenEndpoint  - 通过请求 oauth/token 来获取 token

### action - postAccessToken - 获取token

```java
@RequestMapping(value = "/oauth/token", method=RequestMethod.POST)
	public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam
	Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {

		if (!(principal instanceof Authentication)) {
			throw new InsufficientAuthenticationException(
					"There is no client authentication. Try adding an appropriate authentication filter.");
		}
		//从 principal 中获取 clientId。
		String clientId = getClientId(principal);
        //装在clientDetails
		ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);
		//从 parameters 中获取 clientId、scope、grantType 以组装 TokenRequest。
		TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);

		if (clientId != null && !clientId.equals("")) {
			// 如果在此请求期间客户端通过了身份验证，则仅验证客户端详细信息。
			if (!clientId.equals(tokenRequest.getClientId())) {
				// 再次检查，以确保令牌请求中的客户端ID与经过身份验证的客户端中的相同
				throw new InvalidClientException("Given client ID does not match authenticated client");
			}
		}
        //根据 grantType 设置 TokenRequest 的 scope
		if (authenticatedClient != null) {
			oAuth2RequestValidator.validateScope(tokenRequest, authenticatedClient);
		}
        //授权类型有: password 模式、authorization_code 模式、refresh_token 模式、client_credentials 模式、implicit 模式
        //是否存在授权模式
		if (!StringUtils.hasText(tokenRequest.getGrantType())) {
			throw new InvalidRequestException("Missing grant type");
		}
        //令牌端点不支持隐式授权类型
		if (tokenRequest.getGrantType().equals("implicit")) {
			throw new InvalidGrantException("Implicit grant type not supported from token endpoint");
		}
		// 如果是授权码模式, 则清空 scope。 因为授权请求过程会确定 scope, 所以没必要传
        //但是清空了如何判断客户端访问的资源对应的作用域是否合法？？看check_token希望能的到答案
		if (isAuthCodeRequest(parameters)) {
			// The scope was requested or determined during the authorization step
			if (!tokenRequest.getScope().isEmpty()) {
				logger.debug("Clearing scope of incoming token request");
				tokenRequest.setScope(Collections.<String> emptySet());
			}
		}
		// 如果是刷新 Token 模式, 解析并设置 scope
		if (isRefreshTokenRequest(parameters)) {
			// A refresh token has its own default scopes, so we should ignore any added by the factory here.
			tokenRequest.setScope(OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)));
		}
		//通过令牌授予者获取 Token。
		OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
		if (token == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + tokenRequest.getGrantType());
		}

		return getResponse(token);

	}
```



***

## class - AuthorizationCodeTokenGranter - 授权码模式，令牌授予者

### action - getOAuth2Authentication - 获得Oauth2认证

```java
@Override
protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		//获得请求令牌参数
    Map<String, String> parameters = tokenRequest.getRequestParameters();
	//获得授权码	
    String authorizationCode = parameters.get("code");
    //获得重定向路径
    String redirectUri = parameters.get(OAuth2Utils.REDIRECT_URI);
	//授权码是否为null
    if (authorizationCode == null) {
        throw new InvalidRequestException("An authorization code must be supplied.");
    }
	//销毁授权码
    OAuth2Authentication storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
    if (storedAuth == null) {
        throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
    }
	//获得OAuth2请求信息
    OAuth2Request pendingOAuth2Request = storedAuth.getOAuth2Request();
    // https://jira.springsource.org/browse/SECOAUTH-333
    // 如果授权是在没有使用redirect_uri参数的情况下完成的，则可能是null
    String redirectUriApprovalParameter = pendingOAuth2Request.getRequestParameters().get(
        OAuth2Utils.REDIRECT_URI);
	//匹配回调路径
    if ((redirectUri != null || redirectUriApprovalParameter != null)
        && !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
        throw new RedirectMismatchException("Redirect URI mismatch.");
    }
	//获得客户端id
    String pendingClientId = pendingOAuth2Request.getClientId();
    //获得请求的客户端id
    String clientId = tokenRequest.getClientId();
    if (clientId != null && !clientId.equals(pendingClientId)) {
        // 只是为了检查一下。
        throw new InvalidClientException("Client ID mismatch");
    }

    // 在授权请求中不需要Secret，因此在pendingAuthorizationRequest中不可用。我们确实希望检查令牌请求中是否提供了秘密，但这在其他地方也会发生。

    Map<String, String> combinedParameters = new HashMap<String, String>(pendingOAuth2Request.getRequestParameters());
    // 将最后添加新参数的参数组合在一起，以便在出现任何冲突时覆盖它们
    combinedParameters.putAll(parameters);

    // 使用组合参数创建新的存储请求
    OAuth2Request finalStoredOAuth2Request = pendingOAuth2Request.createOAuth2Request(combinedParameters);

    Authentication userAuth = storedAuth.getUserAuthentication();

    return new OAuth2Authentication(finalStoredOAuth2Request, userAuth);

}
```



***



## class - OAuth2Utils - Oauth2工具类

### action - parseParameterList - 将参数转为集合

```java
public static Set<String> parseParameterList(String values) {
		Set<String> result = new TreeSet<String>();
		if (values != null && values.trim().length() > 0) {
			// the spec says the scope is separated by spaces
			String[] tokens = values.split("[\\s+]");
			result.addAll(Arrays.asList(tokens));
		}
		return result;
}
```



## class - ApprovalStoreUserApprovalHandler - 用户同意授权批准处理实现类

### action - updateAfterApproval

```java
/**
	 *要求显式地批准授权请求(包括所有单独的作用域)和验证用户。授权请求中请求的范围可以通过发送一个请求参数<code>scope. < scopename > </code> = "true"或"approved"(否则将被认为已被拒绝)来获得批准。{@link ApprovalStore}将更新以反映输入。
	 * 
	 * @param authorizationRequest 授权请求。
	 * @param userAuthentication 当前用户身份验证
	 * 
	 * @return 如果当前用户已批准所有作用域，则为已批准的请求。
	 */
public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {
		// Get the approved scopes
		Set<String> requestedScopes = authorizationRequest.getScope();
		Set<String> approvedScopes = new HashSet<String>();
		Set<Approval> approvals = new HashSet<Approval>();

		Date expiry = computeExpiry();

		// 存储已被批准/拒绝的作用域
		Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
    	//轮询这个客户端的作用域
		for (String requestedScope : requestedScopes) {
            // "scope.test"= "scope."+请求的作用域（如："test"）
			String approvalParameter = scopePrefix + requestedScope;
			String value = approvalParameters.get(approvalParameter);
			value = value == null ? "" : value.toLowerCase();
            //是否为true或者时 approve开头
			if ("true".equals(value) || value.startsWith("approve")) {
				approvedScopes.add(requestedScope);
				approvals.add(new Approval(userAuthentication.getName(), authorizationRequest.getClientId(),
						requestedScope, expiry, ApprovalStatus.APPROVED));
			}
			else {
				approvals.add(new Approval(userAuthentication.getName(), authorizationRequest.getClientId(),
						requestedScope, expiry, ApprovalStatus.DENIED));
			}
		}
		approvalStore.addApprovals(approvals);

		boolean approved;
		authorizationRequest.setScope(approvedScopes);
		if (approvedScopes.isEmpty() && !requestedScopes.isEmpty()) {
			approved = false;
		}
		else {
			approved = true;
		}
		authorizationRequest.setApproved(approved);
		return authorizationRequest;
}
```



***



## class - SavedRequestAwareAuthenticationSuccessHandler - 进行登录/授权成功后处理。登录/授权成功后，重定向回之前访问的页面（获取`RequestCache`中存储的地址）

### action - onAuthenticationSuccess - 

```java
@Override
public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws ServletException, IOException {
		SavedRequest savedRequest = requestCache.getRequest(request, response);

		if (savedRequest == null) {
			super.onAuthenticationSuccess(request, response, authentication);

			return;
		}
		String targetUrlParameter = getTargetUrlParameter();
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request
						.getParameter(targetUrlParameter)))) {
			requestCache.removeRequest(request, response);
			super.onAuthenticationSuccess(request, response, authentication);

			return;
		}

		clearAuthenticationAttributes(request);

		// 使用默认跳转路径 - 就是上次session缓存的路径
		String targetUrl = savedRequest.getRedirectUrl();
		logger.debug("Redirecting to DefaultSavedRequest Url: " + targetUrl);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
}
```





## class - RequestCache - 声明了缓存与恢复操作。默认实现类是HttpSessionRequestCache

```java
public interface RequestCache {
 
 // 将request缓存到session中
void saveRequest(HttpServletRequest request, HttpServletResponse response);
 
 // 从session中取request
 SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response);
 
 // 获得与当前request匹配的缓存，并将匹配的request从session中删除
HttpServletRequest getMatchingRequest(HttpServletRequest request,
 HttpServletResponse response);
 
 // 删除缓存的request
 void removeRequest(HttpServletRequest request, HttpServletResponse response);
}
```



***



## class - DefaultRedirectResolver - 重定向类

### action - resolveRedirect - 重定向处理

```java
public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {

		Set<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
    	//客户端必须至少具有一个授权授予类型
		if (authorizedGrantTypes.isEmpty()) {
			throw new InvalidGrantException("A client must have at least one authorized grant type.");
		}
    	//redirect_uri只能由隐式或authorization_code授权类型使用
		if (!containsRedirectGrantType(authorizedGrantTypes)) {
			throw new InvalidGrantException(
					"A redirect_uri can only be used by implicit or authorization_code grant types.");
		}
		Set<String> registeredRedirectUris = client.getRegisteredRedirectUri();
		//必须向客户机注册至少一个redirect_uri
		if (registeredRedirectUris == null || registeredRedirectUris.isEmpty()) {
			throw new InvalidRequestException("At least one redirect_uri must be registered with the client.");
		}
		return obtainMatchingRedirect(registeredRedirectUris, requestedRedirect);
	}
```

### action - obtainMatchingRedirect - 尝试将一个已注册的uri与被请求的uri进行匹配。

```java
private String obtainMatchingRedirect(Set<String> redirectUris, String requestedRedirect) {
		Assert.notEmpty(redirectUris, "Redirect URIs cannot be empty");

		if (redirectUris.size() == 1 && requestedRedirect == null) {
			return redirectUris.iterator().next();
		}
		for (String redirectUri : redirectUris) {
			if (requestedRedirect != null && redirectMatches(requestedRedirect, redirectUri)) {
				return requestedRedirect;
			}
		}
		throw new RedirectMismatchException("Invalid redirect: " + requestedRedirect
				+ " does not match one of the registered values.");
	}
```

***



## class - DefaultOAuth2RequestValidator - 客户端信息验证类

### action - validateScope - 客户端scope验证

```java
public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) throws InvalidScopeException {
    	//这个感觉是因为复用 所以对于获取code时这个参数是相同的
		validateScope(authorizationRequest.getScope(), client.getScope());
	}
```

```
private void validateScope(Set<String> requestScopes, Set<String> clientScopes) {
		
		if (clientScopes != null && !clientScopes.isEmpty()) {
			for (String scope : requestScopes) {
				if (!clientScopes.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
				}
			}
		}
		
		if (requestScopes.isEmpty()) {
			throw new InvalidScopeException("Empty scope (either the client or the user is not allowed the requested scopes)");
		}
	}
```

## class - ApprovalStoreUserApprovalHandler - 用户批准处理程序，通过查阅现有的批准来记住批准决策

### action - isApproved - 查询是否已批准过（就是相当于微信近期授权过就会直接跳过授权点击）

```java
public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		return authorizationRequest.isApproved();
	}
```

```java
public boolean isApproved() {
		return approved;
	}
```

***



## class - DefaultLoginPageGeneratingFilter

***



## class - BasicAuthenticationFilter

### action - doFilterInternal

```java
@Override
protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {
		final boolean debug = this.logger.isDebugEnabled();
		try {
            //是否可以搜索到之前的验证信息 - sessionId
			UsernamePasswordAuthenticationToken authRequest = authenticationConverter.convert(request);
            //如果为null 则此过滤器不做处理
			if (authRequest == null) {
				chain.doFilter(request, response);
				return;
			}

			String username = authRequest.getName();

			if (debug) {
				this.logger
						.debug("Basic Authentication Authorization header found for user '"
								+ username + "'");
			}

			if (authenticationIsRequired(username)) {
				Authentication authResult = this.authenticationManager
						.authenticate(authRequest);

				if (debug) {
					this.logger.debug("Authentication success: " + authResult);
				}

				SecurityContextHolder.getContext().setAuthentication(authResult);

				this.rememberMeServices.loginSuccess(request, response, authResult);

				onSuccessfulAuthentication(request, response, authResult);
			}

		}
		catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				this.logger.debug("Authentication request for failed: " + failed);
			}

			this.rememberMeServices.loginFail(request, response);

			onUnsuccessfulAuthentication(request, response, failed);

			if (this.ignoreFailure) {
				chain.doFilter(request, response);
			}
			else {
				this.authenticationEntryPoint.commence(request, response, failed);
			}

			return;
		}

		chain.doFilter(request, response);
}
```

***



## class - OncePerRequestFilter 

### action - doFilter - 这个{@code doFilter}实现为“already filtered”存储了一个请求属性，如果属性已经存在，则不进行过滤。

```java
@Override
public final void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {

    if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
        throw new ServletException("OncePerRequestFilter just supports HTTP requests");
    }
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
    boolean hasAlreadyFilteredAttribute = request.getAttribute(alreadyFilteredAttributeName) != null;

    if (skipDispatch(httpRequest) || shouldNotFilter(httpRequest)) {

        // 在不调用此过滤器的情况下继续…
        filterChain.doFilter(request, response);
    }
    else if (hasAlreadyFilteredAttribute) {

        if (DispatcherType.ERROR.equals(request.getDispatcherType())) {
            doFilterNestedErrorDispatch(httpRequest, httpResponse, filterChain);
            return;
        }

        // 调用此筛选器…
        filterChain.doFilter(request, response);
    }
    else {
        // Do invoke this filter...
        request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
        try {
            doFilterInternal(httpRequest, httpResponse, filterChain);
        }
        finally {
            // Remove the "already filtered" request attribute for this request.
            request.removeAttribute(alreadyFilteredAttributeName);
        }
    }
}
```

***



## class - WebAsyncManagerIntegrationFilter - 
从WebAsyncManager获取/注册SecurityContextCallableProcessingInterceptor



## class - SecurityContextPersistenceFilter - 请求来临时，创建SecurityContext安全上下文信息，请求结束时清空SecurityContextHolder

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		//确保每个请求只应用一次筛选 标志判断
		if (request.getAttribute(FILTER_APPLIED) != null) {
			// 确保每个请求只应用一次筛选
			chain.doFilter(request, response);
			return;
		}
		
		final boolean debug = logger.isDebugEnabled();
		//确保每个请求只应用一次筛选 标志写入
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

		if (forceEagerSessionCreation) {
			HttpSession session = request.getSession();

			if (debug && session.isNew()) {
				logger.debug("Eagerly created session: " + session.getId());
			}
		}

		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
    	//获取SecurityContext
		SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

		try {
			SecurityContextHolder.setContext(contextBeforeChainExecution);

			chain.doFilter(holder.getRequest(), holder.getResponse());

		}
		finally {
            //结束后清理SecurityContext
			SecurityContext contextAfterChainExecution = SecurityContextHolder
					.getContext();
			// Crucial removal of SecurityContextHolder contents - do this before anything
			// else.
			SecurityContextHolder.clearContext();
			repo.saveContext(contextAfterChainExecution, holder.getRequest(),
					holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);

			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
}
```

***



## class - HeaderWriterFilter - 用来给http响应添加一些Header,比如X-Frame-Options, X-XSS-Protection*，X-Content-Type-Options.

***



## class - LogoutFilter - 退出拦截器，退出的简单操作就是删除Session，根据Spring Security初始化配置的退出地址来匹配请求

### action - doFilter

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		//判断是否为退出请求
		if (requiresLogout(request, response)) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();

			if (logger.isDebugEnabled()) {
				logger.debug("Logging out user '" + auth
						+ "' and transferring to logout destination");
			}

			this.handler.logout(request, response, auth);

			logoutSuccessHandler.onLogoutSuccess(request, response, auth);

			return;
		}

		chain.doFilter(request, response);
}
```

***

## class - UsernamePasswordAuthenticationFilter - 用户名和密码校验Filter/其处理逻辑在父类AbstractAuthenticationProcessingFilter中

### action - doFilter

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);

			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Request is to process authentication");
		}

		Authentication authResult;

		try {
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				// authentication
				return;
			}
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		catch (InternalAuthenticationServiceException failed) {
			logger.error(
					"An internal error occurred while trying to authenticate the user.",
					failed);
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		catch (AuthenticationException failed) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, failed);

			return;
		}

		// Authentication success
		if (continueChainBeforeSuccessfulAuthentication) {
			chain.doFilter(request, response);
		}

		successfulAuthentication(request, response, chain, authResult);
}
```



***



## class - FilterChainProxy - 

### action - doFilter 

```java
@Override
public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (clearContext) {
			try {
				request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
                //通过getFilters(HttpServletRequest)方法，根据request的url来获取对应的Filter。
				doFilterInternal(request, response, chain);
			}
			finally {
				SecurityContextHolder.clearContext();
				request.removeAttribute(FILTER_APPLIED);
			}
		}
		else {
			doFilterInternal(request, response, chain);
		}
}
```

### action - doFilterInternal

```java

private void doFilterInternal(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		FirewalledRequest fwRequest = firewall
				.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse fwResponse = firewall
				.getFirewalledResponse((HttpServletResponse) response);

		List<Filter> filters = getFilters(fwRequest);
		
		if (filters == null || filters.size() == 0) {
			if (logger.isDebugEnabled()) {
				logger.debug(UrlUtils.buildRequestUrl(fwRequest)
						+ (filters == null ? " has no matching filters"
								: " has an empty filter list"));
			}

			fwRequest.reset();

			chain.doFilter(fwRequest, fwResponse);

			return;
		}

		VirtualFilterChain vfc = new VirtualFilterChain(fwRequest, chain, filters);
		vfc.doFilter(fwRequest, fwResponse);
}
```

***



## class - DefaultAccessTokenConverter - token与用户信息转换类

### action -  extractAuthentication

```java
public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
    Map<String, String> parameters = new HashMap<String, String>();
    Set<String> scope = extractScope(map);
    Authentication user = userTokenConverter.extractAuthentication(map);
    String clientId = (String) map.get(clientIdAttribute);
    parameters.put(clientIdAttribute, clientId);
    if (includeGrantType && map.containsKey(GRANT_TYPE)) {
    parameters.put(GRANT_TYPE, (String) map.get(GRANT_TYPE));
    }
    Set<String> resourceIds = new LinkedHashSet<String>(map.containsKey(AUD) ? getAudience(map)
    : Collections.<String>emptySet());

    Collection<? extends GrantedAuthority> authorities = null;
    if (user==null && map.containsKey(AUTHORITIES)) {
    @SuppressWarnings("unchecked")
    String[] roles = ((Collection<String>)map.get(AUTHORITIES)).toArray(new String[0]);
    authorities = AuthorityUtils.createAuthorityList(roles);
    }
    OAuth2Request request = new OAuth2Request(parameters, clientId, authorities, true, scope, resourceIds, null, null,
    null);
    return new OAuth2Authentication(request, user);
}
```



***



## class - RemoteTokenServices - 资源服务器向认证服务器check_token

### action - postForMap - 发送验证请求

```java
private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
    if (headers.getContentType() == null) {
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }
    @SuppressWarnings("rawtypes")
    Map map = restTemplate.exchange(path, HttpMethod.POST,
                                    new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
    @SuppressWarnings("unchecked")
    Map<String, Object> result = map;
    return result;
}
```

***

## class - DefaultHttpFirewall

### action - getFirewalledResponse

```java
@Override
public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		FirewalledRequest fwr = new RequestWrapper(request);

		if (!isNormalized(fwr.getServletPath()) || !isNormalized(fwr.getPathInfo())) {
			throw new RequestRejectedException("Un-normalized paths are not supported: " + fwr.getServletPath()
					+ (fwr.getPathInfo() != null ? fwr.getPathInfo() : ""));
		}

		String requestURI = fwr.getRequestURI();
		if (containsInvalidUrlEncodedSlash(requestURI)) {
			throw new RequestRejectedException("The requestURI cannot contain encoded slash. Got " + requestURI);
		}

		return fwr;
}
```

------

## class - DefaultTokenServices -  授权相关信息工具类

## action - loadAuthentication - 加载oauth token 授权相关信息

```java
public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException,
			InvalidTokenException {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (accessToken.isExpired()) {
			tokenStore.removeAccessToken(accessToken);
			throw new InvalidTokenException("Access token expired: " + accessTokenValue);
		}
		//读取token授权信息
		OAuth2Authentication result = tokenStore.readAuthentication(accessToken);
		if (result == null) {
			// in case of race condition
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
        //客户端信息不为null
		if (clientDetailsService != null) {
            //获得请求的客户端id
			String clientId = result.getOAuth2Request().getClientId();
			try {
                //加载数据库客户端信息
				clientDetailsService.loadClientByClientId(clientId);
			}
			catch (ClientRegistrationException e) {
				throw new InvalidTokenException("Client not valid: " + clientId, e);
			}
		}
		return result;
}
```

***

## class - CheckTokenEndpoint - 验证token端点

### action - checkToken - 验证token处理

```
@RequestMapping(value = "/oauth/check_token")
	@ResponseBody
	public Map<String, ?> checkToken(@RequestParam("token") String value) {
		//读取token信息转为oauth认证对象
		OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
		if (token == null) {
			throw new InvalidTokenException("Token was not recognised");
		}

		if (token.isExpired()) {
			throw new InvalidTokenException("Token has expired");
		}
		//读取token信息转为oauth认证对象
		OAuth2Authentication authentication = resourceServerTokenServices.loadAuthentication(token.getValue());

		Map<String, Object> response = (Map<String, Object>)accessTokenConverter.convertAccessToken(token, authentication);

		// 如果令牌存在且未过期，则始终为真
		response.put("active", true);	// Always true if token exists and not expired

		return response;
	}
```

