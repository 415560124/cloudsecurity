package com.rhy.config;

import com.rhy.security.JwtUserImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.*;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/11 17:19
 * @Modified By:
 * @Version: 1.0.0
 */
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Qualifier("dataSource")
    @Autowired
    private DataSource dataSource;
    /**
     * 用户信息实现类
     */
    @Qualifier("userDetailServiceImpl")
    @Autowired
    private UserDetailsService userDetailsService;
    /**
     * jwt编码解码配置
     */
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    /**
     * jwtToken操作类
     */
    @Autowired
    private JwtTokenStore jwtTokenStore;
    /**
     * Token增强器（增加自定义信息）
     */
    @Autowired
    private TokenEnhancer jwtTokenEnhancer;
    /**
     * 密码编码器实现类
     */
    @Qualifier("passwordEncoderImpl")
    @Autowired
    private PasswordEncoder passwordEncoder;
    /**
     * 配置客户端详细服务
     * 客户端详细信息在这里进行初始化，能够把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息
     * @param clients
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientDetailsService());
//        clients.jdbc(dataSource)
    }

    /**
     * 用来配置令牌端点(Token Endpoint)的安全约束.
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //配置token获取和验证时的策略
        security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()").allowFormAuthenticationForClients();
    }
    /**
     * 用来配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                //引用jdbc token
//                .tokenStore(jdbcTokenStore())
                //引用jwt-token
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
                //引用jdbc code
//                .authorizationCodeServices(jdbcAuthorizationCodeServices())
                .userDetailsService(userDetailsService);
        //修改授权页路径
        endpoints.pathMapping("/oauth/confirm_access","/oauth/confirm_access");
        //自定义token生成方式 ， 把自定义TokenEnhancer加入到TokenEnhancer链中
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtTokenEnhancer,jwtAccessTokenConverter));
        endpoints.tokenEnhancer(tokenEnhancerChain);
    }

    //使用jdbcToken
//    @Bean
//    public JdbcTokenStore jdbcTokenStore(){
//        return new JdbcTokenStore(dataSource);
//    }

    //使用jdbcClient
    @Bean
    public JdbcClientDetailsService jdbcClientDetailsService(){
        return new JdbcClientDetailsService(dataSource);
    }
    @Bean
    public JdbcAuthorizationCodeServices jdbcAuthorizationCodeServices(){
        return new JdbcAuthorizationCodeServices(dataSource);
    }


}
