package com.rhy.config;

import com.rhy.security.JwtUserImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.*;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/14 23:29
 * @Modified By:
 * @Version: 1.0.0
 */
@Configuration
public class JwtConfig{ // extends DefaultUserAuthenticationConverter
    public JwtConfig() {
        super();
    }

//    /**
//     * 自定义实现 token的转换
//     * @param userAuthentication
//     * @return
//     */
//    @Override
//    public Map<String, ?> convertUserAuthentication(Authentication userAuthentication) {
//        Map<String, Object> response = new LinkedHashMap<String, Object>();
//        JwtUserImpl jwtUser = (JwtUserImpl) userAuthentication.getPrincipal();
//        response.put("id",jwtUser.getId());
//        response.put("user_name",jwtUser.getUsername());
//        if (userAuthentication.getAuthorities() != null && !userAuthentication.getAuthorities().isEmpty()) {
//            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(userAuthentication.getAuthorities()));
//        }
//        return response;
//    }


    /**
     * 自定义添加token信息（生成token时）
     * @return
     */
//    @Bean
//    public TokenEnhancer tokenEnhancer(){
//        return (OAuth2AccessToken accessToken, OAuth2Authentication authentication)->{
//            //新添加的令牌信息
//            Map<String, Object> additionalInfo = new HashMap<>();
//            //获得用户信息
//            JwtUserImpl jwtUser = (JwtUserImpl) authentication.getUserAuthentication().getPrincipal();
//            additionalInfo.put("user_name",jwtUser.getUsername());
//            additionalInfo.put("id",jwtUser.getId());
//            return accessToken;
//        };
//    }
    /**
     * 对Jwt签名时，增加一个密钥
     * JwtAccessTokenConverter：对Jwt来进行编码以及解码的类
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        //对称加密只需要传入 signingKey
//        jwtAccessTokenConverter.setSigningKey("test-secret");
        //非对称加密导入证书
        //ClassPathResource加载资源文件                                                                       密匙密码
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("mytest.jks"),"mypass".toCharArray());
        //密匙别名
        jwtAccessTokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));
        return jwtAccessTokenConverter;
    }
    /**
     * 设置token 由Jwt产生，不使用默认的透明令牌
     */
    @Bean
    public JwtTokenStore jwtTokenStore(){
        return new JwtTokenStore(jwtAccessTokenConverter());
    }


}
