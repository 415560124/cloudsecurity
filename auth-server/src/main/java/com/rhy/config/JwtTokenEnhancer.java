package com.rhy.config;

import com.rhy.security.JwtUserImpl;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * @Auther: Herion_Rhy
 * @Description: jwt token 自定义转换类
 * @Date: Created in 2020/1/19 21:49
 * @Modified By:
 * @Version: 1.0.0
 */
@Component
public class JwtTokenEnhancer implements TokenEnhancer {
    /**
     * 令牌加密
     * @param accessToken
     * @param authentication
     * @return
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        //新添加的令牌信息
        Map<String, Object> additionalInfo = new HashMap<>();
        //获得用户信息
        JwtUserImpl jwtUser = (JwtUserImpl) authentication.getUserAuthentication().getPrincipal();
        additionalInfo.put("id",jwtUser.getId());
        ((DefaultOAuth2AccessToken)accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}
