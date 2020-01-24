package com.rhy;

import com.rhy.entity.User;
import com.rhy.event.UserRegisterEvent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;

@SpringBootApplication
@EnableResourceServer
@RestController
public class ResourceServerApplication {
    private static final Logger log = LoggerFactory.getLogger(ResourceServerApplication.class);
    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApplication.class, args);
    }
    @GetMapping("/user")
    public Authentication getUser(Authentication authentication, HttpServletRequest request) throws IOException, CertificateException {
        String s = authentication.getPrincipal().toString();
        String name = authentication.getName();
        String header = request.getHeader("Authorization");
        String token = header.split(" ")[1];
        //获得公钥文件
        ClassPathResource classPathResource = new ClassPathResource("public.txt");
        //读取文件
        BufferedInputStream bufferedInputStream = new BufferedInputStream(classPathResource.getInputStream());
        byte[] bytes = new byte[1024];
        int len;
        StringBuilder stringBuilder = new StringBuilder();
        while((len = bufferedInputStream.read(bytes)) != -1){
            stringBuilder.append(new String(bytes,0,len,"UTF8"));
        }
        //这里还有后续解码步骤  可以断点看里面值
        Jwt jwt = JwtHelper.decode(token);
        System.out.println(stringBuilder.toString());
        log.info("resource: user {}", authentication);
        //异步执行监听事件
        applicationEventPublisher.publishEvent(new UserRegisterEvent(new User()));
        return authentication;
    }
}
