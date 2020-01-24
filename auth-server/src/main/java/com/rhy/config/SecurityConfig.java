package com.rhy.config;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/11 17:29
 * @Modified By:
 * @Version: 1.0.0
 */

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 配置spring security
 *
 * @author simon
 * @create 2018-10-29 16:25
 **/
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置这个bean会在做AuthorizationServerConfigurer配置的时候使用
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    @Value("${system.user.password.secret}")
    private String secret = null;
    /**
     * 用户信息实现类
     */
    @Qualifier("userDetailServiceImpl")
    @Autowired
    private UserDetailsService userDetailsService;
    /**
     * 密码编码器实现类
     */
    @Qualifier("passwordEncoderImpl")
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 自己注入provider
     * 否则无法抛出UserNameNotFound异常
     */
    @Bean
    public DaoAuthenticationProvider iniDaoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setHideUserNotFoundExceptions(false);
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }
    /**
     * 用户验证配置
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(iniDaoAuthenticationProvider());
    }
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/oauth/check_token");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/static/**").permitAll().anyRequest().authenticated()
                //允许所有身份访问    loginPage：登录页url  loginProcessingUrl：登录处理url
                .and().formLogin().loginPage("/login").loginProcessingUrl("/login").permitAll();

    }
}
