package com.rhy.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;

/**
 * @Auther: Herion_Rhy
 * @Description: 自定义用户信息实现类
 * @Date: Created in 2020/1/1 12:32
 * @Modified By:
 * @Version: 1.0.0
 */
public class JwtUserImpl implements UserDetails, Serializable {
    private static final long serialVersionUID = 1L;
    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;
    /**
     * 用户id
     */
    private Long id;
    /**
     * 权限列表
     */
    private Collection<? extends GrantedAuthority> authorities;

    public JwtUserImpl() {
    }

    public JwtUserImpl(String username, String password, Long id, Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.id = id;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    /**
     * 账号是否未过期
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 账号是否未被锁
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 凭证是否不过期
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 账号是否激活
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "JwtUserImpl{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", id='" + id + '\'' +
                ", authorities=" + authorities +
                '}';
    }
}
