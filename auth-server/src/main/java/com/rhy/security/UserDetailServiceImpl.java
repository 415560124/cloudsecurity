package com.rhy.security;

import com.rhy.entity.User;
import com.rhy.entity.UserRole;
import com.rhy.mapper.IRoleMapper;
import com.rhy.mapper.IUserMapper;
import com.rhy.mapper.IUserRoleMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Auther: Herion_Rhy
 * @Description: 用户信息实现类
 * @Date: Created in 2019/12/28 16:52
 * @Modified By:
 * @Version: 1.0.0
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    IUserMapper iUserMapper;
    @Autowired
    IRoleMapper iRoleMapper;
    @Autowired
    IUserRoleMapper iUserRoleMapper;
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        //搜索数据库用户信息
        User user = iUserMapper.selectByUserName(userName);
        //搜索权限信息
        if(user == null){
            throw new UsernameNotFoundException("UserName not found");
        }
        return this.changeToUserDetail(user);
    }

    private UserDetails changeToUserDetail(User user){
        //权限列表
        List<GrantedAuthority> authorities = new ArrayList<>();
        //赋予查询到的角色
        for(UserRole userRole : user.getUserRoles()){
            GrantedAuthority authority = new SimpleGrantedAuthority(userRole.getRole().getRoleName());
            authorities.add(authority);
        }
        //创建UserDetails对象，设置用户名、密码、权限
        UserDetails userDetails = new JwtUserImpl(user.getUserName(),user.getPwd(),user.getId(),authorities);
        return userDetails;

    }
}
