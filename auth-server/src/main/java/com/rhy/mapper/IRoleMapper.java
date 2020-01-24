package com.rhy.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.rhy.entity.Role;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Component;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2019/12/28 17:08
 * @Modified By:
 * @Version: 1.0.0
 */
@Mapper
@Component
public interface IRoleMapper extends BaseMapper<Role> {
    Role selectById(Role role);
}
