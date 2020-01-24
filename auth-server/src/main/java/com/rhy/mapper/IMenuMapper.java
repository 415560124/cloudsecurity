package com.rhy.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.rhy.entity.Menu;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Component;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2019/12/29 16:03
 * @Modified By:
 * @Version: 1.0.0
 */
@Mapper
@Component
public interface IMenuMapper extends BaseMapper<Menu> {
    Menu selectById(int id);
}
