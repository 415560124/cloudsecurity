package com.rhy.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.rhy.entity.MenuFunction;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2019/12/29 16:03
 * @Modified By:
 * @Version: 1.0.0
 */
@Mapper
@Component
public interface IMenuFunctionMapper extends BaseMapper<MenuFunction> {
    List<MenuFunction> selectByMenuFunction(MenuFunction menuFunction);
}
