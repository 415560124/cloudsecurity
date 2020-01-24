package com.rhy.event;

import com.rhy.entity.User;
import org.springframework.context.ApplicationEvent;
import org.springframework.stereotype.Component;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/14 21:20
 * @Modified By:
 * @Version: 1.0.0
 */
@Component
public class UserRegisterEvent extends ApplicationEvent {
    /**
     * Create a new {@code ApplicationEvent}.
     *
     * @param source the object on which the event initially occurred or with
     *               which the event is associated (never {@code null})
     */
    public UserRegisterEvent(User source) {
        super(source);
    }

}
