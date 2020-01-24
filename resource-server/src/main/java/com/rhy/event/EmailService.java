package com.rhy.event;

import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/14 21:30
 * @Modified By:
 * @Version: 1.0.0
 */
@Service
public class EmailService implements ApplicationListener<UserRegisterEvent> {
    @Override
    public void onApplicationEvent(UserRegisterEvent event) {
        System.out.println(event.getSource().toString());
    }
}
