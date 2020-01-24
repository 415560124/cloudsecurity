package com.rhy.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/12 14:37
 * @Modified By:
 * @Version: 1.0.0
 */
@Controller
public class LoginController {
    @GetMapping("/login")
    public String loginPage(Model model){
        return "login";
    }
}
