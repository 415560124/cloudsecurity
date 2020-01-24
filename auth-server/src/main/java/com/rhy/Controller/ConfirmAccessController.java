package com.rhy.Controller;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2020/1/12 16:51
 * @Modified By:
 * @Version: 1.0.0
 */
@Controller
@SessionAttributes("authorizationRequest")
public class ConfirmAccessController {

    @RequestMapping(value = "/oauth/confirm_access",method = RequestMethod.GET)
    public ModelAndView getAccessConfirmation(Map<String,Object> model, HttpServletRequest request){
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
        ModelAndView view = new ModelAndView();
        System.out.println("-------------------authorizationRequest-------------------");
        System.out.println(JSON.toJSONString(authorizationRequest));
        System.out.println("-------------------authorizationRequestEnd-------------------");
        view.setViewName("confirm_access");
        view.addObject("clientId",authorizationRequest.getClientId());
        return view;
    }
}
