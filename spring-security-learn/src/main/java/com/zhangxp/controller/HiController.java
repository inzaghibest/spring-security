package com.zhangxp.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HiController {
    @RequestMapping("/hi")
    public String Hello()
    {
        return "Hello Spring Security!";
    }

    /**
     * 测试资源r1
     * @return
     */
    @RequestMapping("/r/r1")
    public String r1()
    {
        return "访问资源r1";
    }

    /**
     * 测试资源r2
     * @return
     */
    @RequestMapping("/r/r2")
    public String r2()
    {
        return "访问资源r2";
    }

    /**
     * 登录成功跳转页面
     * @return
     */
    @RequestMapping("/login-success")
    public String success()
    {
        return "登录成功!";
    }

    @RequestMapping("/logout")
    public String logout()
    {
        return "退出登录!";
    }
}
