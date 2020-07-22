package com.zhangxp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import tk.mybatis.spring.annotation.MapperScan;

@SpringBootApplication
@MapperScan("com.zhangxp.mapper")
@EnableEurekaClient
public class AuthService {
    public static void main(String[] args)
    {
        SpringApplication.run(AuthService.class, args);
    }
}
