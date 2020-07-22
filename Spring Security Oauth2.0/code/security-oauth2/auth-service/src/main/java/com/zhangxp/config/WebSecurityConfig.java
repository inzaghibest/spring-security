package com.zhangxp.config;

import com.zhangxp.service.SpringUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 认证管理器
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 安全拦截机制配置
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        // 关闭csrf安全控制,否则我们将访问不到我们自定义的登录页面
        httpSecurity.csrf().disable();
        httpSecurity.authorizeRequests()
        // .antMatchers("/service-hi/r1").hasAnyAuthority("p1")
                // 对认证请求放行
                .antMatchers("/login**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin();
    }
}