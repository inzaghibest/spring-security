package com.zhangxp.config;


import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置用户信息,包括用户姓名，密码，权限等信息
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService()
    {
        // 基于内存的方式
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zhangxp").password("123").authorities("p1").build());
        manager.createUser(User.withUsername("zhangxa").password("123").authorities("p2").build());
        return manager;
    }

    /**
     * 密码编码器，采用何种方式校验密码
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     *  安全拦截机制
     * @param httpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception
    {
        httpSecurity.authorizeRequests()
                .antMatchers("/r/r1").hasAnyAuthority("p1")
                .antMatchers("/r/r2").hasAnyAuthority("p2")
                .antMatchers("/hi/**").authenticated() // /hi/**请求必须认证通过
                .anyRequest().permitAll()// 其他所有请求放行
                .and()
                .formLogin()// 允许表单登录
                .successForwardUrl("/login-success"); // 登录成功后跳转的地址

    }
}
