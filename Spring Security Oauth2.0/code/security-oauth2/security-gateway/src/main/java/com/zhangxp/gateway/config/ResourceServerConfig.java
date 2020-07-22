package com.zhangxp.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
public class ResourceServerConfig {
    public static final String RESOURCE_ID = "res1";

    // auth-service资源配置
    @Configuration
    @EnableResourceServer
    public class authResourceServerConfig extends ResourceServerConfigurerAdapter {

        @Autowired
        private  TokenStore tokenStore;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) {
            resources.tokenStore(tokenStore).resourceId(RESOURCE_ID)
                    .stateless(true);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers("/auth-service/**").permitAll(); // 对认证请求放行
        }
    }

    // order资源配置
    @Configuration
    @EnableResourceServer
    public class ServiceHiServerConfig extends ResourceServerConfigurerAdapter {

        @Autowired
        private  TokenStore tokenStore;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources){
            resources.resourceId(RESOURCE_ID)
                    .tokenStore(tokenStore)
                    .stateless(true);
        }

        @Override
        public void configure(HttpSecurity httpSecurity) throws Exception {
            httpSecurity.authorizeRequests()
                    .antMatchers("/service-hi/**").access("#oauth2.hasScope('ROLE_ADMIN')")
                    .and().csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }
    }
}
