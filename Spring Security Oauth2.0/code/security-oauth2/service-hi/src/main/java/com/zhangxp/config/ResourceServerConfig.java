package com.zhangxp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer    // 标记这是一个资源服务
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    // 与认证服务中标识的资源匹配,从而标识这个是res1,是要被保护的这个资源
    public static final String RESOURCE_ID = "res1";

    // 注入
    @Autowired
    TokenStore tokenStore;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(RESOURCE_ID)
//                .tokenServices(tokenServices())
                .tokenStore(tokenStore) // 自己来验证token,不通过认证服务/oauth/check_token来验证
                .stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/service-hi/**").access("#oauth2.hasScope('ROLE_ADMIN')") // 校验是否与认证中的授权范围一致
                .and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 不用记录session,因为我们是基于token的方式。
    }

    // 资源服务令牌解析服务
    // 向认证授权服务器验证token
//    @Bean
//    public ResourceServerTokenServices tokenServices() {
//        RemoteTokenServices services = new RemoteTokenServices();
//        services.setCheckTokenEndpointUrl("http://localhost:5000/auth-service/oauth/check_token");
//        services.setClientId("c1");
//        services.setClientSecret("123");
//        return services;
//    }
}
