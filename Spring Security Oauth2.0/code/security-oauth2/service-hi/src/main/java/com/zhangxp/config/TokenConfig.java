package com.zhangxp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class TokenConfig {
    // 生成jwt令牌的密钥
    private String STRING_KEY = "auth-123";

    @Bean
    public TokenStore tokenStore()
    {
        // JWT令牌存储方式
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter()
    {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey(STRING_KEY);
        return jwtAccessTokenConverter;
    }
    // 令牌的存储方式
//    @Bean
//    public TokenStore tokenStore() {
//        // 内存方式,生成普通令牌
//        return new InMemoryTokenStore();
//    }
}
