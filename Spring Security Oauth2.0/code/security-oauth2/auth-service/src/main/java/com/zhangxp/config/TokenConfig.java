package com.zhangxp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class TokenConfig {
    // 生成jwt令牌的密钥,被保护的资源校验jwt令牌,需要采用相同的秘钥
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
}
