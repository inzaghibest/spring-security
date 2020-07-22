package com.zhangxp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtAccessTokenConverter accessTokenConverter;
    @Autowired
    PasswordEncoder passwordEncoder;



    // 令牌访问端点的安全策略,即令牌访问端点允许用户的访问策略
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")  // /oauth/token_key这个url是公开的,jwt令牌时公钥访问端点
                .checkTokenAccess("permitAll()") // /oauth/check_token  校验令牌的请求放行
                .allowFormAuthenticationForClients(); // 允许进行表单验证
    }

    /**
     * 采用读数据库的方式获取客户端信息
     * */
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource)
    {
        ClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        ((JdbcClientDetailsService)clientDetailsService).setPasswordEncoder(passwordEncoder);
        return clientDetailsService;
    }

    // 配置客户端详情信息,用来指定哪些客户端可以访问授权认证服务。
    // 客户端信息可以配置到内存中，也可以存到数据库中。
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
//        clients.inMemory() // 使用in-memory方式存储
//                .withClient("c1") // 客户端id
//                .secret(new BCryptPasswordEncoder().encode("123")) // 客户端秘钥
//                .resourceIds("res1") // 资源列表
//                .authorizedGrantTypes("authorization_code", "password", "client_credentials",
//                        "implicit", "refresh_token") // oauth2.0支持的认证类型
//                .scopes("all") // 授权的范围 只读等
//                .autoApprove(false) // 授权码模式时跳转到授权页面,true直接发令牌,不跳转
//                .redirectUris("http://www.baidu.com");
    }

    // 令牌访问端点
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 密码模式需要
        endpoints.authenticationManager(authenticationManager)
                // 授权码模式需要
                .authorizationCodeServices(authorizationCodeServices)
                // 令牌管理服务
                .tokenServices(tokenServices())
                // 允许post提交
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    // 令牌管理模式
    @Bean
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        // 客户端信息服务
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        // 是否产生刷新令牌
        defaultTokenServices.setSupportRefreshToken(true);
        // 令牌存储策略
        defaultTokenServices.setTokenStore(tokenStore);

        // 设置令牌增强
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain);

        defaultTokenServices.setAccessTokenValiditySeconds(7200);
        defaultTokenServices.setRefreshTokenValiditySeconds(259200);
        return defaultTokenServices;
    }

    // 授权码服务
//    @Bean
//    public AuthorizationCodeServices authorizationCodeServices() {
//        return new InMemoryAuthorizationCodeServices();
//    }

    // 授权码模式需要,授权码也采用数据库的方式
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) {
        return new JdbcAuthorizationCodeServices(dataSource);
    }
}
