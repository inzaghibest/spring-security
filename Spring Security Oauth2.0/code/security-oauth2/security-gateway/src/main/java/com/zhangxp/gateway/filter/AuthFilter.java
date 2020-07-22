package com.zhangxp.gateway.filter;

import com.alibaba.fastjson.JSON;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthFilter extends ZuulFilter {
    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext ctx = RequestContext.getCurrentContext();
        // 从安全上下文拿到用户身份对象
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("----------1----------" + authentication.toString());
        if (!(authentication instanceof OAuth2Authentication)) // 如果不是OAuth2Authentication格式,就不进行解析
        {
            return null;
        }
        System.out.println("----------2----------");
        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
        Authentication userAuthentication = oAuth2Authentication.getUserAuthentication();
        // 取出用户身份信息
        String principal = userAuthentication.getName();
        // 获取当前用户的权限信息
        List<String> authorities = new ArrayList<String>();
        userAuthentication.getAuthorities().stream().forEach(c->authorities.add(((GrantedAuthority) c).getAuthority()));
        // 取出其他信息
        OAuth2Request oAuth2Request = oAuth2Authentication.getOAuth2Request();
        Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
        Map<String, Object> jsonToken = new HashMap<>(requestParameters);
        // 把身份信息和权限信息放在json中,加入http header中
        if (userAuthentication != null)
        {
            jsonToken.put("principal", principal);
            jsonToken.put("authorities", authorities);
        }
        System.out.println("----------11----------");
        // 转发给微服务
        ctx.addZuulRequestHeader("jsonToken", JSON.toJSONString(jsonToken));
        return null;
    }
}
