package com.zhangxp.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.zhangxp.model.UserDto;
import org.codehaus.jackson.JsonToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("---------TokenAuthenticationFilter------------");
        // 解析出头当中的token
        String token = httpServletRequest.getHeader("jsonToken");
        if (token != null)
        {
            System.out.println("token:-------------" + token);
            // 将token转换为json对象
            JSONObject jsonObject = JSON.parseObject(token);
            // 用户身份信息
            String principal = jsonObject.getString("principal");
            UserDto userDto = new UserDto();
            userDto.setUsername(principal);
            // 用户权限
            JSONArray jsonArray =  jsonObject.getJSONArray("authorities");
            String[] strings = jsonArray.toArray(new String[jsonArray.size()]);

            // 将用户身份信息和权限填充到security
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userDto, null,
                            AuthorityUtils.createAuthorityList(strings));
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
            // 将对象填充到spring security上下文中
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
