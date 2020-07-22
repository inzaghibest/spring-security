package com.zhangxp.controller;

import com.zhangxp.model.UserDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceHi {
    @GetMapping(value = "/r1")
    @PreAuthorize("hasAnyAuthority('p1')") // 标记拥有p1权限,方可访问此url
    public String r1()
    {
        UserDto userDto =  (UserDto) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userDto.getUsername() +  "hi,你好啊!";
//        return "hi,你好啊!";
    }

    @GetMapping(value = "/r2")
    @PreAuthorize("hasAnyAuthority('p2')") // 标记拥有p1权限,方可访问此url
    public String r2()
    {
        return "hi,你好啊!";
    }
}
