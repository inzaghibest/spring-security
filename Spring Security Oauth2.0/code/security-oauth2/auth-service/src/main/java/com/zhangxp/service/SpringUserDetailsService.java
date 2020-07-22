package com.zhangxp.service;

import com.zhangxp.entity.MyUser;
import com.zhangxp.mapper.MyUserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Created by Administrator on 2020/6/25 0025.
 */
@Service
public class SpringUserDetailsService implements UserDetailsService {
    @Autowired
    private MyUserMapper myUserMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MyUser myUserDTO = new MyUser();
        myUserDTO.setUsername(username);
        MyUser myUser =  myUserMapper.selectOne(myUserDTO);
        if (myUser == null)
        {
            return null;
        }
        UserDetails userDetails = User.withUsername(myUser.getUsername()).password(myUser.getPassword()).authorities(myUser.getAuthorites()).build();
        return userDetails;
    }
}
