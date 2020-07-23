package com.zhangxp.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        UserDetails userDetails = User.withUsername("zhangsan").
                password("$2a$10$R.kUP2WSdzWQL3qzo6pF/uzpqPsvp/q1HF0fm9KZR/O8KwJgHe5Fm").
                authorities("p1").build();
        return userDetails;
    }
}
