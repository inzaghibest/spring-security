package com.zhangxp.entity;

import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Table(name = "myuser")
public class MyUser {
    @GeneratedValue(generator = "JDBC")
    @Id
    private Integer id;

    private String password;

    private String username;

    private String fullname;

    private String mobile;

    private String authorites;
    /**
     * @return id
     */
    public Integer getId() {
        return id;
    }

    /**
     * @param id
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * @return password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * @return username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @param username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return fullname
     */
    public String getFullname() {
        return fullname;
    }

    /**
     * @param fullname
     */
    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    /**
     * @return mobile
     */
    public String getMobile() {
        return mobile;
    }

    /**
     * @param mobile
     */
    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    /**
     * @return authorites
     */
    public String getAuthorites() {
        return authorites;
    }

    /**
     * @param authorites
     */
    public void setAuthorites(String authorites) {
        this.authorites = authorites;
    }

    @Override
    public String toString() {
        return "用户信息: username = " + this.username + " password = " + this.password;
    }
}