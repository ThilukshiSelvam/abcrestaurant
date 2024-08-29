package com.system.abcrestaurant.service;

import com.system.abcrestaurant.model.User;

public interface UserService {

    public User findUserByJwtToken(String jwt) throws Exception;

    public User findUserByUsername(String username) throws Exception;
}

