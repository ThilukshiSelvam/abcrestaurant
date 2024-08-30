package com.system.abcrestaurant.service;

import com.system.abcrestaurant.config.JwtProvider;
import com.system.abcrestaurant.model.USER_ROLE;
import com.system.abcrestaurant.model.User;
import com.system.abcrestaurant.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImp implements UserService{

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtProvider jwtProvider;

    @Override
    public User findUserByJwtToken(String jwt) throws Exception {
        String username = jwtProvider.getUsernameFromJwtToken(jwt);
        if ("admin".equals(username)) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setPassword(new BCryptPasswordEncoder().encode("123"));
            adminUser.setRole(USER_ROLE.ROLE_ADMIN);
            return adminUser;
        }
        User user=findUserByUsername(username);
        return user;
    }

    @Override
    public User findUserByUsername(String username) throws Exception {
        User user=userRepository.findByUsername(username);

        if(user==null){
            throw new Exception("user not found");
        }
        return user;
    }
}