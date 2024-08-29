package com.system.abcrestaurant.repository;

import com.system.abcrestaurant.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {

    public User findByUsername(String Username);

}

