package com.system.abcrestaurant.controller;

import com.system.abcrestaurant.config.JwtProvider;
import com.system.abcrestaurant.model.USER_ROLE;
import com.system.abcrestaurant.model.User;
import com.system.abcrestaurant.repository.UserRepository;
import com.system.abcrestaurant.request.LoginRequest;
import com.system.abcrestaurant.response.AuthResponse;
import com.system.abcrestaurant.service.CustomerUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private CustomerUserDetailsService customerUserDetailsService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody User user) {
        AuthResponse authResponse = new AuthResponse();

        try {
            // Checking if the username is already used
            if (userRepository.findByUsername(user.getUsername()) != null) {
                authResponse.setMessage("Username is already in use");
                return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
            }

            // Validate required fields
            if (user.getUsername() == null || user.getPassword() == null || user.getRole() == null || user.getEmail() == null) {
                authResponse.setMessage("Fields cannot be empty");
                return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
            }

            // Create a new User
            User createdUser = new User();
            createdUser.setEmail(user.getEmail());
            createdUser.setUsername(user.getUsername());
            createdUser.setRole(user.getRole());
            createdUser.setPassword(passwordEncoder.encode(user.getPassword()));

            User savedUser = userRepository.save(createdUser);

            Authentication authentication = new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtProvider.generateToken(authentication);

            authResponse.setJwt(jwt);
            authResponse.setMessage("Account Created successfully");
            authResponse.setRole(savedUser.getRole());

            return new ResponseEntity<>(authResponse, HttpStatus.CREATED);

        } catch (Exception e) {
            authResponse.setMessage("Error occurred during registration");
            return new ResponseEntity<>(authResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest req) {
        AuthResponse authResponse = new AuthResponse();

        try {
            String username = req.getUsername();
            String password = req.getPassword();

            // Validate required fields
            if (username == null || password == null) {
                authResponse.setMessage("Username and password are required");
                return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
            }

            // Authenticate the user
            Authentication authentication = authenticate(username, password);

            // Retrieve the role of the authenticated user
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            String role = authorities.isEmpty() ? null : authorities.iterator().next().getAuthority();

            // Generate a JWT for the authenticated user
            String jwt = jwtProvider.generateToken(authentication);

            authResponse.setJwt(jwt);
            authResponse.setMessage("Login successful");
            authResponse.setRole(USER_ROLE.valueOf(role));

            return new ResponseEntity<>(authResponse, HttpStatus.OK);

        } catch (BadCredentialsException e) {
            authResponse.setMessage("Invalid username or password");
            return new ResponseEntity<>(authResponse, HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            authResponse.setMessage("Invalid username or password");
            return new ResponseEntity<>(authResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Helper method to authenticate a user
    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = customerUserDetailsService.loadUserByUsername(username);

        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}