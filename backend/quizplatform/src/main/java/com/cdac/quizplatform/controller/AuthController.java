package com.cdac.quizplatform.controller;

import com.cdac.quizplatform.dto.LoginRequest;
import com.cdac.quizplatform.dto.RegistrationRequest;
import jakarta.validation.Valid;
import com.cdac.quizplatform.model.Role;
import com.cdac.quizplatform.model.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.cdac.quizplatform.repository.RoleRepository;
import com.cdac.quizplatform.repository.UserRepository;
import com.cdac.quizplatform.util.JwtUtils;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthController(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtils jwtUtils){
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest){
        if(userRepository.findByUsername(registrationRequest.getUsername()).isPresent()){
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        if(userRepository.findByEmail(registrationRequest.getEmail()).isPresent()){
            return ResponseEntity.badRequest().body("Error: Email is already used!");
        }

        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setEmail(registrationRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));

        Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow(()-> new RuntimeException("Error: Role not found."));
        user.setRoles(Collections.singleton(userRole));

        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully.");
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        Authentication authentication = null;
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
        } catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentails");
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(loginRequest.getUsername());

        return ResponseEntity.ok(jwt);
    }
}
