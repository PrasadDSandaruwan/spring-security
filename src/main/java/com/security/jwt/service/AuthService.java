package com.security.jwt.service;


import com.security.jwt.config.JWTTokenProvider;
import com.security.jwt.model.Role;
import com.security.jwt.model.User;
import com.security.jwt.repository.UserRepository;
import com.security.jwt.request.AuthenticationRequest;
import com.security.jwt.request.RefreshTokenRequest;
import com.security.jwt.request.RegisterRequest;
import com.security.jwt.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JWTTokenProvider jwtProvider;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        Role role;
        if (registerRequest.getRole().equalsIgnoreCase(Role.ADMIN.name()))
            role = Role.ADMIN;
        else
            role = Role.USER;

        User user = User
                .builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(role)
                .build();
        userRepository.save(user);

        String token = jwtProvider.generateToken(user);


        return AuthenticationResponse
                .builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
            authenticationManager.authenticate( new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getEmail(),
                    authenticationRequest.getPassword()
            ));

            User user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
            String token = jwtProvider.generateToken(user);

            return AuthenticationResponse
                    .builder()
                    .token(token)
                    .build();

    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        return null;
    }
}
