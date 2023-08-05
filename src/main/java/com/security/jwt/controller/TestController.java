package com.security.jwt.controller;


import com.security.jwt.response.AuthorizationResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test/")
public class TestController {
    @GetMapping("/admin")
    public ResponseEntity<AuthorizationResponse> testAdminAPI() {
        return  ResponseEntity.ok(AuthorizationResponse.builder().message("WELCOME ADMIN").build());
    }

    @GetMapping("/user")
    public ResponseEntity<AuthorizationResponse> testUserAPI() {
        return ResponseEntity.ok(AuthorizationResponse.builder().message("WELCOME USER").build());
    }
}
