package com.vishal.springsecurityjwt.controller;

import com.vishal.springsecurityjwt.model.User;
import com.vishal.springsecurityjwt.model.RefreshToken;
import com.vishal.springsecurityjwt.service.AuthService;
import com.vishal.springsecurityjwt.service.JwtService;
import com.vishal.springsecurityjwt.service.RefreshTokenService;
import com.vishal.springsecurityjwt.utils.AuthResponse;
import com.vishal.springsecurityjwt.utils.LoginRequest;
import com.vishal.springsecurityjwt.utils.RefreshTokenRequest;
import com.vishal.springsecurityjwt.utils.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;


    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authService.register(registerRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {

        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenRequest.getRefreshToken());
        User user = refreshToken.getUser();

        String accessToken = jwtService.generateToken(user);

        return ResponseEntity.ok(AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getRefreshToken())
                .build());
    }
}
