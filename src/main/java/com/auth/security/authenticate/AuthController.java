package com.auth.security.authenticate;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/project1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/registerUser")
    public ResponseEntity<ResponseAuth> registerUser(
            @RequestBody RegisterUserRequest registerUserRequest
    ) {
        return ResponseEntity.ok(authService.registerUser(registerUserRequest));
    }
    @PostMapping("/authenticateUser")
    public ResponseEntity<ResponseAuth> authenticateUser(
            @RequestBody RequestAuth requestAuth
    ) {
        return ResponseEntity.ok(authService.authenticateUser(requestAuth));
    }
}
