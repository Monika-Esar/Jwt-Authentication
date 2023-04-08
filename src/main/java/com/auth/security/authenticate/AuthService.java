package com.auth.security.authenticate;

import com.auth.security.config.JwtTokenService;
import com.auth.security.model.UserDetail;
import com.auth.security.model.UserDetailRepository;
import com.auth.security.model.UserRole;
import com.auth.security.token.AuthToken;
import com.auth.security.token.AuthTokenRepository;
import com.auth.security.token.AuthTokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailRepository userDetailRepository;
    private final AuthTokenRepository authTokenRepository;
    private final JwtTokenService jwtTokenService;


    public ResponseAuth registerUser(RegisterUserRequest userRequest) {
        var user = UserDetail.builder()
                .firstname(userRequest.getFirstname())
                .lastname(userRequest.getLastname())
                .emailId(userRequest.getEmailId())
                .password(passwordEncoder.encode(userRequest.getPassword()))
                .userRole(UserRole.USER)
                .build();
        var savedUser = userDetailRepository.save(user);
        var jwtToken = jwtTokenService.generateJwtToken(user);
        saveUserAuthToken(savedUser, jwtToken);
        return ResponseAuth.builder()
                .authToken(jwtToken)
                .build();
    }

    public ResponseAuth authenticateUser(RequestAuth requestAuth) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        requestAuth.getUserEmail(),
                        requestAuth.getPassword()
                )
        );
        var user = userDetailRepository.findByEmailId(requestAuth.getUserEmail())
                .orElseThrow();
        var jwtToken = jwtTokenService.generateJwtToken(user);
        revokeAllUserAuthTokens(user);
        saveUserAuthToken(user, jwtToken);
        return ResponseAuth.builder()
                .authToken(jwtToken)
                .build();
    }

    private void saveUserAuthToken(UserDetail userDetail, String jwtToken) {
        var token = AuthToken.builder()
                .userDetail(userDetail)
                .authToken(jwtToken)
                .authTokenType(AuthTokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        authTokenRepository.save(token);
    }

    private void revokeAllUserAuthTokens(UserDetail userDetail) {
        var validUserAuthTokens = authTokenRepository.findAllValidAuthTokenByUser(userDetail.getId());
        if (validUserAuthTokens.isEmpty())
            return;
        validUserAuthTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        authTokenRepository.saveAll(validUserAuthTokens);
    }
}
