package com.auth.security.token;

import com.auth.security.model.UserDetail;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "auth_token")
public class AuthToken {
    @Id
    @GeneratedValue
    public Integer id;

    @Column(unique = true)
    public String authToken;

    @Enumerated(EnumType.STRING)
    public AuthTokenType authTokenType = AuthTokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @ManyToOne
    @JoinColumn(name = "user_id")
    public UserDetail userDetail;
}
