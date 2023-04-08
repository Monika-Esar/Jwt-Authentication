package com.auth.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Integer> {
    @Query(value = """
      select t from AuthToken t inner join UserDetail u\s
      on t.userDetail.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
    List<AuthToken> findAllValidAuthTokenByUser(Integer id);

    Optional<AuthToken> findByAuthToken(String authToken);
}
