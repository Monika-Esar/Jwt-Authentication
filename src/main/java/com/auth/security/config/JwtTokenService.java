package com.auth.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtTokenService {
    private static final String SECURITY_KEY="6150645367566B597033733676397924423F4528482B4D6251655468576D5A71";
    public String extractUserName(String jwtToken) {
        return extractUserClaim(jwtToken,Claims::getSubject);
    }

    public <T> T extractUserClaim(String jwtToken, Function<Claims, T> claimsResolver){
        final Claims userClaims = extractUserClaims(jwtToken);
        return claimsResolver.apply(userClaims);
    }
    private Claims extractUserClaims(String jwtToken){
        return Jwts.parserBuilder().setSigningKey(getSigningkey()).build().parseClaimsJws(jwtToken).getBody();
    }

    public String generateJwtToken(UserDetails userDetails){
        return generateJwtToken(new HashMap<>(), userDetails);
    }
    public String generateJwtToken(Map<String, Object> userClaims, UserDetails userDetails){
        return Jwts.builder().setClaims(userClaims).setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis())).setExpiration(new Date(System.currentTimeMillis()+2000*60*24)).signWith(getSigningkey(), SignatureAlgorithm.HS256).compact();
    }
    private Key getSigningkey() {
        byte[] secretKeyBytes = Decoders.BASE64.decode(SECURITY_KEY);
        return Keys.hmacShaKeyFor(secretKeyBytes);
    }

    public boolean isJwtTokenValid(String jwtToken, UserDetails userDetails){
        final String userName = extractUserName(jwtToken);
        return (userName.equals(userDetails.getUsername())) && !isJwtTokenExpired(jwtToken);
    }

    private boolean isJwtTokenExpired(String jwtToken) {
        return extractExpirationTokenTime(jwtToken).before(new Date());
    }

    private Date extractExpirationTokenTime(String jwtToken) {
        return extractUserClaim(jwtToken, Claims::getExpiration);
    }
}
