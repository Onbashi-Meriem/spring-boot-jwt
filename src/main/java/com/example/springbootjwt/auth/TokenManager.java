package com.example.springbootjwt.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;
import java.util.Date;


@Service
public class TokenManager {
    private static final String secretKey="HaydiKodlayalim";
    private static final int validity=5*60*1000;
    public String generateToken(String username){
        return  Jwts.builder()
                .setSubject(username)
                .setIssuer("www.hadikodlayalim.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+validity))
                .signWith( SignatureAlgorithm.HS256, secretKey)
                .compact();
    }
    public boolean tokenValidate(String token){
        if(getUserFromToken(token)!=null && !isExpired(token)){
            return true;
        }
        return false;
    }
    public String getUserFromToken(String token){
        return getClaims(token).getSubject();
    }
    public boolean isExpired(String token){
        return getClaims(token).getExpiration().before(new Date(System.currentTimeMillis()));
    }

    private Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }
}
