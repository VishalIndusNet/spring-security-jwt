package com.vishal.springsecurityjwt.repo;

import com.vishal.springsecurityjwt.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken,Integer> {

    Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
