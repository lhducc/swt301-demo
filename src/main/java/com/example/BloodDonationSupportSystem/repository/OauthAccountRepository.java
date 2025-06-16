package com.example.BloodDonationSupportSystem.repository;

import com.example.BloodDonationSupportSystem.entity.OauthAccountEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthAccountRepository extends JpaRepository<OauthAccountEntity, Long> {
    Optional<OauthAccountEntity> findByProviderAndProviderUserId(String provider, String providerUserId);
    Optional<OauthAccountEntity> findByAccount(String account);
}
