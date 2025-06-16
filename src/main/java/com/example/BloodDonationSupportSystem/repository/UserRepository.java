package com.example.BloodDonationSupportSystem.repository;

import com.example.BloodDonationSupportSystem.entity.OauthAccountEntity;
import com.example.BloodDonationSupportSystem.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;
@Repository
public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByPhoneNumber(String phoneNumber);
    Optional<UserEntity> findByOauthAccount(OauthAccountEntity oauthAccountEntity);
    Optional<UserEntity> findByUserId(UUID userId);
    boolean existsByPhoneNumber(String phoneNumber);
}
