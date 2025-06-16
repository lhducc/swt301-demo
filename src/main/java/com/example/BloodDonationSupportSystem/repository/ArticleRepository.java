package com.example.BloodDonationSupportSystem.repository;

import com.example.BloodDonationSupportSystem.entity.ArticleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ArticleRepository extends JpaRepository<ArticleEntity, UUID> {
    List<ArticleEntity> findByStatus(String status);



}
