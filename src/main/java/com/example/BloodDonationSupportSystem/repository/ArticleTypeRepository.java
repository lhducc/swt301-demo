package com.example.BloodDonationSupportSystem.repository;

import com.example.BloodDonationSupportSystem.entity.ArticleTypeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ArticleTypeRepository extends JpaRepository<ArticleTypeEntity, Integer> {
    Optional<ArticleTypeEntity> findByArticleTypeId(int id);
}
