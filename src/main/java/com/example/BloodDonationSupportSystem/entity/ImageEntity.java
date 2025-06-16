package com.example.BloodDonationSupportSystem.entity;

import com.google.type.DateTime;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

@Data
@Entity(name = "image")
public class ImageEntity {
    @Id
    @GeneratedValue
    @JdbcTypeCode(SqlTypes.UUID)
    @Column(name = "image_id", columnDefinition = "uniqueidentifier")
    private UUID imageId;

    @Column(name = "image_url")
    private String imageUrl;

    @Column(name = "description")
    private String description;

    @Column(name = "created_at")
    private DateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "article_id")
    private ArticleEntity article;



}
