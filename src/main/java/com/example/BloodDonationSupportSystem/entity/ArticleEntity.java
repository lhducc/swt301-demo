package com.example.BloodDonationSupportSystem.entity;


import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Date;
import java.util.List;

@Data
@Entity(name = "article")
public class ArticleEntity {
    @Id
    @GeneratedValue
    @JdbcTypeCode(SqlTypes.UUID)
    @Column(name = "article_id", columnDefinition = "uniqueidentifier")
    private String articleId;

    @Column(name = "title")
    private String title;

    @Column(name = "content")
    private String content;

    @Column(name = "created_at")
    private Date createdAt;

    @Column(name = "status")
    private String status;

    @ManyToOne
    @JoinColumn(name = "article_type_id")
    private ArticleTypeEntity articleTypeEntity;

    @ManyToOne
    @JoinColumn(name = "created_by_admin_id")
    private UserEntity createdByAdminId;

    @OneToMany(mappedBy = "imageId")
    private List<ImageEntity> images;


}
