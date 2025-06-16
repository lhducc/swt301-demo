package com.example.BloodDonationSupportSystem.dto.articleDTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class ArticleDTO {

    private int articleId;
    @NotBlank(message = "Title cannot blank")
    private String title;

    private String content;

    private String status;

    @NotNull(message = "Must be have article type")
    private String articleTypeName;

    @NotNull(message = "Must be have created by admin id")
    private UUID createdByAdminId;

}
