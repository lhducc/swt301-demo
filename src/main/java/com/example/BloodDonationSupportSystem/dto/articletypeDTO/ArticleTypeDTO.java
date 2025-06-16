package com.example.BloodDonationSupportSystem.dto.articletypeDTO;


import jakarta.validation.constraints.NotNull;
import lombok.Data;



@Data
public class ArticleTypeDTO {


    private String name;

    private String description;
}
