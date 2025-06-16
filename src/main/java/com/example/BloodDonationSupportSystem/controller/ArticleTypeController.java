package com.example.BloodDonationSupportSystem.controller;

import com.example.BloodDonationSupportSystem.base.BaseReponse;
import com.example.BloodDonationSupportSystem.dto.articleDTO.ArticleDTO;
import com.example.BloodDonationSupportSystem.dto.articletypeDTO.ArticleTypeDTO;

import com.example.BloodDonationSupportSystem.service.articletypeservice.ArticleTypeService;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@Tag(name = "ArticleTypeController")
public class ArticleTypeController {

    @Autowired
    private ArticleTypeService articleTypeService;

    @PostMapping("/article-type")
    public BaseReponse<?> addArticleType(@RequestBody @Valid ArticleTypeDTO dto) {
        ArticleTypeDTO response = articleTypeService.create(dto);
        return new BaseReponse<>(HttpStatus.OK.value(), "Article create successfully", response);
    }

    @GetMapping("/article-type/{id}")
    public BaseReponse<?> getArticleTypeById(@PathVariable int id) {
        ArticleTypeDTO response = articleTypeService.getById(id);
        return new BaseReponse<>(HttpStatus.OK.value(), "Get article type successfully", response);
    }

    @GetMapping("/article-types")
    public BaseReponse<?> getAllArticleTypes() {
        List<ArticleTypeDTO> response = articleTypeService.getAll();
        return new BaseReponse<>(HttpStatus.OK.value(), "Get articles type successfully", response);
    }

    @PutMapping("/article-type/{id}")
    public BaseReponse<?> updateArticleType(@PathVariable int id, @RequestBody @Valid ArticleTypeDTO dto) {
        ArticleTypeDTO response = articleTypeService.update(id, dto);
        return new BaseReponse<>(HttpStatus.OK.value(), "Update article type successfully", response);
    }

    @DeleteMapping("/article-type/{id}")
    public BaseReponse<?> deleteArticleType(@PathVariable int id) {
        String response = articleTypeService.delete(id);
        return new BaseReponse<>(HttpStatus.OK.value(), "Delete article type successfully", response);
    }





}
