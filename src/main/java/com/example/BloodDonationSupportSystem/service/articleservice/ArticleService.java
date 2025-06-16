package com.example.BloodDonationSupportSystem.service.articleservice;

import com.example.BloodDonationSupportSystem.dto.articleDTO.ArticleDTO;
import com.example.BloodDonationSupportSystem.entity.ArticleEntity;
import com.example.BloodDonationSupportSystem.exception.ResourceNotFoundException;
import com.example.BloodDonationSupportSystem.repository.ArticleRepository;
import com.example.BloodDonationSupportSystem.repository.ArticleTypeRepository;
import com.example.BloodDonationSupportSystem.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class ArticleService {

    @Autowired
    private ArticleRepository articleRepository;

    @Autowired
    private ArticleTypeRepository articleTypeRepository;

    @Autowired
    private UserRepository userRepository;

    public ArticleDTO create(ArticleDTO dto) {
        ArticleEntity article = new ArticleEntity();
        article.setTitle(dto.getTitle());
        article.setContent(dto.getContent());
        article.setStatus("CHỜ ĐỢI");
        article.setArticleTypeEntity(articleTypeRepository.findByArticleTypeId(dto.getArticleId())
                .orElseThrow(() -> new ResourceNotFoundException("ArticleType not found")));
        article.setCreatedByAdminId(userRepository.findById(dto.getCreatedByAdminId())
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found")));
        articleRepository.save(article);
        return mapToDTO(article);
    }

    public ArticleDTO getById(UUID id) {
        return articleRepository.findById(id)
                .map(article -> this.mapToDTO(article))
                .orElseThrow(() -> new ResourceNotFoundException("Article not found"));
    }

    public List<ArticleDTO> getAll() {
        return articleRepository.findAll().stream().map(article -> this.mapToDTO(article)).toList();
    }


    public ArticleDTO update(UUID id, ArticleDTO dto) {
        ArticleEntity article = articleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article not found"));
        article.setTitle(dto.getTitle());
        article.setContent(dto.getContent());
        article.setStatus(dto.getStatus());
        articleRepository.save(article);
        return mapToDTO(article);
    }

    public String delete(UUID id) {
        ArticleEntity article = articleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article not found"));
        articleRepository.delete(article);
        return "Deleted Article";
    }

    private ArticleDTO mapToDTO(ArticleEntity entity) {
        ArticleDTO dto = new ArticleDTO();
        dto.setTitle(entity.getTitle());
        dto.setContent(entity.getContent());
        dto.setStatus(entity.getStatus());
        dto.setArticleTypeName(entity.getArticleTypeEntity().getName());
        dto.setCreatedByAdminId(entity.getCreatedByAdminId().getUserId());
        return dto;
    }



}
