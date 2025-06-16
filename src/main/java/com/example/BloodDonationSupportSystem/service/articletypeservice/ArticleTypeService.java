package com.example.BloodDonationSupportSystem.service.articletypeservice;

import com.example.BloodDonationSupportSystem.dto.articletypeDTO.ArticleTypeDTO;
import com.example.BloodDonationSupportSystem.entity.ArticleTypeEntity;
import com.example.BloodDonationSupportSystem.exception.ResourceNotFoundException;
import com.example.BloodDonationSupportSystem.repository.ArticleTypeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ArticleTypeService {
    @Autowired
    private ArticleTypeRepository articleTypeRepo;

    public ArticleTypeDTO create(ArticleTypeDTO dto) {
        ArticleTypeEntity entity = new ArticleTypeEntity();
        entity.setName(dto.getName());
        entity.setDescription(dto.getDescription());
        articleTypeRepo.save(entity);
        return mapToDTO(entity);
    }


    public ArticleTypeDTO getById(int id) {
        ArticleTypeEntity entity = articleTypeRepo.findByArticleTypeId(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article type not found"));
        return mapToDTO(entity);
    }


    public List<ArticleTypeDTO> getAll() {
        return articleTypeRepo.findAll().stream()
                .map(article -> this.mapToDTO(article))
                .toList();
    }


    public ArticleTypeDTO update(int id, ArticleTypeDTO dto) {
        ArticleTypeEntity entity = articleTypeRepo.findByArticleTypeId(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article type not found"));
        entity.setName(dto.getName());
        entity.setDescription(dto.getDescription());
        articleTypeRepo.save(entity);
        return mapToDTO(entity);
    }


    public String delete(int id) {
        ArticleTypeEntity entity = articleTypeRepo.findByArticleTypeId(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article type not found"));
        articleTypeRepo.delete(entity);
        return "Article type deleted";
    }

    private ArticleTypeDTO mapToDTO(ArticleTypeEntity entity) {
        ArticleTypeDTO dto = new ArticleTypeDTO();
        dto.setName(entity.getName());
        dto.setName(entity.getName());
        dto.setDescription(entity.getDescription());
        return dto;
    }





}
