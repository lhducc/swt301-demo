package com.example.BloodDonationSupportSystem.service.userservice;

import com.example.BloodDonationSupportSystem.Utils.AuthUtils;
import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.UserProfileDTO;
import com.example.BloodDonationSupportSystem.entity.UserEntity;
import com.example.BloodDonationSupportSystem.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public UserProfileDTO getCurrentUserProfile() {
        try {
            UserDetails currentUser = AuthUtils.getCurrentUser();
            UUID userId;
            try {
                userId = UUID.fromString(currentUser.getUsername());
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Invalid UUID format for user ID: " + currentUser.getUsername());
            }
            UserEntity userEntity = userRepository.findByUserId(userId)
                    .orElseThrow(() -> new RuntimeException("UserId Not Found At getCurrentUserProfile()" + currentUser.getUsername()));
            UserProfileDTO userProfileDTO = new UserProfileDTO();
            userProfileDTO.setId(userEntity.getUserId());
            userProfileDTO.setFullName(userEntity.getFullName());
            userProfileDTO.setPhoneNumber(userEntity.getPhoneNumber());
            userProfileDTO.setGender(userEntity.getGender());
            userProfileDTO.setDayOfBirth(userEntity.getDateOfBirth());
            userProfileDTO.setAddress(userEntity.getAddress());
            userProfileDTO.setBloodType(userEntity.getBloodType());
            userProfileDTO.setLongitude(userEntity.getLongitude());
            userProfileDTO.setLatitude(userEntity.getLatitude());
            userProfileDTO.setRole(userEntity.getRole().getRoleName());
            return userProfileDTO;
        } catch (Exception e) {
            throw new RuntimeException("Error while getting current user profile");
        }






    }


}
