package com.example.BloodDonationSupportSystem.Utils;

import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.UserProfileDTO;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class AuthUtils {
    public static UserDetails getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return (UserDetails) authentication.getPrincipal();
        }
        throw new RuntimeException("User is not authenticated");


    }




}
