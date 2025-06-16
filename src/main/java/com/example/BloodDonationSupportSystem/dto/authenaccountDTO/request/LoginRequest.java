package com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

@Data
@AllArgsConstructor
public class LoginRequest {
    @NotBlank(message = "Phonenumber can't blank")
    @Length(min = 10, max = 10, message = "PhoneNumber must be 10 numbers")
    private String phoneNumber;

    @NotBlank(message = "Password can't blank")
    @Length(min = 6, message = "Password less than 6 characters")
    private String password;



}
