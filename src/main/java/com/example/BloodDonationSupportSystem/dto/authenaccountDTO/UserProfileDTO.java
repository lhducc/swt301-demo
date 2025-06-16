package com.example.BloodDonationSupportSystem.dto.authenaccountDTO;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.UUID;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserProfileDTO {
    private UUID id;
    private String fullName;
    private LocalDate dayOfBirth;
    private String gender;
    private String address;
    private String phoneNumber;
    private String longitude;
    private String latitude;
    private String bloodType;
    private String role;

}
