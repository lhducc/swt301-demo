package com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

import java.time.LocalDate;

@Data
public class RegisterRequest {
    @NotBlank(message = "Phonenumber can't blank")
    @Length(min = 10, max = 10, message = "PhoneNumber must be 10 numbers")
    private String phoneNumber;

    @NotBlank(message = "Password can't blank")
    @Length(min = 6, message = "Password less than 6 characters")
    private String confirmPassword;

    @NotNull(message = "FullName can't null")
    private String fullName;

    @NotNull(message = "Gender can't null")
    private String gender;

    @NotNull(message = "Day of birth can't null")
    @Past(message = "Day of birth must be past")
    private LocalDate dateOfBirth;

    @NotNull(message = "Address can't null")
    private String address;

    @NotNull(message = "Status can't null")
    private String status;




}
