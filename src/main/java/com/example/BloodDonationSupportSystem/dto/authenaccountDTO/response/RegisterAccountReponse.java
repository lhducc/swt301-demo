package com.example.BloodDonationSupportSystem.dto.authenaccountDTO.response;

import jakarta.validation.constraints.NotNull;
import lombok.Data;


@Data
public class RegisterAccountReponse {
    @NotNull
    private String message;
}
