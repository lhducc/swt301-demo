package com.example.BloodDonationSupportSystem.base;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BaseReponse<T> {
    private int status;
    private String message;
    private T data;
}
