package com.example.BloodDonationSupportSystem.service.authaccountservice;

import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request.RegisterRequest;
import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.response.RegisterAccountReponse;
import com.example.BloodDonationSupportSystem.entity.RoleEntity;
import com.example.BloodDonationSupportSystem.entity.UserEntity;
import com.example.BloodDonationSupportSystem.exception.BadRequestException;
import com.example.BloodDonationSupportSystem.exception.ResourceNotFoundException;
import com.example.BloodDonationSupportSystem.repository.RoleRepository;
import com.example.BloodDonationSupportSystem.repository.UserRepository;
import com.example.BloodDonationSupportSystem.service.jwtservice.JwtService;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testng.annotations.BeforeMethod;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.time.LocalDate;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;


public class RegisterTest {


    private AuthAccountService authAccountService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private Authentication authentication;


    @BeforeMethod
    public void setup() {
        MockitoAnnotations.openMocks(this);

        authAccountService = new AuthAccountService(userRepository, passwordEncoder, roleRepository, authenticationManager, jwtService);

    }


    private RegisterRequest mockRequest(String phone, String fullName, String address, String gender, String status, String confirmPassword) {
        RegisterRequest request = new RegisterRequest();
        request.setPhoneNumber(phone);
        request.setFullName(fullName);
        request.setAddress(address);
        request.setGender(gender);
        request.setDateOfBirth(LocalDate.of(1995, 1, 1));
        request.setStatus(status);
        request.setConfirmPassword(confirmPassword);
        return request;
    }

    @Test
    public void testRegisterSuccess() {
        RegisterRequest request = mockRequest("0912345678", "Nguyen Van A", "Hanoi", "NAM", "ACTIVE", "password123");

        when(userRepository.existsByPhoneNumber(request.getPhoneNumber())).thenReturn(false);
        when(roleRepository.findByRoleName("ROLE_MEMBER")).thenReturn(Optional.of(new RoleEntity()));
        when(passwordEncoder.encode(request.getConfirmPassword())).thenReturn("encodedPassword");

        RegisterAccountReponse response = authAccountService.register(request);

        assertNotNull(response);
        assertEquals(response.getMessage(), "Registration successful");
        verify(userRepository, times(1)).save(any(UserEntity.class));
    }

    @Test(expectedExceptions = BadRequestException.class)
    public void testRegisterPhoneNumberAlreadyExists() {
        RegisterRequest request = mockRequest("0912345678", "Nguyen Van A", "Hanoi", "NAM", "ACTIVE", "password123");
        when(userRepository.existsByPhoneNumber(request.getPhoneNumber())).thenReturn(true);
        authAccountService.register(request);
    }


    @DataProvider(name = "registerSuccessCase")
    public Object[][] registerFailureCases() {
        RoleEntity role = new RoleEntity();
        role.setRoleName("ROLE_MEMBER");
        RegisterRequest requestData1 = mockRequest( "0912345678", "Nguyen Van A", "Hanoi", "NAM", "ACTIVE", "password123");
        RegisterRequest requestData2 = mockRequest(  "0988765432", "Tran Thi B", "Ho Chi Minh City", "NU","INACTIVE", "myStrongPassword!");
        return new Object[][] {
                {
                        requestData1,
                        role,
                        "encodedPassword123"
                },
                {
                        requestData2,
                        role,
                        "encodedPassword456"
                }
        };
    }

    @Test(dataProvider = "registerSuccessCase")
    public void testRegisterSuccessWithMultipleData(RegisterRequest request, RoleEntity mockRole, String encodedPassword) {
        when(userRepository.existsByPhoneNumber(request.getPhoneNumber())).thenReturn(false);
        when(roleRepository.findByRoleName("ROLE_MEMBER")).thenReturn(Optional.of(mockRole));
        when(passwordEncoder.encode(request.getConfirmPassword())).thenReturn(encodedPassword);

        RegisterAccountReponse response = authAccountService.register(request);

        ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository).save(captor.capture());

        UserEntity saved = captor.getValue();

        assertEquals(saved.getPhoneNumber(), request.getPhoneNumber());
        assertEquals(saved.getFullName(), request.getFullName());
        assertEquals(saved.getAddress(), request.getAddress());
        assertEquals(saved.getGender(), request.getGender());
        assertEquals(saved.getDateOfBirth(), request.getDateOfBirth());
        assertEquals(saved.getStatus(), request.getStatus());
        assertEquals(saved.getRole(), mockRole);
        assertEquals(saved.getPasswordHash(), encodedPassword);

        assertEquals(response.getMessage(), "Registration successful");
    }



}
