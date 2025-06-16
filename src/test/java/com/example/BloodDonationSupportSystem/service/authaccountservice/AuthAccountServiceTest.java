package com.example.BloodDonationSupportSystem.service.authaccountservice;

import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request.LoginRequest;
import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request.RegisterRequest;
import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.response.LoginAccountResponse;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;


public class AuthAccountServiceTest {


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

    @Test
    public void login_WithValidCredentials_ShouldReturnToken() {
        // Arrange
        String phone = "0909999999";
        String password = "123456";
        String hashedPassword = "hashed123";
        String expectedToken = "jwt.token.value";

        RoleEntity role = new RoleEntity();
        role.setRoleName("ROLE_MEMBER");

        UserEntity user = new UserEntity();
        user.setUserId(UUID.randomUUID());
        user.setPhoneNumber(phone);
        user.setPasswordHash(hashedPassword);
        user.setRole(role);

        UserDetails userDetails = new User(user.getUserId().toString(), hashedPassword, user.getAuthorities());

        // Mock userRepository
        when(userRepository.findByPhoneNumber(phone)).thenReturn(Optional.of(user));

        // Mock authentication

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);

        // Mock JWT
        when(jwtService.generateToken(any(UserDetails.class))).thenReturn(expectedToken);

        // Act
        LoginAccountResponse response = authAccountService.authAccount(new LoginRequest(phone, password));

        // Assert
        assertEquals(expectedToken, response.getToken());
        verify(authenticationManager, times(1)).authenticate(any());
    }






    @Test(dataProvider = "loginFailureCases")
    public void login_WithInvalidInput_ShouldThrowException(
            String phone, String password, String expectedMessage, boolean isPhoneExists) {

        // Arrange
        if (!isPhoneExists) {
            when(userRepository.findByPhoneNumber(phone)).thenReturn(Optional.empty());
        } else {
            RoleEntity role = new RoleEntity();
            role.setRoleName("ROLE_MEMBER");

            UserEntity user = new UserEntity();
            user.setPhoneNumber(phone);
            user.setPasswordHash("correctPassword");
            user.setRole(role);

            when(userRepository.findByPhoneNumber(phone)).thenReturn(Optional.of(user));
            doThrow(new BadCredentialsException("Bad credentials"))
                    .when(authenticationManager).authenticate(any());
        }

        // Act & Assert
        try {
            authAccountService.authAccount(new LoginRequest(phone, password));
            Assert.fail("Expected BadRequestException was not thrown");
        } catch (BadRequestException ex) {
            assertEquals(ex.getMessage(), expectedMessage);
        }
    }

    @DataProvider(name = "loginFailureCases")
    public Object[][] loginFailureCases() {
        return new Object[][] {
                { "0000000000", "123456", "PhoneNumber doesn't exist", false },
                { "0909999999", "wrongpass", "Incorrect username or password!!!", true }
        };
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

    @Test
    public void testRegister_Success() {
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
    public void testRegister_PhoneNumberAlreadyExists() {
        RegisterRequest request = mockRequest("0912345678", "Nguyen Van A", "Hanoi", "NAM", "ACTIVE", "password123");
        when(userRepository.existsByPhoneNumber(request.getPhoneNumber())).thenReturn(true);
        authAccountService.register(request);
    }

    @Test(expectedExceptions = ResourceNotFoundException.class)
    public void testRegister_RoleNotFound() {
        RegisterRequest request = mockRequest("0912345678", "Nguyen Van A", "Hanoi", "NAM", "ACTIVE", "password123");
        when(userRepository.existsByPhoneNumber(request.getPhoneNumber())).thenReturn(false);
        when(roleRepository.findByRoleName("ROLE_MEMBER")).thenReturn(Optional.empty());
        authAccountService.register(request);
    }

}