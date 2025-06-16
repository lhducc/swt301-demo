package com.example.BloodDonationSupportSystem.service.authaccountservice;

import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.request.LoginRequest;
import com.example.BloodDonationSupportSystem.dto.authenaccountDTO.response.LoginAccountResponse;
import com.example.BloodDonationSupportSystem.entity.RoleEntity;
import com.example.BloodDonationSupportSystem.entity.UserEntity;
import com.example.BloodDonationSupportSystem.exception.BadRequestException;
import com.example.BloodDonationSupportSystem.repository.RoleRepository;
import com.example.BloodDonationSupportSystem.repository.UserRepository;
import com.example.BloodDonationSupportSystem.service.jwtservice.JwtService;
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

import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;



public class LoginTest {


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
        String phone = "0909999999";
        String password = "123456";
        String hashedPassword = "hashed123";
        String expectedToken = "jwt.token.value";
        String expectedRole = "ROLE_USER";

        RoleEntity role = new RoleEntity();
        role.setRoleName(expectedRole);

        UserEntity user = new UserEntity();
        user.setUserId(UUID.randomUUID());
        user.setPhoneNumber(phone);
        user.setPasswordHash(hashedPassword);
        user.setRole(role);

        UserDetails userDetails = new User(user.getUserId().toString(), hashedPassword, user.getAuthorities());

        when(userRepository.findByPhoneNumber(phone)).thenReturn(Optional.of(user));

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);

        when(jwtService.generateToken(any(UserDetails.class))).thenReturn(expectedToken);

        LoginAccountResponse response = authAccountService.authAccount(new LoginRequest(phone, password));

        assertEquals(expectedToken, response.getToken());
        verify(authenticationManager, times(1)).authenticate(any());
    }






    @Test(dataProvider = "loginFailureCases")
    public void login_WithInvalidInput_ShouldThrowException(
            String phone, String password, String expectedMessage, boolean isPhoneExists) {

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




}