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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class AuthAccountService {

    private UserRepository userRepository;

    private RoleRepository roleRepository;

    private AuthenticationManager authenticationManager;

    private JwtService jwtService;

    private PasswordEncoder passwordEncoder;

    public AuthAccountService (UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository, AuthenticationManager authenticationManager, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
        this.authenticationManager = authenticationManager;
    }



    public RegisterAccountReponse register(RegisterRequest registerRequest) {
        RegisterAccountReponse response;
        if (userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
            throw new BadRequestException("Phone number already in use");
        }
            UserEntity user = new UserEntity();
            user.setPhoneNumber(registerRequest.getPhoneNumber());
            Optional<RoleEntity> roleMember = roleRepository.findByRoleName("ROLE_MEMBER");
            user.setRole(roleMember.orElseThrow(() -> new ResourceNotFoundException("Cannot find role")));
            user.setFullName(registerRequest.getFullName());
            user.setAddress(registerRequest.getAddress());
            user.setDateOfBirth(registerRequest.getDateOfBirth());
            user.setGender(registerRequest.getGender());
            user.setStatus(registerRequest.getStatus());
            user.setPasswordHash(passwordEncoder.encode(registerRequest.getConfirmPassword()));
            userRepository.save(user);
            response = new RegisterAccountReponse();
            response.setMessage("Registration successful");





        return response;
    }

    public LoginAccountResponse authAccount(LoginRequest loginRequest) {

        LoginAccountResponse loginAccountResponse;
        UserEntity user = userRepository.findByPhoneNumber(loginRequest.getPhoneNumber()).orElseThrow(() -> new BadRequestException("PhoneNumber doesn't exist"));
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getPhoneNumber(), loginRequest.getPassword()));
        } catch (AuthenticationException e) {
            throw new BadRequestException("Incorrect username or password!!!");
        }

        String token = jwtService.generateToken(new User(user.getUserId().toString(), user.getPasswordHash(), Collections.singleton(new SimpleGrantedAuthority(user.getRole().getRoleName()))));
        loginAccountResponse = new LoginAccountResponse(token);
        return loginAccountResponse;


    }






}
