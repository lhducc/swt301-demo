package com.example.BloodDonationSupportSystem.config;




import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Blood Donation Support System API")
                        .version("1.0.0")
                        .description("API For Blood Donation Support System")
                        .contact(new Contact()
                                .name("Le Phat Khoi Nguyen")
                                .email("nguyenlpkse182643@fpt.edu.vn")
                                .url("https://blooddonationsupportsystem.github.io/blooddonationsupportsystem")))


                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));


    }
    @Bean
    public GroupedOpenApi bloodDonationSupportSystemGroup() {
        return GroupedOpenApi.builder().group("rest-api").packagesToScan("com.example.BloodDonationSupportSystem.controller").build();
    }

}
