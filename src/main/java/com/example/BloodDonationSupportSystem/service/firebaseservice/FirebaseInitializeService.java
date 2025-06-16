package com.example.BloodDonationSupportSystem.service.firebaseservice;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@Service
public class FirebaseInitializeService {
    @Value("${firebase.config}")
    private String firebaseConfig;
    @Value("${firebase.projectID}")
    private String projectID;
    @PostConstruct
    public void init() {
        final String firebaseConfigJSON = firebaseConfig;
        if (firebaseConfigJSON == null) {
            throw new IllegalStateException("FIREBASE_CONFIG env var not set");
        }

        ByteArrayInputStream serviceAccount = new ByteArrayInputStream(firebaseConfigJSON.getBytes());
        FirebaseOptions options;
        try {
            options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .setStorageBucket(projectID + ".appspot.com").build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (FirebaseApp.getApps().isEmpty()) {
            FirebaseApp.initializeApp(options);
        }
    }

}
