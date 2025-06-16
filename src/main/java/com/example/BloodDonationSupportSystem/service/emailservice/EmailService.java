package com.example.BloodDonationSupportSystem.service.emailservice;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    @Autowired
    private JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String email;

    public void sendHealthReminder(String username, String userEmail ) throws MessagingException {
            MimeMessage message = mailSender.createMimeMessage();

            // true = multipart
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(userEmail);

            helper.setSubject("Nhắc nhở theo dõi sức khỏe sau hiến máu");

            // Cả plain text và HTML (để client tự chọn)
            helper.setText("Xin chào " + username + "\n" +
                    "\n" +
                    "Cảm ơn bạn đã tham gia hiến máu tình nguyện.\n" +
                    "\n" +
                    "Vui lòng theo dõi tình trạng sức khỏe trong 48 giờ tới. Nếu có dấu hiệu bất thường như chóng mặt, mệt mỏi kéo dài, hãy đến trung tâm y tế gần nhất.\n" +
                    "\n" +
                    "Trân trọng,\n" +
                    "Trung tâm Hiến máu", " <div style=\"max-width: 600px; margin: 0 auto;\">\n" +
                    "    <h2 style=\"color: #d32f2f;\">Cảm ơn bạn đã hiến máu!</h2>\n" +
                    "\n" +
                    "    <p>Xin chào <strong>"+username+"</strong>,</p>\n" +
                    "\n" +
                    "    <p>Trung tâm xin chân thành cảm ơn bạn đã tham gia hiến máu tình nguyện.</p>\n" +
                    "\n" +
                    "    <p>\n" +
                    "      Vui lòng theo dõi tình trạng sức khỏe của bạn trong vòng <strong>48 giờ tới</strong>. Nếu có các dấu hiệu bất thường như <em>chóng mặt</em>, <em>mệt mỏi kéo dài</em>, hãy đến trung tâm y tế gần nhất để kiểm tra.\n" +
                    "    </p>\n" +
                    "\n" +
                    "    <p>Nếu bạn có bất kỳ câu hỏi nào, hãy phản hồi lại email này hoặc liên hệ với chúng tôi qua số điện thoại hỗ trợ.</p>\n" +
                    "\n" +
                    "    <p style=\"margin-top: 32px;\">Trân trọng,<br />\n" +
                    "    <strong>Trung tâm Hiến máu</strong></p>\n" +
                    "  </div>"); // (text, html)

            helper.setFrom(email);

            mailSender.send(message);
    }
}
