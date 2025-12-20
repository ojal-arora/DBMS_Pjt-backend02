package in.bushansirgur.moneymanager.service;

import org.springframework.stereotype.Component;

/**
 * Dummy EmailService for production (Render).
 * Prevents JavaMailSender startup crash.
 */
@Component
public class EmailService {

    public void sendEmail(String to, String subject, String body) {
        // EMAIL DISABLED ON RENDER
        System.out.println("Email skipped (Render): " + subject);
    }

    public void sendEmailWithAttachment(
            String to,
            String subject,
            String body,
            byte[] attachment,
            String filename
    ) {
        // EMAIL DISABLED ON RENDER
        System.out.println("Email with attachment skipped (Render): " + subject);
    }
}
