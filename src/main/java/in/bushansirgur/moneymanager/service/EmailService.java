package in.bushansirgur.moneymanager.service;

import org.springframework.stereotype.Component;

@Component
public class EmailService {

    public void sendEmail(String to, String subject, String body) {
        System.out.println("Email disabled on Render");
    }

    public void sendEmailWithAttachment(
            String to,
            String subject,
            String body,
            byte[] attachment,
            String filename
    ) {
        System.out.println("Email attachment disabled on Render");
    }
}
