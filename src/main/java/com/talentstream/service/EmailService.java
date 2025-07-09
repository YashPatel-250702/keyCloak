package com.talentstream.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.amazonaws.services.s3.AmazonS3;
import com.talentstream.AwsSecretsManagerUtil;
import org.json.JSONObject;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.auth.AWSStaticCredentialsProvider;

import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

@Service
public class EmailService {

    @Autowired
    private AwsSecretsManagerUtil secretsManagerUtil;

    private String getSecret() {
        return secretsManagerUtil.getSecret();
    }

    // Configure the JavaMailSender manually
    private JavaMailSenderImpl getJavaMailSender() {
        String secret = getSecret();
        JSONObject jsonObject = new JSONObject(secret);
        String userName = jsonObject.getString("AWS_EMAIL_USERNAME");
        String passWord = jsonObject.getString("AWS_EMAIL_PASSWORD");

        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("email-smtp.ap-south-1.amazonaws.com");
        mailSender.setPort(587); // TLS port

        // Set your SMTP credentials directly
        mailSender.setUsername(userName);
        mailSender.setPassword(passWord);

        // Set additional mail properties
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true"); // Enables debug information in logs

        return mailSender;
    }

    // Sends an OTP verification email to the applicant for identity verification.
    public void sendOtpEmail(String to, String otp) {
        try {
            // Use the manually configured JavaMailSender
            JavaMailSenderImpl mailSender = getJavaMailSender();

            javax.mail.internet.MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom(new InternetAddress("no-reply@bitlabs.in", "bitLabs Jobs"));
            helper.setTo(to);
            helper.setSubject("OTP verification for bitLabs Jobs");

            String content = "Dear Applicant,\n\n" +
                    "Your OTP is: " + otp + "\n\n" +
                    "We received a request to verify your identity for bitLabs Jobs. To complete the sign-up process, please use the above One-Time Password (OTP).\n\n"
                    +
                    "This OTP is valid for the next 1 minute. For your security, please do not share this code with anyone.\n\n"
                    +
                    "If you did not request this verification, please ignore this email.\n\n" +
                    "Thank you for using bitLabs Jobs!\n\n" +
                    "Best regards,\n" +
                    "The bitLabs Jobs Team\n\n" +
                    "This is an auto-generated email. Please do not reply.";

            helper.setText(content);

            // Send the email
            mailSender.send(message);
        } catch (MessagingException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}
