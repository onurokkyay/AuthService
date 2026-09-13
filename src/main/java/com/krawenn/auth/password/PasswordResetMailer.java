package com.krawenn.auth.password;

import com.krawenn.auth.config.AuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * Delivers a reset link by email.
 *
 * <p><b>Everything the recipient reads comes from configuration</b> — sender, product name, subject and body. This
 * service is shared by applications it knows nothing about, and CI fails the build if one of their names reaches the
 * source tree; a hard-coded sentence here would be exactly that.
 *
 * <p><b>Failures are logged, never thrown.</b> The request that caused this has already been answered with 202 and is
 * gone. There is nothing left to fail, and nothing a retry in here could achieve that the person asking again after the
 * cooldown cannot.
 *
 * <p><b>Neither the link, the code nor the address is logged.</b> The link and the code are credentials until they
 * expire, and log lines in this
 * service identify accounts by id. An SMTP error can quote the recipient back, which is why only its type is logged at
 * error level and the full exception waits for debug.
 *
 * <p>The mail sender is looked up rather than injected: Spring Boot creates one only when {@code spring.mail.host} is
 * set, and a deployment that has not configured mail must still start.
 */
@Component
public class PasswordResetMailer {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetMailer.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final AuthProperties properties;

    public PasswordResetMailer(ObjectProvider<JavaMailSender> mailSender, AuthProperties properties) {
        this.mailSender = mailSender;
        this.properties = properties;
    }

    public void send(PasswordResetTokens.IssuedReset reset) {
        AuthProperties.PasswordReset.Mail mail = properties.passwordReset().mail();
        if (!mail.enabled()) {
            log.warn(
                    "User {} asked for a password reset, but mail delivery is disabled "
                            + "(auth.password-reset.mail.enabled); nothing was sent",
                    reset.userId());
            return;
        }

        JavaMailSender sender = mailSender.getIfAvailable();
        if (sender == null) {
            log.error(
                    "User {} asked for a password reset, but no mail server is configured (spring.mail.host); "
                            + "nothing was sent",
                    reset.userId());
            return;
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(mail.from());
        message.setTo(reset.email());
        message.setSubject(fill(mail.subject(), reset, mail));
        message.setText(fill(mail.bodyTemplate(), reset, mail));

        try {
            sender.send(message);
            log.info("Sent a password reset email to user {}", reset.userId());
        } catch (MailException ex) {
            log.error(
                    "Could not send the password reset email to user {}: {}",
                    reset.userId(),
                    ex.getClass().getName());
            log.debug("Mail delivery failure for user {}", reset.userId(), ex);
        }
    }

    private String fill(
            String template, PasswordResetTokens.IssuedReset reset, AuthProperties.PasswordReset.Mail mail) {
        return template.replace("{product}", mail.productName())
                .replace("{username}", reset.username())
                .replace(
                        "{minutes}",
                        String.valueOf(properties.passwordReset().tokenTtl().toMinutes()))
                .replace("{link}", reset.link())
                .replace("{code}", reset.code());
    }
}
