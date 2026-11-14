package com.krawenn.auth.password;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/** Built by Spring's validator factory, which is what lets it be handed the checker. */
public class NotBreachedValidator implements ConstraintValidator<NotBreached, String> {

    private final BreachedPasswords breachedPasswords;

    public NotBreachedValidator(BreachedPasswords breachedPasswords) {
        this.breachedPasswords = breachedPasswords;
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        return !breachedPasswords.isBreached(password);
    }
}
