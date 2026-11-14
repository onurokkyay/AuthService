package com.krawenn.auth.password;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A new password that is not known from a data breach. Checked with the rest of the request, so a client
 * gets it back as one more field error.
 */
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NotBreachedValidator.class)
public @interface NotBreached {

    String message() default "has appeared in a data breach; choose another";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
