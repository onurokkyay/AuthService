package com.krawenn.auth.user;

/**
 * The roles this service knows about.
 *
 * <p>Deliberately just two. This service answers "who is this and are they an
 * administrator of the identity system"; deciding what a user may do inside a business
 * domain is the consuming service's job, so there is no permission model here.
 */
public enum Role {
    USER,
    ADMIN;

    /** The Spring Security authority name, which carries the conventional prefix. */
    public String authority() {
        return "ROLE_" + name();
    }
}
