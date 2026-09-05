package com.krawenn.auth.user;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Lookups are case-insensitive to match the {@code lower(...)} unique indexes, so a
 * user cannot register a second account differing only in letter case.
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByEmailIgnoreCase(String email);
}
