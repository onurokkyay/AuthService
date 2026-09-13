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

    /** Password reset starts from an address, because an address is what a locked-out person still knows. */
    Optional<User> findByEmailIgnoreCase(String email);
}
