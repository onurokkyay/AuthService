package com.krawenn.auth.user;

import com.krawenn.auth.error.UserNotFoundException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reads and administrative changes to accounts. */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public User require(UUID userId) {
        return userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
    }

    /**
     * Takes effect immediately for refreshes, since the next access token is built from
     * the stored role. An already-issued access token keeps the old role until it
     * expires, which is the price of stateless verification and is why the access token
     * lifetime is kept short.
     */
    @Transactional
    public User assignRole(UUID userId, Role role) {
        User user = require(userId);
        Role previous = user.getRole();
        user.assignRole(role);
        log.info("Role of user {} changed from {} to {}", userId, previous, role);
        return user;
    }
}
