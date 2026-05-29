package com.demo.authpoc.user;

import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory user store for the demo. Two preloaded users: alice/wonderland, bob/builder.
 */
@Service
public class UserService {

    private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    public UserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void seed() {
        register("alice", "wonderland", Set.of("USER"));
        register("bob", "builder", Set.of("USER", "ADMIN"));
    }

    public User register(String username, String rawPassword, Set<String> roles) {
        User user = new User(
                UUID.randomUUID().toString(),
                username,
                passwordEncoder.encode(rawPassword),
                roles
        );
        usersByUsername.put(username, user);
        return user;
    }

    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(usersByUsername.get(username));
    }

    public Optional<User> authenticate(String username, String rawPassword) {
        return findByUsername(username)
                .filter(u -> passwordEncoder.matches(rawPassword, u.passwordHash()));
    }

    public Optional<User> findById(String id) {
        return usersByUsername.values().stream()
                .filter(u -> u.id().equals(id))
                .findFirst();
    }
}
