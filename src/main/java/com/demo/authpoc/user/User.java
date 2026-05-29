package com.demo.authpoc.user;

import java.util.Set;

public record User(
        String id,
        String username,
        String passwordHash,
        Set<String> roles
) {}
