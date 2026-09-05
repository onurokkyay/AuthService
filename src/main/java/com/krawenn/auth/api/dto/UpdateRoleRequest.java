package com.krawenn.auth.api.dto;

import com.krawenn.auth.user.Role;
import jakarta.validation.constraints.NotNull;

public record UpdateRoleRequest(@NotNull Role role) {}
