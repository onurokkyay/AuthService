package com.krawenn.auth.api;

import com.krawenn.auth.api.dto.UpdateRoleRequest;
import com.krawenn.auth.api.dto.UserResponse;
import com.krawenn.auth.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration of accounts. Restricted to {@code ADMIN} by the filter chain, which
 * guards the whole {@code /api/admin} prefix.
 *
 * <p>Only role assignment is exposed. Listing or editing accounts belongs to whatever
 * back-office a consuming project builds, not to the identity service.
 */
@RestController
@RequestMapping("/api/admin/users")
@Tag(name = "Administration", description = "Account administration (ADMIN only)")
public class AdminUserController {

    private final UserService userService;

    public AdminUserController(UserService userService) {
        this.userService = userService;
    }

    @PatchMapping("/{userId}/role")
    @Operation(summary = "Assign a role to an account")
    public UserResponse updateRole(@PathVariable UUID userId, @Valid @RequestBody UpdateRoleRequest request) {
        return UserResponse.from(userService.assignRole(userId, request.role()));
    }
}
