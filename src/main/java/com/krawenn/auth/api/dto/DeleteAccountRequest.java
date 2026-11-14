package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

/** @param password the account's current password, asked again because this cannot be undone */
public record DeleteAccountRequest(@NotBlank String password) {}
