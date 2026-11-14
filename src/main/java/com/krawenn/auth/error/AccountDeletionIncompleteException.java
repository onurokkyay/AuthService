package com.krawenn.auth.error;

/**
 * An application that holds data about the account did not confirm deleting it, so the account was left
 * open. Trying again is safe: every step before the last is idempotent.
 */
public class AccountDeletionIncompleteException extends AuthException {

    public AccountDeletionIncompleteException() {
        super(
                ErrorCode.ACCOUNT_DELETION_INCOMPLETE,
                "The account could not be deleted everywhere yet, so it is still open. Try again shortly.");
    }
}
