-- A short code alongside every reset link, for clients that cannot open one.
--
-- A link in an email lands in a browser. A mobile application has no page for it to open until
-- it owns a verified https domain, so the same email also carries six digits the person can type
-- into the application instead. The code is exchanged for a reset token, and the reset itself is
-- the one that already exists.
--
-- Six digits are guessable where a 256-bit token is not, which is what the attempt counter is
-- for: a few wrong codes retire the request, link included.

ALTER TABLE password_reset_token
    -- BCrypt of the code, not SHA-256: a fast digest of a six-digit number is reversed by trying
    -- all million of them. Null once the code has been exchanged, so it works once, and on rows
    -- issued before this migration, which expire within the hour.
    ADD COLUMN code_hash            text,
    ADD COLUMN failed_code_attempts integer NOT NULL DEFAULT 0;
