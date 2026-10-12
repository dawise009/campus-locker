<?php
declare(strict_types=1);

// Keep existing password handling compatible with seeded accounts.
function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

// Issue a random token and store only its hash.
function issue_reset_token(string $email): string
{
    $email = strtolower(trim($email));
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash("sha256", $token);

    $stmt = db()->prepare("
        INSERT INTO reset_tokens (email, token, created_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(email) DO UPDATE SET
            token = excluded.token,
            created_at = excluded.created_at
    ");
    $stmt->execute([$email, $tokenHash]);

    return $token;
}

// Call inside the password-reset transaction.
// A successful match deletes the issued token exactly once.
function consume_reset_token(string $email, string $token): bool
{
    $email = strtolower(trim($email));

    if (!preg_match('/\A[0-9a-f]{64}\z/', $token)) {
        return false;
    }

    $tokenHash = hash("sha256", $token);

    $stmt = db()->prepare("
        DELETE FROM reset_tokens
        WHERE email = ?
          AND token = ?
          AND created_at >= date('now')
          AND created_at <= datetime('now')
    ");
    $stmt->execute([$email, $tokenHash]);

    return $stmt->rowCount() === 1;
}
