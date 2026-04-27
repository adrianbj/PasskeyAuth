<?php
require_once __DIR__ . '/../vendor/autoload.php';

// Provide a fresh in-memory SQLite DB per test run
function pa_test_pdo(): PDO {
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE passkey_auth (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        credential_id BLOB NOT NULL UNIQUE,
        public_key    BLOB NOT NULL,
        sign_count    INTEGER NOT NULL DEFAULT 0,
        name          TEXT NOT NULL,
        created       TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used     TEXT
    )");
    return $pdo;
}
