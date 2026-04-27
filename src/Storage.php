<?php declare(strict_types=1);

namespace PasskeyAuth;

use PDO;

final class Storage
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $tableName = 'passkey_auth',
    ) {}

    public function add(int $userId, array $row): int
    {
        $sql = "INSERT INTO {$this->tableName}
                (user_id, credential_id, public_key, sign_count, name)
                VALUES (:user_id, :credential_id, :public_key, :sign_count, :name)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'user_id'       => $userId,
            'credential_id' => $row['credential_id'],
            'public_key'    => $row['public_key'],
            'sign_count'    => $row['sign_count'] ?? 0,
            'name'          => $row['name'],
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * SEC-F #2: atomic count-and-insert for the per-user cap.
     *
     * Without this, two concurrent registerFinish calls on different sessions
     * for the same target user can both pass the application-level count check
     * and both insert, drifting one or two rows past MAX_CREDENTIALS_PER_USER.
     * The cap is a soft DoS bound, not a security boundary, so the prior race
     * was benign — but trivially closeable.
     *
     * Implementation: wrap the lock + count + insert in a transaction. The
     * `SELECT ... FOR UPDATE` on the user_id index in MySQL/InnoDB takes
     * record + gap locks scoped to that user_id, blocking concurrent inserts
     * from the same user_id range until commit. SQLite parses but ignores
     * `FOR UPDATE`; tests don't exercise concurrency, so this is fine.
     *
     * Returns the inserted row id, or null when the cap was hit (caller
     * translates to a 409 conflict).
     *
     * @throws \PDOException on any non-cap failure (including UNIQUE-key
     *         violation on credential_id; caller catches SQLSTATE 23000).
     */
    public function addIfUnderCap(int $userId, array $row, int $cap): ?int
    {
        // Nested transaction guard: if the caller already started a tx (we
        // don't, today, but be defensive) we just proceed without our own.
        $ownTx = !$this->pdo->inTransaction();
        if ($ownTx) $this->pdo->beginTransaction();

        try {
            $lock = $this->pdo->prepare(
                "SELECT id FROM {$this->tableName} WHERE user_id = :uid FOR UPDATE"
            );
            $lock->execute(['uid' => $userId]);
            $existing = (int) $lock->rowCount();
            if ($existing >= $cap) {
                if ($ownTx) $this->pdo->rollBack();
                return null;
            }

            $id = $this->add($userId, $row);
            if ($ownTx) $this->pdo->commit();
            return $id;
        } catch (\Throwable $e) {
            if ($ownTx && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function findByCredentialId(string $credentialId): ?array
    {
        $stmt = $this->pdo->prepare(
            "SELECT * FROM {$this->tableName} WHERE credential_id = :cid LIMIT 1"
        );
        $stmt->execute(['cid' => $credentialId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * SEC-F #3: hard LIMIT 100. The application-level cap
     * (Endpoints::MAX_CREDENTIALS_PER_USER = 25) is the authoritative bound,
     * but a future bug or manual DB write could exceed it. This LIMIT means
     * the management UI render path can never become a slow query, even if
     * the cap is bypassed. 100 is 4x the cap — well clear of any legitimate
     * value, narrow enough to keep render bounded.
     */
    public function listForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT * FROM {$this->tableName} WHERE user_id = :uid ORDER BY created DESC LIMIT 100"
        );
        $stmt->execute(['uid' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countForUser(int $userId): int
    {
        $stmt = $this->pdo->prepare(
            "SELECT COUNT(*) FROM {$this->tableName} WHERE user_id = :uid"
        );
        $stmt->execute(['uid' => $userId]);
        return (int) $stmt->fetchColumn();
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare(
            "SELECT * FROM {$this->tableName} WHERE id = :id LIMIT 1"
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    public function rename(int $id, string $name): bool
    {
        $stmt = $this->pdo->prepare(
            "UPDATE {$this->tableName} SET name = :name WHERE id = :id"
        );
        $stmt->execute(['name' => $name, 'id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function delete(int $id): bool
    {
        $stmt = $this->pdo->prepare(
            "DELETE FROM {$this->tableName} WHERE id = :id"
        );
        $stmt->execute(['id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function deleteAllForUser(int $userId): int
    {
        $stmt = $this->pdo->prepare(
            "DELETE FROM {$this->tableName} WHERE user_id = :uid"
        );
        $stmt->execute(['uid' => $userId]);
        return $stmt->rowCount();
    }

    public function touchLastUsed(int $id, int $signCount): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE {$this->tableName}
             SET sign_count = :sc, last_used = CURRENT_TIMESTAMP
             WHERE id = :id"
        );
        $stmt->execute(['sc' => $signCount, 'id' => $id]);
    }
}
