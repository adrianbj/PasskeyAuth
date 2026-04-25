# PasskeyAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a clean WebAuthn passkey authentication module for the ProcessWire admin login at `paddle.grief.coach`, replacing the broken `LoginPassKey` module.

**Architecture:** Single autoload PW module; native WebAuthn via `lbuchs/WebAuthn`; URL-hook API endpoints (no template files); GitHub-style autofill+button login UX with a dismissable registration banner; multiple passkeys per user managed from the admin user-edit page.

**Tech Stack:** PHP 8.1+, ProcessWire 3.0.173+, `lbuchs/WebAuthn` ^2.x, MySQL/MariaDB, vanilla JS (no framework), PHPUnit for unit tests.

**Spec:** `/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/docs/superpowers/specs/2026-04-25-passkeyauth-design.md`

---

## File Structure

All paths relative to `/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/` unless absolute.

```
PasskeyAuth/
├── PasskeyAuth.module.php   # autoload module class — wires hooks, manages config, install/uninstall
├── PasskeyAuth.info.php     # PW module metadata
├── composer.json            # requires lbuchs/WebAuthn ^2; phpunit dev dep
├── PasskeyAuth.js           # client; mode-based (login | banner | manage)
├── PasskeyAuth.css          # styling for banner + management list + login button
├── src/
│   ├── Storage.php          # DB CRUD for passkey_auth table; no PW or WebAuthn knowledge
│   ├── Server.php           # wraps lbuchs/WebAuthn; no DB knowledge
│   └── Endpoints.php        # URL-hook handlers; orchestrates Storage + Server + PW session/user
├── tests/
│   ├── bootstrap.php        # SQLite in-memory DB for unit tests
│   └── StorageTest.php      # PHPUnit tests for Storage
└── docs/superpowers/
    ├── specs/2026-04-25-passkeyauth-design.md
    └── plans/2026-04-25-passkeyauth.md      # this file
```

---

## Task 1: Module skeleton + composer + install/uninstall

**Files:**
- Create: `/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/PasskeyAuth.info.php`
- Create: `/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/composer.json`
- Create: `/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/PasskeyAuth.module.php`

- [ ] **Step 1: Create info.php**

```php
<?php namespace ProcessWire;

$info = [
    'title'    => 'Passkey Auth',
    'summary'  => 'WebAuthn passkey login for ProcessWire admin',
    'author'   => 'Adrian Jones',
    'version'  => '0.1.0',
    'icon'     => 'key',
    'autoload' => true,
    'singular' => true,
    'requires' => ['ProcessWire>=3.0.173', 'PHP>=8.1'],
];
```

- [ ] **Step 2: Create composer.json**

```json
{
    "name": "adrianbj/passkey-auth",
    "description": "WebAuthn passkey login for ProcessWire admin",
    "license": "MIT",
    "type": "pw-module",
    "require": {
        "php": ">=8.1",
        "lbuchs/webauthn": "^2.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0"
    },
    "autoload": {
        "psr-4": {
            "PasskeyAuth\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "PasskeyAuth\\Tests\\": "tests/"
        }
    }
}
```

- [ ] **Step 3: Run composer install**

```bash
cd /Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth && composer install
```

Expected: `vendor/` directory created with `lbuchs/webauthn` and `phpunit/phpunit` installed.

- [ ] **Step 4: Create PasskeyAuth.module.php skeleton**

```php
<?php namespace ProcessWire;

require_once __DIR__ . '/vendor/autoload.php';

class PasskeyAuth extends WireData implements Module, ConfigurableModule
{
    const TABLE_NAME = 'passkey_auth';
    const LEGACY_TABLE_NAME = 'loginpasskey';

    public function __construct()
    {
        parent::__construct();
        $this->set('apiUrlPrefix', '/passkey-auth/');
        $this->set('appName', '');
        $this->set('rpId', '');
        $this->set('allowedRoles', []);
        $this->set('userVerification', 'preferred');
        $this->set('residentKeyRequirement', 'required');
        $this->set('bannerEnabled', 1);
    }

    public function init(): void
    {
        // Hooks wired in later tasks
    }

    public function ___install(): void
    {
        $db = $this->wire('database');
        $db->exec("CREATE TABLE IF NOT EXISTS " . self::TABLE_NAME . " (
            id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id         INT UNSIGNED NOT NULL,
            credential_id   VARBINARY(255) NOT NULL,
            public_key      BLOB NOT NULL,
            sign_count      INT UNSIGNED NOT NULL DEFAULT 0,
            name            VARCHAR(120) NOT NULL,
            aaguid          CHAR(36) DEFAULT NULL,
            transports      VARCHAR(80) DEFAULT NULL,
            created         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used       TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY credential_id_unique (credential_id),
            KEY user_id_idx (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Note: no FK to pages(id). Many shared MySQL hosts deny REFERENCES privilege.
        // Cascade-delete is replicated at the application layer via a Pages::deleted hook
        // (see PasskeyAuth::onUserDeleted + Storage::deleteAllForUser).

        $this->message('PasskeyAuth installed. Configure module before use.');
    }

    public function ___uninstall(): void
    {
        $db = $this->wire('database');
        $db->exec("DROP TABLE IF EXISTS " . self::TABLE_NAME);
        $db->exec("DROP TABLE IF EXISTS " . self::LEGACY_TABLE_NAME);
        $this->message('PasskeyAuth uninstalled.');
    }

    public function getModuleConfigInputfields(array $data)
    {
        // Implemented in Task 13
        return new InputfieldWrapper();
    }
}
```

- [ ] **Step 5: Smoke test — install in PW**

In ProcessWire admin: Modules → Refresh → find "Passkey Auth" → Install.

Expected: success message; no PHP errors in logs; check that `passkey_auth` table exists:

```bash
mysql -u <user> -p <db> -e "SHOW TABLES LIKE 'passkey_auth';"
```

Expected output: one row showing `passkey_auth`.

Then uninstall and confirm the table is dropped.

- [ ] **Step 6: Reinstall the module** (we'll need it installed for subsequent tasks)

---

## Task 2: Storage class with PHPUnit tests (TDD)

**Files:**
- Create: `tests/bootstrap.php`
- Create: `tests/StorageTest.php`
- Create: `src/Storage.php`
- Create: `phpunit.xml`

- [ ] **Step 1: Create phpunit.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="tests/bootstrap.php"
         colors="true"
         failOnWarning="true"
         failOnRisky="true">
    <testsuites>
        <testsuite name="default">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

- [ ] **Step 2: Create tests/bootstrap.php**

```php
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
        aaguid        TEXT,
        transports    TEXT,
        created       TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used     TEXT
    )");
    return $pdo;
}
```

- [ ] **Step 3: Write the first failing test**

Create `tests/StorageTest.php`:

```php
<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Storage;

final class StorageTest extends TestCase
{
    private \PDO $pdo;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->pdo = pa_test_pdo();
        $this->storage = new Storage($this->pdo, 'passkey_auth');
    }

    public function testAddInsertsRowAndReturnsId(): void
    {
        $id = $this->storage->add(42, [
            'credential_id' => "\x01\x02\x03",
            'public_key'    => "\xAA\xBB\xCC",
            'name'          => 'My Mac',
            'aaguid'        => null,
            'transports'    => null,
            'sign_count'    => 0,
        ]);
        $this->assertGreaterThan(0, $id);
    }
}
```

- [ ] **Step 4: Run test — should fail because Storage doesn't exist**

```bash
cd /Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth && ./vendor/bin/phpunit
```

Expected: failure — `Class "PasskeyAuth\Storage" not found`.

- [ ] **Step 5: Create minimal Storage class to pass first test**

Create `src/Storage.php`:

```php
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
                (user_id, credential_id, public_key, sign_count, name, aaguid, transports)
                VALUES (:user_id, :credential_id, :public_key, :sign_count, :name, :aaguid, :transports)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'user_id'       => $userId,
            'credential_id' => $row['credential_id'],
            'public_key'    => $row['public_key'],
            'sign_count'    => $row['sign_count'] ?? 0,
            'name'          => $row['name'],
            'aaguid'        => $row['aaguid'] ?? null,
            'transports'    => $row['transports'] ?? null,
        ]);
        return (int) $this->pdo->lastInsertId();
    }
}
```

- [ ] **Step 6: Run test — should pass**

```bash
./vendor/bin/phpunit
```

Expected: 1 test, 1 assertion, OK.

- [ ] **Step 7: Add findByCredentialId test**

Append to `StorageTest.php`:

```php
public function testFindByCredentialIdReturnsRow(): void
{
    $this->storage->add(42, [
        'credential_id' => "\x01\x02\x03",
        'public_key'    => "\xAA\xBB\xCC",
        'name'          => 'My Mac',
        'sign_count'    => 0,
    ]);
    $row = $this->storage->findByCredentialId("\x01\x02\x03");
    $this->assertNotNull($row);
    $this->assertSame(42, (int) $row['user_id']);
    $this->assertSame("\xAA\xBB\xCC", $row['public_key']);
}

public function testFindByCredentialIdReturnsNullForUnknown(): void
{
    $this->assertNull($this->storage->findByCredentialId("\x99\x99"));
}
```

- [ ] **Step 8: Run tests — confirm new ones fail**

```bash
./vendor/bin/phpunit
```

Expected: failures — `findByCredentialId` not defined.

- [ ] **Step 9: Implement findByCredentialId**

Add to `Storage.php`:

```php
public function findByCredentialId(string $credentialId): ?array
{
    $stmt = $this->pdo->prepare(
        "SELECT * FROM {$this->tableName} WHERE credential_id = :cid LIMIT 1"
    );
    $stmt->execute(['cid' => $credentialId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row;
}
```

- [ ] **Step 10: Run tests — all pass**

- [ ] **Step 11: Add tests + implementations for remaining methods**

Add to test:

```php
public function testListForUserReturnsAllRows(): void
{
    $this->storage->add(7, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'a']);
    $this->storage->add(7, ['credential_id' => "\x02", 'public_key' => "\xBB", 'name' => 'b']);
    $this->storage->add(8, ['credential_id' => "\x03", 'public_key' => "\xCC", 'name' => 'c']);
    $rows = $this->storage->listForUser(7);
    $this->assertCount(2, $rows);
}

public function testCountForUser(): void
{
    $this->assertSame(0, $this->storage->countForUser(99));
    $this->storage->add(99, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'a']);
    $this->assertSame(1, $this->storage->countForUser(99));
}

public function testRenameUpdatesName(): void
{
    $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'old']);
    $this->assertTrue($this->storage->rename($id, 'new'));
    $row = $this->storage->findById($id);
    $this->assertSame('new', $row['name']);
}

public function testDeleteRemovesRow(): void
{
    $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'x']);
    $this->assertTrue($this->storage->delete($id));
    $this->assertNull($this->storage->findById($id));
}

public function testTouchLastUsedUpdatesCounterAndTimestamp(): void
{
    $id = $this->storage->add(1, ['credential_id' => "\x01", 'public_key' => "\xAA", 'name' => 'x']);
    $this->storage->touchLastUsed($id, 5);
    $row = $this->storage->findById($id);
    $this->assertSame(5, (int) $row['sign_count']);
    $this->assertNotNull($row['last_used']);
}
```

Implement in `Storage.php`:

```php
public function listForUser(int $userId): array
{
    $stmt = $this->pdo->prepare(
        "SELECT * FROM {$this->tableName} WHERE user_id = :uid ORDER BY created DESC"
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

public function touchLastUsed(int $id, int $signCount): void
{
    $stmt = $this->pdo->prepare(
        "UPDATE {$this->tableName}
         SET sign_count = :sc, last_used = CURRENT_TIMESTAMP
         WHERE id = :id"
    );
    $stmt->execute(['sc' => $signCount, 'id' => $id]);
}
```

- [ ] **Step 12: Run all tests — all pass**

```bash
./vendor/bin/phpunit
```

Expected: all green.

---

## Task 3: Server class — registration and login options

**Files:**
- Create: `src/Server.php`

This wraps `lbuchs/WebAuthn`. `lbuchs\WebAuthn\WebAuthn::getCreateArgs()` and `getGetArgs()` produce the option blobs we hand to the browser.

- [ ] **Step 1: Create Server.php scaffold**

```php
<?php declare(strict_types=1);

namespace PasskeyAuth;

use lbuchs\WebAuthn\WebAuthn;

final class Server
{
    private WebAuthn $webauthn;

    public function __construct(
        string $rpName,
        string $rpId,
        array $allowedFormats = ['none', 'packed', 'apple']
    ) {
        $this->webauthn = new WebAuthn($rpName, $rpId, $allowedFormats);
    }

    /**
     * Generate registration options for a user.
     *
     * @param int    $userId            ProcessWire user ID (binary-encoded as user.id for WebAuthn)
     * @param string $userName          Username (login handle)
     * @param string $userDisplayName   Friendly display name
     * @param string[] $excludeCredentialIds Raw credential ID bytes the user already has
     * @return array Decoded option blob (cast from object) ready for json_encode
     */
    public function registrationOptions(
        int $userId,
        string $userName,
        string $userDisplayName,
        array $excludeCredentialIds = [],
        string $userVerification = 'preferred',
        bool $requireResidentKey = true,
    ): array {
        $userIdBin = pack('N', $userId);  // 4-byte big-endian for compactness; alternative: hex
        $args = $this->webauthn->getCreateArgs(
            $userIdBin,
            $userName,
            $userDisplayName,
            30,                                  // timeout seconds — caller-overridable later
            $requireResidentKey,
            $userVerification,
            null,                                // crossPlatformAttachment: null = any (platform + roaming). true = roaming only. false = platform only.
            $excludeCredentialIds
        );
        // Note: getCreateArgs returns stdClass; we keep as object for JSON, but extract challenge for storage
        return [
            'options'   => $args,
            'challenge' => $this->webauthn->getChallenge()->getBinaryString(),
        ];
    }

    public function loginOptions(
        array $allowedCredentialIds = [],
        string $userVerification = 'preferred',
    ): array {
        $args = $this->webauthn->getGetArgs(
            $allowedCredentialIds,
            30,
            true,   // typeUsb
            true,   // typeNfc
            true,   // typeBle
            true,   // typeHybrid
            true,   // typeInt
            $userVerification
        );
        return [
            'options'   => $args,
            'challenge' => $this->webauthn->getChallenge()->getBinaryString(),
        ];
    }
}
```

- [ ] **Step 2: Smoke-test Server::registrationOptions returns the right shape**

Add to `tests/StorageTest.php` (or create `tests/ServerTest.php`):

Create `tests/ServerTest.php`:

```php
<?php declare(strict_types=1);

namespace PasskeyAuth\Tests;

use PHPUnit\Framework\TestCase;
use PasskeyAuth\Server;

final class ServerTest extends TestCase
{
    public function testRegistrationOptionsHasExpectedFields(): void
    {
        $server = new Server('Test App', 'localhost');
        $result = $server->registrationOptions(42, 'alice', 'Alice');
        $this->assertArrayHasKey('options', $result);
        $this->assertArrayHasKey('challenge', $result);
        $this->assertNotEmpty($result['challenge']);
        $opts = $result['options'];
        $this->assertObjectHasProperty('publicKey', $opts);
        $this->assertObjectHasProperty('challenge', $opts->publicKey);
        $this->assertObjectHasProperty('rp', $opts->publicKey);
        $this->assertSame('Test App', $opts->publicKey->rp->name);
        $this->assertSame('localhost', $opts->publicKey->rp->id);
    }

    public function testLoginOptionsHasExpectedFields(): void
    {
        $server = new Server('Test App', 'localhost');
        $result = $server->loginOptions();
        $this->assertArrayHasKey('options', $result);
        $this->assertArrayHasKey('challenge', $result);
        $opts = $result['options'];
        $this->assertObjectHasProperty('publicKey', $opts);
        $this->assertObjectHasProperty('challenge', $opts->publicKey);
    }
}
```

- [ ] **Step 3: Run tests**

```bash
./vendor/bin/phpunit
```

Expected: all pass. If `getCreateArgs` signature differs from assumed (lbuchs has had minor signature variations across 2.x), adjust `Server::registrationOptions` to match the installed version. Refer to `vendor/lbuchs/webauthn/src/WebAuthn.php` for the actual method signature.

---

## Task 4: Server class — verification methods

**Files:**
- Modify: `src/Server.php`

Verification methods can't be unit-tested without real attestation/assertion fixtures, so we implement them and rely on integration testing in later tasks.

**Note on lib API translation:** `processCreate`/`processGet` accept ONLY `bool` for the user-verification flag (unlike `getCreateArgs`/`getGetArgs` which accept `bool|string`). To keep the Server's public API consistent (string-based UV like the options methods), `verifyRegistration` and `verifyLogin` accept the UV policy as a string and translate via a private `uvToBool` helper: `'required'` → `true`, `'preferred'`/`'discouraged'` → `false`.

**Note on lib signature:** the installed `lbuchs/webauthn` `processCreate` signature is `processCreate($clientDataJSON, $attestationObject, $challenge, $requireUserVerification=false, $requireUserPresent=true, $failIfRootMismatch=true, $requireCtsProfileMatch=true)`. There is no `setChallenge()` method — the challenge is passed directly. Earlier draft of this plan referenced `setChallenge()` and a 5-arg `processCreate(... , true /*failIfRootMismatch*/)`; both are corrected below.

- [ ] **Step 1: Add verifyRegistration to Server.php**

```php
/**
 * Verify a registration attestation. Returns the data needed for storage.
 *
 * @param string $clientDataJson    Raw clientDataJSON bytes from the browser.
 * @param string $attestationObject Raw attestationObject bytes.
 * @param string $challenge         Original challenge bytes (server-side).
 * @param string $userVerification  'required' | 'preferred' | 'discouraged'.
 * @return array{credentialId: string, publicKey: string, signCount: int, aaguid: string|null, transports: string|null}
 */
public function verifyRegistration(
    string $clientDataJson,
    string $attestationObject,
    string $challenge,
    string $userVerification = 'preferred',
): array {
    // Note: lbuchs lib has no setChallenge(); challenge is passed directly to processCreate.
    $data = $this->webauthn->processCreate(
        $clientDataJson,
        $attestationObject,
        $challenge,
        $this->uvToBool($userVerification),  // lib accepts only bool here
        true,                                // requireUserPresent
        true,                                // failIfRootMismatch
    );

    return [
        'credentialId' => $data->credentialId,
        'publicKey'    => $data->credentialPublicKey,
        'signCount'    => (int) ($data->signatureCounter ?? 0),
        'aaguid'       => $data->AAGUID ?? null,
        'transports'   => isset($data->transports) ? json_encode($data->transports) : null,
    ];
}
```

- [ ] **Step 2: Add verifyLogin and uvToBool helper to Server.php**

```php
/**
 * Verify a login assertion against a stored credential.
 *
 * @param string      $clientDataJson    Raw clientDataJSON bytes.
 * @param string      $authenticatorData Raw authenticatorData bytes.
 * @param string      $signature         Raw signature bytes.
 * @param string|null $userHandle        Raw userHandle bytes if discoverable; else null.
 * @param string      $publicKey         Stored credential public key.
 * @param string      $challenge         Original challenge bytes.
 * @param int         $storedSignCount   Last seen signature counter for the credential.
 * @param string      $userVerification  'required' | 'preferred' | 'discouraged'.
 * @return array{signCount: int}
 * @throws \lbuchs\WebAuthn\WebAuthnException on verification failure
 */
public function verifyLogin(
    string $clientDataJson,
    string $authenticatorData,
    string $signature,
    ?string $userHandle,
    string $publicKey,
    string $challenge,
    int $storedSignCount,
    string $userVerification = 'preferred',
): array {
    // Note: lbuchs lib has no setChallenge(); challenge is passed directly to processGet.
    $data = $this->webauthn->processGet(
        $clientDataJson,
        $authenticatorData,
        $signature,
        $publicKey,
        $challenge,
        $storedSignCount,
        $this->uvToBool($userVerification),
    );

    return [
        'signCount' => (int) ($data->signatureCounter ?? $storedSignCount),
    ];
}

/**
 * Map our string user-verification preference to the bool the lib's verify methods expect.
 * Only 'required' counts as strict UV; 'preferred' and 'discouraged' both relax the check.
 */
private function uvToBool(string $userVerification): bool
{
    return strtolower($userVerification) === 'required';
}
```

- [ ] **Step 3: Run tests to confirm nothing broke**

```bash
./vendor/bin/phpunit
```

Expected: same passes; verify methods aren't tested directly here.

- [ ] **Step 4: Commit Storage + Server progress**

(no commit yet — directory is not a git repo. If user later initialises one, batch this with subsequent tasks. Note for execution: skip git commit steps until repo is present.)

---

## Task 5: Endpoints class scaffold + JSON helper

**Files:**
- Create: `src/Endpoints.php`

**Note on CSRF wiring.** PW's `SessionCSRF::hasValidToken($id, $reset)` treats its first argument as a token *id/name*, not a value, and `getTokenValue($id)` will fabricate a fresh token entry under any id passed to it — so we MUST use a fixed, server-controlled id (`'passkey-auth'`). The server obtains the canonical token value via `$session->CSRF->getTokenValue('passkey-auth')` and exposes it to the client (via login-form hook in Task 10 or markup attributes elsewhere). The client returns the value either as the `X-CSRF-Token` header or as `csrf` in the JSON body. The server validates with `hash_equals($expected, $submitted)` for constant-time comparison.

- [ ] **Step 1: Create Endpoints.php**

```php
<?php declare(strict_types=1);

namespace PasskeyAuth;

use ProcessWire\HookEvent;
use ProcessWire\User;
use ProcessWire\WireException;

final class Endpoints
{
    private const SESSION_NAMESPACE = 'PasskeyAuth';
    private const CHALLENGE_KEY = 'challenge';
    private const BANNER_DISMISSED_KEY = 'banner_dismissed';
    private const CSRF_ID = 'passkey-auth';

    public function __construct(
        private readonly Storage $storage,
        private readonly Server $server,
        private readonly \ProcessWire\Wire $wire,
        private readonly array $allowedRoleIds,
        private readonly string $userVerification,
        private readonly bool $requireResidentKey,
    ) {}

    /**
     * Set JSON content type, status code, and return the encoded body.
     */
    private function respond(array $data, int $status = 200): string
    {
        http_response_code($status);
        header('Content-Type: application/json');
        return json_encode($data, JSON_THROW_ON_ERROR);
    }

    private function error(string $message, string $code, int $status = 400): string
    {
        return $this->respond(['error' => $message, 'code' => $code], $status);
    }

    private function readJsonBody(): array
    {
        $raw = trim((string) file_get_contents('php://input'));
        if ($raw === '') return [];
        try {
            $decoded = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : [];
        } catch (\JsonException) {
            return [];
        }
    }

    private function session(): \ProcessWire\Session { return $this->wire->wire('session'); }
    private function user(): User { return $this->wire->wire('user'); }

    private function requireLoggedIn(): ?string
    {
        if (!$this->user()->isLoggedin()) {
            return $this->error('Authentication required', 'auth_required', 401);
        }
        return null;
    }

    private function requireCsrf(array $body): ?string
    {
        $submitted = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($body['csrf'] ?? '');
        $submitted = is_string($submitted) ? trim($submitted) : '';
        if ($submitted === '') {
            return $this->error('Invalid session', 'invalid_csrf', 403);
        }
        $expected = $this->wire->wire('session')->CSRF->getTokenValue(self::CSRF_ID);
        if (!is_string($expected) || $expected === '' || !hash_equals($expected, $submitted)) {
            return $this->error('Invalid session', 'invalid_csrf', 403);
        }
        return null;
    }

    /** Targeted user for management endpoints; superuser-gated for cross-user. */
    private function targetUser(?int $userId): ?User
    {
        $current = $this->user();
        if ($userId === null || $userId === $current->id) return $current;
        if (!$current->isSuperuser()) return null;
        $target = $this->wire->wire('users')->get($userId);
        return ($target && $target->id) ? $target : null;
    }

    private function isAllowedByRole(User $user): bool
    {
        if (empty($this->allowedRoleIds)) return false;
        foreach ($user->roles as $role) {
            if (in_array($role->id, $this->allowedRoleIds, true)) return true;
        }
        return false;
    }

    /**
     * Strict base64url decoder. WebAuthn `cred.toJSON()` produces base64url
     * (uses `-_` instead of `+/`, no padding). Returns null for malformed input.
     */
    private function base64UrlDecode(string $s): ?string
    {
        if ($s === '') return null;
        $b64 = strtr($s, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) $b64 .= str_repeat('=', 4 - $pad);
        $decoded = base64_decode($b64, true);
        return $decoded === false ? null : $decoded;
    }

    private function clearRegistrationSession(): void
    {
        $this->session()->removeFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY);
        $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_user_id');
        $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_name');
    }

    // Endpoint methods added in subsequent tasks.
}
```

---

## Task 6: Registration endpoints

**Files:**
- Modify: `src/Endpoints.php` — add `registerOptions` and `registerFinish` methods

- [ ] **Step 1: Add registerOptions**

```php
public function registerOptions(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $current = $this->user();
    $userId = isset($body['userId']) ? (int) $body['userId'] : $current->id;
    $target = $this->targetUser($userId);
    if (!$target) return $this->error('Forbidden', 'forbidden', 403);

    if (!$this->isAllowedByRole($target)) {
        return $this->error('User not permitted to register passkeys', 'role_denied', 403);
    }

    $existing = $this->storage->listForUser($target->id);
    $excludeIds = array_map(fn($r) => (string) $r['credential_id'], $existing);

    $name = trim((string) ($body['name'] ?? ''));
    if ($name === '') $name = 'Passkey added ' . date('Y-m-d');

    $result = $this->server->registrationOptions(
        $target->id,
        $target->name,
        $target->name,  // displayName — could be made configurable later
        $excludeIds,
        $this->userVerification,
        $this->requireResidentKey,
    );

    $this->session()->setFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY, $result['challenge']);
    $this->session()->setFor(self::SESSION_NAMESPACE, 'register_user_id', $target->id);
    $this->session()->setFor(self::SESSION_NAMESPACE, 'register_name', $name);

    return $this->respond(['options' => $result['options']]);
}
```

- [ ] **Step 2: Add registerFinish**

```php
public function registerFinish(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $challenge = $this->session()->getFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY);
    $userId    = (int) $this->session()->getFor(self::SESSION_NAMESPACE, 'register_user_id');
    $name      = (string) $this->session()->getFor(self::SESSION_NAMESPACE, 'register_name');
    if (!$challenge || !$userId) {
        return $this->error('No registration in progress', 'no_session', 400);
    }

    $cred = $body['credential'] ?? null;
    if (!is_array($cred)) return $this->error('Missing credential', 'missing_credential', 400);

    $clientDataJson    = base64_decode((string) ($cred['response']['clientDataJSON'] ?? ''));
    $attestationObject = base64_decode((string) ($cred['response']['attestationObject'] ?? ''));
    if (!$clientDataJson || !$attestationObject) {
        return $this->error('Invalid credential payload', 'invalid_payload', 400);
    }

    try {
        $verified = $this->server->verifyRegistration($clientDataJson, $attestationObject, $challenge, $this->userVerification);
    } catch (\Throwable $e) {
        $this->wire->wire('log')->save('passkey-auth', 'verifyRegistration failed: ' . $e->getMessage());
        return $this->error('Verification failed', 'verify_failed', 400);
    }

    $id = $this->storage->add($userId, [
        'credential_id' => $verified['credentialId'],
        'public_key'    => $verified['publicKey'],
        'sign_count'    => $verified['signCount'],
        'name'          => $name,
        'aaguid'        => $verified['aaguid'],
        'transports'    => $verified['transports'],
    ]);

    // Clear session state
    $this->session()->removeFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY);
    $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_user_id');
    $this->session()->removeFor(self::SESSION_NAMESPACE, 'register_name');

    return $this->respond([
        'ok' => true,
        'passkey' => [
            'id' => $id,
            'name' => $name,
        ],
    ]);
}
```

- [ ] **Step 3: Smoke-check by reading the methods aloud** — no test runnable yet (need PW context).

---

## Task 7: Login endpoints

**Files:**
- Modify: `src/Endpoints.php` — add `loginOptions`, `loginFinish`

- [ ] **Step 1: Add loginOptions**

```php
public function loginOptions(HookEvent $event): string
{
    // No auth required (pre-login). No CSRF (challenge replaces it).
    $result = $this->server->loginOptions([], $this->userVerification);

    $this->session()->setFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY, $result['challenge']);

    return $this->respond(['options' => $result['options']]);
}
```

- [ ] **Step 2: Add loginFinish**

```php
public function loginFinish(HookEvent $event): string
{
    $body = $this->readJsonBody();
    $cred = $body['credential'] ?? null;
    if (!is_array($cred)) return $this->error('Authentication failed', 'auth_failed', 400);

    $challenge = $this->session()->getFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY);
    if (!$challenge) return $this->error('Authentication failed', 'auth_failed', 400);

    $response = $cred['response'] ?? null;
    if (!is_array($response)) return $this->error('Authentication failed', 'auth_failed', 400);

    $rawId             = $this->base64UrlDecode((string) ($cred['rawId'] ?? ''));
    $clientDataJson    = $this->base64UrlDecode((string) ($response['clientDataJSON'] ?? ''));
    $authenticatorData = $this->base64UrlDecode((string) ($response['authenticatorData'] ?? ''));
    $signature         = $this->base64UrlDecode((string) ($response['signature'] ?? ''));
    $userHandleRaw     = $response['userHandle'] ?? null;
    $userHandle        = is_string($userHandleRaw) && $userHandleRaw !== '' ? $this->base64UrlDecode($userHandleRaw) : null;

    if ($rawId === null || $clientDataJson === null || $authenticatorData === null || $signature === null) {
        return $this->error('Authentication failed', 'auth_failed', 400);
    }

    $row = $this->storage->findByCredentialId($rawId);
    if (!$row) return $this->error('Authentication failed', 'auth_failed', 400);

    try {
        $verified = $this->server->verifyLogin(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $userHandle,
            (string) $row['public_key'],
            $challenge,
            (int) $row['sign_count'],
            $this->userVerification,
        );
    } catch (\Throwable $e) {
        $this->wire->wire('log')->save('passkey-auth', 'verifyLogin failed: ' . $e->getMessage());
        return $this->error('Authentication failed', 'auth_failed', 400);
    }

    $userId = (int) $row['user_id'];
    $user = $this->wire->wire('users')->get($userId);
    if (!$user || !$user->id) return $this->error('Authentication failed', 'auth_failed', 400);
    if (!$this->isAllowedByRole($user)) return $this->error('Authentication failed', 'auth_failed', 403);

    // Counter-regression check: warn but don't reject (iCloud reports 0 reliably).
    if ($verified['signCount'] !== 0 && $verified['signCount'] <= (int) $row['sign_count']) {
        $this->wire->wire('log')->save(
            'passkey-auth',
            "WARN: counter regression for credential id={$row['id']} stored={$row['sign_count']} got={$verified['signCount']}"
        );
    }

    $this->storage->touchLastUsed((int) $row['id'], $verified['signCount']);
    $this->session()->removeFor(self::SESSION_NAMESPACE, self::CHALLENGE_KEY);
    $this->wire->wire('session')->forceLogin($user);

    return $this->respond([
        'ok' => true,
        'redirect' => $this->wire->wire('config')->urls->admin,
    ]);
}
```

---

## Task 8: Management endpoints

**Files:**
- Modify: `src/Endpoints.php` — add `list`, `rename`, `delete`, `bannerDismiss`

- [ ] **Step 1: Add list**

```php
public function list(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $userId = isset($body['userId']) ? (int) $body['userId'] : null;
    $target = $this->targetUser($userId);
    if (!$target) return $this->error('Forbidden', 'forbidden', 403);

    $rows = $this->storage->listForUser($target->id);
    $out = array_map(fn($r) => [
        'id'       => (int) $r['id'],
        'name'     => $r['name'],
        'created'  => $r['created'],
        'lastUsed' => $r['last_used'],
        'aaguid'   => $r['aaguid'],
    ], $rows);

    return $this->respond(['passkeys' => $out]);
}
```

- [ ] **Step 2: Add rename**

```php
public function rename(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $id   = (int) ($body['id'] ?? 0);
    $name = trim((string) ($body['name'] ?? ''));
    if (!$id || $name === '') return $this->error('Invalid input', 'invalid_input', 400);

    $row = $this->storage->findById($id);
    if (!$row) return $this->error('Not found', 'not_found', 404);
    $target = $this->targetUser((int) $row['user_id']);
    if (!$target) return $this->error('Forbidden', 'forbidden', 403);

    $this->storage->rename($id, $name);
    return $this->respond(['ok' => true]);
}
```

- [ ] **Step 3: Add delete**

```php
public function delete(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $id = (int) ($body['id'] ?? 0);
    if (!$id) return $this->error('Invalid input', 'invalid_input', 400);

    $row = $this->storage->findById($id);
    if (!$row) return $this->error('Not found', 'not_found', 404);
    $target = $this->targetUser((int) $row['user_id']);
    if (!$target) return $this->error('Forbidden', 'forbidden', 403);

    $this->storage->delete($id);
    return $this->respond(['ok' => true]);
}
```

- [ ] **Step 4: Add bannerDismiss**

```php
public function bannerDismiss(HookEvent $event): string
{
    if ($err = $this->requireLoggedIn()) return $err;
    $body = $this->readJsonBody();
    if ($err = $this->requireCsrf($body)) return $err;

    $this->session()->setFor(self::SESSION_NAMESPACE, self::BANNER_DISMISSED_KEY, 1);
    return $this->respond(['ok' => true]);
}
```

---

## Task 9: Wire URL hooks in PasskeyAuth.module.php

**Files:**
- Modify: `PasskeyAuth.module.php` — flesh out `init()` to register URL hooks

- [ ] **Step 1: Add a private method to build the Endpoints instance**

Add to `PasskeyAuth.module.php`:

```php
private ?Endpoints $endpoints = null;

private function endpoints(): Endpoints
{
    if ($this->endpoints) return $this->endpoints;

    $config = $this->wire('config');
    $rpName = $this->appName ?: $config->httpHost;
    $rpId   = $this->rpId    ?: $config->httpHost;

    $storage  = new \PasskeyAuth\Storage($this->wire('database'), self::TABLE_NAME);
    $server   = new \PasskeyAuth\Server($rpName, $rpId);
    $allowedRoleIds = array_map('intval', (array) ($this->allowedRoles ?: []));

    $this->endpoints = new \PasskeyAuth\Endpoints(
        $storage,
        $server,
        $this,
        $allowedRoleIds,
        (string) $this->userVerification,
        $this->residentKeyRequirement === 'required',
    );
    return $this->endpoints;
}
```

- [ ] **Step 2: Register URL hooks in init()**

Replace `init()`:

```php
public function init(): void
{
    $prefix = '/' . trim((string) $this->apiUrlPrefix, '/');

    $hook = function(string $action, string $method) use ($prefix) {
        $this->wire()->addHook("{$prefix}/{$action}", function($event) use ($method) {
            return $this->endpoints()->{$method}($event);
        });
    };

    $hook('register/options', 'registerOptions');
    $hook('register/finish',  'registerFinish');
    $hook('login/options',    'loginOptions');
    $hook('login/finish',     'loginFinish');
    $hook('list',             'list');
    $hook('rename',           'rename');
    $hook('delete',           'delete');
    $hook('banner/dismiss',   'bannerDismiss');
}
```

- [ ] **Step 3: Add `use` statements at top**

At top of `PasskeyAuth.module.php`, after the namespace declaration:

```php
use PasskeyAuth\Endpoints;
```

- [ ] **Step 4: Smoke test in browser**

After Modules → Refresh, hit the endpoint:

```bash
curl -i https://griefcoach.test/passkey-auth/login/options -X POST -H "Content-Type: application/json" -d '{}'
```

Expected: `200 OK`, `Content-Type: application/json`, body contains `"options"` with `publicKey.challenge`.

If it returns the site's 404 HTML, the hook isn't firing — refresh modules and ensure the module is autoloaded.

---

## Task 10: Login form hook + JS + CSS

**Files:**
- Modify: `PasskeyAuth.module.php` — add `addLoginButton` hook
- Create: `PasskeyAuth.js` (initial scaffold + `mode: 'login'`)
- Create: `PasskeyAuth.css`

- [ ] **Step 1: Add ProcessLogin hook in init()**

In `PasskeyAuth.module.php` `init()`, add:

```php
$this->addHookAfter('ProcessLogin::buildLoginForm', $this, 'addLoginButton');
```

- [ ] **Step 2: Add addLoginButton method**

```php
public function addLoginButton(HookEvent $event): void
{
    $form    = $event->return;
    $modules = $this->wire('modules');
    $config  = $this->wire('config');

    // Tag the username input for autofill
    $userField = $form->getChildByName('login_name');
    if ($userField) {
        $userField->attr('autocomplete', 'username webauthn');
    }

    $markup = $modules->get('InputfieldMarkup');
    $markup->name = 'passkey_auth_login';
    $markup->value = '
        <div class="passkey-auth-login">
            <button type="button" id="passkey-auth-signin" class="ui-button">Sign in with passkey</button>
            <p class="passkey-auth-status" role="status" aria-live="polite"></p>
        </div>';
    $form->add($markup);

    $jsUrl  = $config->urls($this) . 'PasskeyAuth.js';
    $cssUrl = $config->urls($this) . 'PasskeyAuth.css';
    $apiUrl = '/' . trim((string) $this->apiUrlPrefix, '/') . '/';

    $config->styles->add($cssUrl);

    $scriptMarkup = $modules->get('InputfieldMarkup');
    $scriptMarkup->name = 'passkey_auth_login_js';
    $scriptMarkup->value = '
        <script>window.PasskeyAuth = ' . json_encode([
            'apiUrl' => $apiUrl,
            'mode'   => 'login',
        ]) . ';</script>
        <script src="' . htmlspecialchars($jsUrl) . '" defer></script>';
    $form->add($scriptMarkup);
}
```

- [ ] **Step 3: Create PasskeyAuth.js scaffold**

`/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/PasskeyAuth.js`:

```js
(function() {
    'use strict';
    const cfg = window.PasskeyAuth || {};
    if (!cfg.apiUrl || !cfg.mode) return;

    // ---- Helpers ----
    const b64uToBytes = (str) => {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        const bin = atob(str);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
    };
    const bytesToB64 = (buf) => {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    };

    async function postJSON(path, body = {}) {
        const res = await fetch(cfg.apiUrl + path, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': cfg.csrf || '',
            },
            credentials: 'same-origin',
            body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => null);
        if (!res.ok || !data) throw new Error((data && data.error) || 'Request failed');
        return data;
    }

    function decodePublicKeyOptions(opts) {
        // opts.publicKey.challenge / user.id / excludeCredentials[].id / allowCredentials[].id are base64
        const pk = opts.publicKey;
        if (typeof pk.challenge === 'string') pk.challenge = b64uToBytes(pk.challenge);
        if (pk.user && typeof pk.user.id === 'string') pk.user.id = b64uToBytes(pk.user.id);
        if (Array.isArray(pk.excludeCredentials)) {
            pk.excludeCredentials.forEach(c => { if (typeof c.id === 'string') c.id = b64uToBytes(c.id); });
        }
        if (Array.isArray(pk.allowCredentials)) {
            pk.allowCredentials.forEach(c => { if (typeof c.id === 'string') c.id = b64uToBytes(c.id); });
        }
        return opts;
    }

    function serializeAssertion(cred) {
        return {
            id: cred.id,
            rawId: bytesToB64(cred.rawId),
            type: cred.type,
            response: {
                clientDataJSON:    bytesToB64(cred.response.clientDataJSON),
                authenticatorData: bytesToB64(cred.response.authenticatorData),
                signature:         bytesToB64(cred.response.signature),
                userHandle:        cred.response.userHandle ? bytesToB64(cred.response.userHandle) : null,
            },
        };
    }

    function serializeAttestation(cred) {
        return {
            id: cred.id,
            rawId: bytesToB64(cred.rawId),
            type: cred.type,
            response: {
                clientDataJSON:     bytesToB64(cred.response.clientDataJSON),
                attestationObject:  bytesToB64(cred.response.attestationObject),
            },
        };
    }

    // ---- Mode dispatch ----
    document.addEventListener('DOMContentLoaded', () => {
        if (cfg.mode === 'login')   initLogin();
        if (cfg.mode === 'banner')  initBanner();
        if (cfg.mode === 'manage')  initManage();
    });

    // ---- Login mode ----
    async function initLogin() {
        const btn    = document.getElementById('passkey-auth-signin');
        const status = document.querySelector('.passkey-auth-status');
        if (!btn) return;

        if (!window.PublicKeyCredential) {
            btn.style.display = 'none';
            return;
        }

        const setStatus = (msg) => { if (status) status.textContent = msg || ''; };
        const fail = () => setStatus('Authentication failed — try password instead.');

        const abortCtl = new AbortController();
        let conditionalRunning = false;

        // Start conditional UI if available
        if (PublicKeyCredential.isConditionalMediationAvailable
            && await PublicKeyCredential.isConditionalMediationAvailable()) {
            try {
                conditionalRunning = true;
                const optsRes = await postJSON('login/options');
                const opts = decodePublicKeyOptions({ publicKey: optsRes.options.publicKey });
                navigator.credentials.get({
                    mediation: 'conditional',
                    publicKey: opts.publicKey,
                    signal: abortCtl.signal,
                }).then(async (cred) => {
                    if (!cred) return;
                    await finishLogin(cred);
                }).catch(() => {});
            } catch (e) {
                // ignore — fall through to button
            }
        }

        btn.addEventListener('click', async () => {
            btn.disabled = true;
            setStatus('');
            if (conditionalRunning) abortCtl.abort();
            try {
                const optsRes = await postJSON('login/options');
                const opts = decodePublicKeyOptions({ publicKey: optsRes.options.publicKey });
                const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
                await finishLogin(cred);
            } catch (e) {
                fail();
                btn.disabled = false;
            }
        });
    }

    async function finishLogin(cred) {
        const result = await postJSON('login/finish', {
            credential: serializeAssertion(cred),
        });
        if (result.ok && result.redirect) window.location.href = result.redirect;
    }

    // ---- Banner / Manage stubs (filled in later tasks) ----
    function initBanner() { /* Task 11 */ }
    function initManage() { /* Task 12 */ }
})();
```

- [ ] **Step 4: Create PasskeyAuth.css**

`/Users/adrianjones/Sites/griefcoach.test/site/modules/PasskeyAuth/PasskeyAuth.css`:

```css
.passkey-auth-login { margin-top: 1em; }
.passkey-auth-status { margin-top: .5em; min-height: 1.4em; color: #c00; }

.passkey-auth-banner {
    position: fixed; top: 0; left: 0; right: 0; z-index: 10000;
    display: flex; align-items: center; gap: .75em;
    padding: .75em 1em;
    background: #fff8c5; color: #24292f;
    border-bottom: 1px solid #d0a800;
    font-size: 14px;
}
.passkey-auth-banner__icon { font-size: 18px; }
.passkey-auth-banner__text { flex: 1; }
.passkey-auth-banner button { cursor: pointer; }

.passkey-auth-manage { margin-top: .5em; }
.passkey-auth-list { list-style: none; padding: 0; margin: 0 0 1em; }
.passkey-auth-list li {
    display: flex; align-items: center; gap: 1em;
    padding: .5em 0; border-bottom: 1px solid #eee;
}
.passkey-auth-list li:last-child { border-bottom: none; }
```

- [ ] **Step 5: Manual smoke test**

1. Refresh modules in PW admin.
2. Log out.
3. Visit `/htgc-admin/login/`.
4. Confirm:
   - "Sign in with passkey" button is visible below the password field.
   - Username field has `autocomplete="username webauthn"` (inspect element).
5. With **no passkeys registered yet**, clicking the button should produce a generic error message and not crash.

---

## Task 11: Banner hook + banner mode JS

**Files:**
- Modify: `PasskeyAuth.module.php` — add `injectBanner` hook
- Modify: `PasskeyAuth.js` — implement `initBanner`

- [ ] **Step 1: Add Page::render hook in init()**

Add to `init()`:

```php
$this->addHookAfter('Page::render', $this, 'injectBanner');
```

- [ ] **Step 2: Implement injectBanner**

In `PasskeyAuth.module.php`:

```php
public function injectBanner(HookEvent $event): void
{
    $page = $event->object;
    if (!$page || $page->template->name !== 'admin') return;
    if (!$this->bannerEnabled) return;

    $user = $this->wire('user');
    if (!$user->isLoggedin()) return;

    $allowedRoleIds = array_map('intval', (array) ($this->allowedRoles ?: []));
    $allowed = false;
    foreach ($user->roles as $r) {
        if (in_array($r->id, $allowedRoleIds, true)) { $allowed = true; break; }
    }
    if (!$allowed) return;

    $session = $this->wire('session');
    if ($session->getFor('PasskeyAuth', 'banner_dismissed')) return;

    $storage = new \PasskeyAuth\Storage($this->wire('database'), self::TABLE_NAME);
    if ($storage->countForUser($user->id) > 0) return;

    $config = $this->wire('config');
    $apiUrl = '/' . trim((string) $this->apiUrlPrefix, '/') . '/';
    $jsUrl  = $config->urls($this) . 'PasskeyAuth.js';
    $cssUrl = $config->urls($this) . 'PasskeyAuth.css';
    $csrf   = $session->CSRF->getTokenValue('passkey-auth');

    $banner = '<link rel="stylesheet" href="' . htmlspecialchars($cssUrl) . '">'
            . '<div class="passkey-auth-banner" data-passkey-auth-banner>'
            . '<span class="passkey-auth-banner__icon">🔑</span>'
            . '<span class="passkey-auth-banner__text">Add a passkey for faster, more secure sign-in.</span>'
            . '<button type="button" data-passkey-auth-action="register">Set up</button>'
            . '<button type="button" data-passkey-auth-action="dismiss" aria-label="Dismiss">×</button>'
            . '</div>'
            . '<script>window.PasskeyAuth = ' . json_encode([
                'apiUrl' => $apiUrl,
                'mode'   => 'banner',
                'csrf'   => $csrf,
                'userName' => $user->name,
            ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) . ';</script>'
            . '<script src="' . htmlspecialchars($jsUrl) . '" defer></script>';

    $event->return = str_ireplace('</body>', $banner . '</body>', (string) $event->return);
}
```

- [ ] **Step 3: Implement initBanner in PasskeyAuth.js**

Replace `function initBanner() { /* Task 11 */ }` with:

```js
async function initBanner() {
    const banner = document.querySelector('[data-passkey-auth-banner]');
    if (!banner) return;

    banner.querySelector('[data-passkey-auth-action="dismiss"]').addEventListener('click', async () => {
        try { await postJSON('banner/dismiss'); } catch (e) {}
        banner.remove();
    });

    banner.querySelector('[data-passkey-auth-action="register"]').addEventListener('click', async () => {
        const defaultName = guessDeviceName();
        const name = prompt('Name this passkey:', defaultName);
        if (!name) return;
        try {
            await registrationFlow(name);
            banner.innerHTML = '<span class="passkey-auth-banner__text">✓ Passkey added</span>';
            setTimeout(() => banner.remove(), 3000);
        } catch (e) {
            const status = document.createElement('span');
            status.style.color = '#c00';
            status.textContent = ' Could not add passkey: ' + (e.message || 'unknown error');
            banner.appendChild(status);
        }
    });
}

function guessDeviceName() {
    const ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua))   return 'iPad';
    if (/Mac OS X/.test(ua)) return 'Mac';
    if (/Android/.test(ua)) return 'Android';
    if (/Windows/.test(ua)) return 'Windows';
    return 'My device';
}

async function registrationFlow(name, userId = null) {
    const optsRes = await postJSON('register/options', { name, userId });
    const opts = decodePublicKeyOptions({ publicKey: optsRes.options.publicKey });
    const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
    return await postJSON('register/finish', {
        name, userId, credential: serializeAttestation(cred),
    });
}
```

- [ ] **Step 4: Manual smoke test**

1. Refresh modules.
2. Log into admin as a superuser (with no passkeys).
3. Confirm yellow banner appears at top.
4. Click "×" → banner removes; reload → banner stays gone (session-scoped).
5. Open another browser/incognito, log in, click "Set up" → enter name → biometric/PIN prompt → success message → banner fades.
6. Verify a row was added to `passkey_auth`:
   ```bash
   mysql -u <user> -p <db> -e "SELECT id, user_id, name, created FROM passkey_auth;"
   ```

---

## Task 12: Management UI hook + manage mode JS

**Files:**
- Modify: `PasskeyAuth.module.php` — add hooks for ProcessUser/ProcessProfile
- Modify: `PasskeyAuth.js` — implement `initManage`

- [ ] **Step 1: Add hooks in init()**

```php
$this->addHookAfter('ProcessUser::buildEditForm', $this, 'addManageFieldset');
$this->addHookAfter('ProcessProfile::buildForm',  $this, 'addManageFieldset');
```

- [ ] **Step 2: Implement addManageFieldset**

```php
public function addManageFieldset(HookEvent $event): void
{
    $form = $event->return;
    if (!$form) return;

    $process = $event->object;
    $current = $this->wire('user');

    // Determine which user we're editing
    if ($process instanceof \ProcessWire\ProcessProfile) {
        $editedUser = $current;
    } else {
        $editedUser = method_exists($process, 'getEditedUser')
            ? $process->getEditedUser()
            : $current;
    }
    if (!$editedUser || !$editedUser->id) return;

    // Permission: superuser may edit anyone; otherwise only self
    if (!$current->isSuperuser() && $editedUser->id !== $current->id) return;

    $modules = $this->wire('modules');
    $config  = $this->wire('config');
    $session = $this->wire('session');

    $storage = new \PasskeyAuth\Storage($this->wire('database'), self::TABLE_NAME);
    $count   = $storage->countForUser($editedUser->id);

    $fieldset = $modules->get('InputfieldFieldset');
    $fieldset->name = 'passkey_auth_manage';
    $fieldset->label = 'Passkeys';
    $fieldset->icon = 'key';
    $fieldset->collapsed = $count > 0
        ? \ProcessWire\Inputfield::collapsedNo
        : \ProcessWire\Inputfield::collapsedYes;

    $apiUrl = '/' . trim((string) $this->apiUrlPrefix, '/') . '/';
    $jsUrl  = $config->urls($this) . 'PasskeyAuth.js';
    $cssUrl = $config->urls($this) . 'PasskeyAuth.css';
    $csrf   = $session->CSRF->getTokenValue('passkey-auth');

    $markup = $modules->get('InputfieldMarkup');
    $markup->name = 'passkey_auth_manage_markup';
    $markup->value = '<link rel="stylesheet" href="' . htmlspecialchars($cssUrl) . '">'
        . '<div class="passkey-auth-manage" data-user-id="' . (int) $editedUser->id . '">'
        . '<ul class="passkey-auth-list"></ul>'
        . '<button type="button" data-passkey-auth-action="add" class="ui-button">Add a passkey</button>'
        . '<p class="passkey-auth-status" role="status" aria-live="polite"></p>'
        . '</div>'
        . '<script>window.PasskeyAuth = ' . json_encode([
            'apiUrl' => $apiUrl,
            'mode'   => 'manage',
            'csrf'   => $csrf,
            'userId' => (int) $editedUser->id,
            'userName' => $editedUser->name,
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) . ';</script>'
        . '<script src="' . htmlspecialchars($jsUrl) . '" defer></script>';
    $fieldset->add($markup);

    $form->add($fieldset);
}
```

- [ ] **Step 3: Implement initManage in PasskeyAuth.js**

Replace `function initManage() { /* Task 12 */ }` with:

```js
async function initManage() {
    const root = document.querySelector('.passkey-auth-manage');
    if (!root) return;
    const userId = parseInt(root.dataset.userId, 10) || null;
    const list = root.querySelector('.passkey-auth-list');
    const status = root.querySelector('.passkey-auth-status');
    const addBtn = root.querySelector('[data-passkey-auth-action="add"]');

    function setStatus(msg, isErr = false) {
        status.textContent = msg || '';
        status.style.color = isErr ? '#c00' : '';
    }

    function renderRow(p) {
        const li = document.createElement('li');
        li.dataset.id = p.id;
        const name = document.createElement('span');
        name.className = 'passkey-auth-name';
        name.textContent = p.name;
        name.title = 'Click to rename';
        name.addEventListener('click', () => beginRename(p.id, name));
        const meta = document.createElement('span');
        meta.className = 'passkey-auth-meta';
        meta.textContent = ' · added ' + (p.created || '').split(' ')[0]
            + (p.lastUsed ? ', last used ' + p.lastUsed.split(' ')[0] : ', never used');
        const del = document.createElement('button');
        del.type = 'button';
        del.textContent = 'Delete';
        del.addEventListener('click', () => doDelete(p.id, li));
        li.append(name, meta, del);
        return li;
    }

    function beginRename(id, span) {
        const input = document.createElement('input');
        input.type = 'text';
        input.value = span.textContent;
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') input.blur();
            if (e.key === 'Escape') { input.value = span.textContent; input.blur(); cancelled = true; }
        });
        let cancelled = false;
        input.addEventListener('blur', async () => {
            if (cancelled) { input.replaceWith(span); return; }
            const newName = input.value.trim();
            if (!newName || newName === span.textContent) { input.replaceWith(span); return; }
            try {
                await postJSON('rename', { id, name: newName, userId });
                span.textContent = newName;
                input.replaceWith(span);
            } catch (e) {
                setStatus('Rename failed', true);
                input.replaceWith(span);
            }
        });
        span.replaceWith(input);
        input.focus();
        input.select();
    }

    async function doDelete(id, li) {
        if (!confirm('Delete this passkey?')) return;
        try {
            await postJSON('delete', { id, userId });
            li.remove();
        } catch (e) {
            setStatus('Delete failed', true);
        }
    }

    async function load() {
        list.innerHTML = '';
        try {
            const res = await postJSON('list', { userId });
            (res.passkeys || []).forEach(p => list.appendChild(renderRow(p)));
        } catch (e) {
            setStatus('Could not load passkeys', true);
        }
    }

    addBtn.addEventListener('click', async () => {
        const defaultName = guessDeviceName();
        const name = prompt('Name this passkey:', defaultName);
        if (!name) return;
        setStatus('');
        try {
            await registrationFlow(name, userId);
            await load();
        } catch (e) {
            setStatus('Could not add passkey: ' + (e.message || 'unknown'), true);
        }
    });

    await load();
}
```

- [ ] **Step 4: Manual smoke test**

1. Refresh modules.
2. As superuser, navigate to `/htgc-admin/profile/`.
3. Confirm "Passkeys" fieldset appears.
4. Click "Add a passkey" → registers a new credential → list updates with the new entry.
5. Click on the name → rename → press Enter → verify rename persists after reload.
6. Click "Delete" → confirm → row removes; verify in DB.
7. Navigate to `/htgc-admin/access/users/edit/?id=N` for another user → confirm fieldset shows that user's passkeys (and that as superuser you can manage them).
8. As a non-superuser, confirm: editing your own profile shows the fieldset; editing another user (if even reachable) does NOT.

---

## Task 13: Module config screen

**Files:**
- Modify: `PasskeyAuth.module.php` — flesh out `getModuleConfigInputfields`

- [ ] **Step 1: Replace stub with real config fields**

```php
public function getModuleConfigInputfields(array $data)
{
    $modules = $this->wire('modules');
    $config  = $this->wire('config');
    $roles   = $this->wire('roles');
    $fields  = new InputfieldWrapper();

    $f = $modules->get('InputfieldText');
    $f->name = 'apiUrlPrefix';
    $f->label = 'API URL prefix';
    $f->description = 'Where the URL hooks register. Must start and end with /.';
    $f->value = $data['apiUrlPrefix'] ?? '/passkey-auth/';
    $f->required = true;
    $fields->add($f);

    $f = $modules->get('InputfieldText');
    $f->name = 'appName';
    $f->label = 'Application name';
    $f->description = 'Friendly name shown in the OS biometric prompt. Defaults to host.';
    $f->value = $data['appName'] ?? '';
    $f->placeholder = $config->httpHost;
    $fields->add($f);

    $f = $modules->get('InputfieldText');
    $f->name = 'rpId';
    $f->label = 'Relying Party ID';
    $f->description = 'Hostname WebAuthn binds credentials to. Must match origin host. **Do not change** after passkeys are registered.';
    $f->value = $data['rpId'] ?? '';
    $f->placeholder = $config->httpHost;
    $fields->add($f);

    $f = $modules->get('InputfieldCheckboxes');
    $f->name = 'allowedRoles';
    $f->label = 'Allowed roles';
    $f->description = 'Only users with at least one of these roles can register or use passkeys.';
    foreach ($roles->find('limit=200') as $role) {
        if ($role->id === $config->guestUserRolePageID) continue;
        $f->addOption($role->id, $role->name);
    }
    if (!empty($data['allowedRoles'])) $f->attr('value', $data['allowedRoles']);
    $fields->add($f);

    $f = $modules->get('InputfieldRadios');
    $f->name = 'userVerification';
    $f->label = 'User verification';
    $f->addOption('discouraged', 'Discouraged');
    $f->addOption('preferred', 'Preferred (default)');
    $f->addOption('required', 'Required');
    $f->value = $data['userVerification'] ?? 'preferred';
    $fields->add($f);

    $f = $modules->get('InputfieldRadios');
    $f->name = 'residentKeyRequirement';
    $f->label = 'Resident key (discoverable credentials) requirement';
    $f->description = 'Required is needed for the autofill flow.';
    $f->addOption('discouraged', 'Discouraged');
    $f->addOption('preferred', 'Preferred');
    $f->addOption('required', 'Required (default)');
    $f->value = $data['residentKeyRequirement'] ?? 'required';
    $fields->add($f);

    $f = $modules->get('InputfieldCheckbox');
    $f->name = 'bannerEnabled';
    $f->label = 'Show registration banner';
    $f->description = 'Auto-prompt logged-in admins without passkeys to register one.';
    if (!empty($data['bannerEnabled'])) $f->attr('checked', 'checked');
    $fields->add($f);

    return $fields;
}
```

- [ ] **Step 2: Manual smoke test**

1. Modules → Passkey Auth → Module Settings.
2. Confirm all fields render.
3. Set `Allowed roles` to `superuser`, save.
4. Reload — confirm value persists.
5. Confirm `appName` and `rpId` show the host as placeholder when blank.

---

## Task 14: End-to-end manual test pass + final cleanup

**Files:** none (verification + tidy)

This task verifies the whole flow end-to-end on the local site at `https://griefcoach.test/`.

- [ ] **Step 1: Fresh install verification**

1. Uninstall PasskeyAuth.
2. Confirm `passkey_auth` table is dropped:
   ```bash
   mysql -e "SHOW TABLES LIKE 'passkey_auth';" <db>   # should be empty
   ```
3. Reinstall.
4. Configure `appName=GriefCoach Admin`, `rpId=griefcoach.test`, `allowedRoles=[superuser]`.

- [ ] **Step 2: First-time registration via banner**

1. Log in to admin as superuser (using existing password).
2. Verify yellow banner appears.
3. Click "Set up" → name "Mac Touch ID" → biometric → success.
4. Verify in DB:
   ```bash
   mysql -e "SELECT id, user_id, name, sign_count, created FROM passkey_auth;" <db>
   ```
   One row, sign_count=0 (or counter), name="Mac Touch ID".

- [ ] **Step 3: Login flow (autofill)**

1. Log out.
2. Visit `/htgc-admin/login/`.
3. Click into username field. Confirm browser shows passkey suggestion in autofill dropdown (Chrome/Safari).
4. Pick the suggestion → biometric → redirected to `/htgc-admin/`.
5. Verify `last_used` timestamp on the row updated.

- [ ] **Step 4: Login flow (button)**

1. Log out, reload login page.
2. Click "Sign in with passkey" button.
3. Modal credential picker appears → pick → biometric → redirected to admin.

- [ ] **Step 5: Add a second passkey via management UI**

1. While logged in, go to `/htgc-admin/profile/`.
2. Open "Passkeys" fieldset.
3. Click "Add a passkey" → name "YubiKey" or "iPhone" → register.
4. Confirm two rows in `passkey_auth`.
5. Rename, delete, verify behaviour.

- [ ] **Step 6: Cross-user management as superuser**

1. As superuser, edit another user with allowed role → register passkey on their behalf (using YOUR authenticator — they'll need to do their own real-world registration; this is just permission testing).
2. Confirm row added with that user's `user_id`.
3. As a non-superuser admin (if applicable), confirm you cannot see another user's passkey fieldset.

- [ ] **Step 7: Banner dismissal**

1. As a user with no passkeys, log in → banner appears.
2. Click "×" → banner removes.
3. Navigate to another admin page → banner stays gone.
4. Log out, log back in → banner reappears (session-scoped dismissal).

- [ ] **Step 8: Counter-regression warning**

(Optional, if you have an authenticator with non-zero counter)

1. Log in via passkey.
2. Manually `UPDATE passkey_auth SET sign_count = 9999 WHERE id = N;`
3. Log out, log back in via same passkey.
4. Check `/site/assets/logs/passkey-auth.txt` for "WARN: counter regression" entry.
5. Confirm login still succeeds (warn but don't reject).

- [ ] **Step 9: Uninstall + reinstall safety**

1. Register a passkey, then uninstall.
2. Confirm tables dropped.
3. Reinstall.
4. Confirm `passkey_auth` exists, is empty.

- [ ] **Step 10: Production deployment plan**

Document in a deploy checklist (in CLAUDE.md or wherever you keep deploy notes):

```
PasskeyAuth deployment to paddle.grief.coach:

1. SSH/SCP the entire /site/modules/PasskeyAuth/ directory (including vendor/).
2. ssh prod 'find /path/to/site/modules/PasskeyAuth/vendor -type f | head -1'  → confirm composer deps present.
3. Admin → Modules → Refresh.
4. Install PasskeyAuth.
5. Configure: appName=Paddle Admin, rpId=paddle.grief.coach, allowedRoles=[superuser].
6. Smoke test: curl -X POST https://paddle.grief.coach/passkey-auth/login/options -H 'Content-Type: application/json' -d '{}'
   → expect JSON with options.publicKey.challenge.
7. Log in with password, register a passkey via banner.
8. Log out, test passkey login.
9. Enable TfaTotp on the same admin user as a fallback path.
```

---

## Self-review notes (filled in by the writer)

- **Spec coverage:** All sections of the spec are covered. Endpoints match spec table. Storage schema matches. Login flow matches. Banner conditions match. Management UI matches. Module config matches.
- **Placeholder check:** No TBD/TODO. Stub `initBanner` and `initManage` in Task 10's JS are filled in by Tasks 11 and 12 respectively, and called out as such.
- **Type consistency:** `Storage` method names (`add`, `findByCredentialId`, `listForUser`, `findById`, `rename`, `delete`, `touchLastUsed`, `countForUser`) used consistently across Storage tests, Server, Endpoints, and module hooks. Endpoint paths match across PHP routing, JS calls, and the spec.

## Known follow-ups (not in this plan)

- ProcessLogin layout may surface the "Sign in with passkey" button below the login button instead of beside it. Cosmetic; address with CSS once we see the actual rendering.
- AAGUID lookup table for friendly authenticator names ("iCloud Keychain", "1Password", "YubiKey 5") is currently a no-op. Add a small JSON map later if useful.
- Test coverage for `Server::verifyRegistration` and `verifyLogin` is integration-only (manual). If you ever want unit tests, lbuchs/WebAuthn ships fixtures in its own test suite that can be borrowed.
