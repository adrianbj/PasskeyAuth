<?php declare(strict_types=1);

/**
 * Minimal ProcessWire API stubs so Endpoints can be exercised without booting
 * ProcessWire. Only the surface Endpoints actually touches is implemented.
 */

namespace ProcessWire;

if (!class_exists(Wire::class)) {

    class Wire
    {
        private array $api = [];

        public function setApiVar(string $name, $value): void
        {
            $this->api[$name] = $value;
        }

        public function wire($name = null)
        {
            return $this->api[$name] ?? null;
        }
    }

    class User
    {
        public function __construct(
            public int $id = 0,
            private bool $superuser = false,
            public array $roles = [],
            private bool $loggedin = true,
        ) {}

        public function isLoggedin(): bool { return $this->loggedin; }
        public function isSuperuser(): bool { return $this->superuser; }
    }

    class Session
    {
        public object $CSRF;
        private array $data = [];

        public function __construct(string $csrfToken = 'test-token')
        {
            $this->CSRF = new class($csrfToken) {
                public function __construct(private string $token) {}
                public function getTokenValue(string $id): string { return $this->token; }
            };
        }

        public function getFor(string $ns, string $key)
        {
            return $this->data[$ns][$key] ?? null;
        }

        public function setFor(string $ns, string $key, $value): void
        {
            $this->data[$ns][$key] = $value;
        }

        public function removeFor(string $ns, string $key): void
        {
            unset($this->data[$ns][$key]);
        }
    }
}

namespace PasskeyAuth\Tests;

if (!class_exists(FakeLog::class)) {

    class FakeLog
    {
        public array $entries = [];

        public function save(string $channel, string $message): void
        {
            $this->entries[] = [$channel, $message];
        }
    }

    class FakeUsers
    {
        public function __construct(private array $usersById = []) {}

        public function get(int $id): ?\ProcessWire\User
        {
            return $this->usersById[$id] ?? null;
        }
    }

    /**
     * Stream wrapper that lets tests control what php://input returns.
     * Activate with stream_wrapper_unregister('php') + stream_wrapper_register,
     * restore with stream_wrapper_restore('php') in tearDown.
     */
    class MockPhpStream
    {
        public static string $input = '';
        public $context;
        private int $pos = 0;

        public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
        {
            return $path === 'php://input';
        }

        public function stream_read(int $count): string
        {
            $chunk = substr(self::$input, $this->pos, $count);
            $this->pos += strlen($chunk);
            return $chunk;
        }

        public function stream_eof(): bool
        {
            return $this->pos >= strlen(self::$input);
        }

        public function stream_seek(int $offset, int $whence = SEEK_SET): bool
        {
            if ($whence === SEEK_SET) { $this->pos = $offset; return true; }
            if ($whence === SEEK_CUR) { $this->pos += $offset; return true; }
            if ($whence === SEEK_END) { $this->pos = strlen(self::$input) + $offset; return true; }
            return false;
        }

        public function stream_tell(): int
        {
            return $this->pos;
        }

        public function stream_stat(): array
        {
            return [];
        }
    }
}
