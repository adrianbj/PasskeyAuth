<?php namespace ProcessWire;

/**
 * ProcessPasskeyAuth — admin-page-gated endpoints for passkey management.
 *
 * Owns the protected (post-login) WebAuthn endpoints. Lives at
 * /admin/passkey-auth/ as a hidden Process module page. PW's admin-tree
 * carve-out (ProcessPageView redirects guests to login) keeps unauthenticated
 * users out, which is the only authorization this gate buys us — page-view
 * permission is held by every non-guest admin role. Real authorization is the
 * in-endpoint isAllowedByRole + CSRF + ownership checks.
 *
 * The guest-reachable login endpoints stay as URL hooks in PasskeyAuth.module.php
 * — admin pages can't be reached by logged-out users (that's why ProcessLogin
 * has its own carve-out), so login can't live here.
 *
 * All endpoint logic lives in PasskeyAuth\Endpoints. This module is a thin
 * dispatcher that delegates each execute*() to the matching method on the
 * Endpoints instance built by the main PasskeyAuth module.
 */
class ProcessPasskeyAuth extends Process implements Module
{
    public static function getModuleInfo(): array
    {
        return [
            'title'      => 'Passkey Auth (admin endpoints)',
            'summary'    => 'Internal admin-gated endpoints for passkey management',
            'author'     => 'Adrian Jones',
            'version'    => '0.1.0',
            'icon'       => 'key',
            // Process modules autoload only when their admin page is hit, so
            // the protected endpoints don't add boot cost on non-admin requests.
            'autoload'   => false,
            'singular'   => true,
            'requires'   => ['PasskeyAuth', 'ProcessWire>=3.0.173', 'PHP>=8.1'],
            // page-view is the broadest admin permission (every non-guest
            // admin role holds it). It only excludes guests — finer-grained
            // authorization is enforced by isAllowedByRole + CSRF + ownership
            // inside Endpoints. See class docblock for why this is sufficient.
            'permission' => 'page-view',
            // Tells PW to install/uninstall the admin page automatically.
            // Hidden so it doesn't appear in the admin nav.
            'page'       => [
                'name'   => 'passkey-auth',
                'parent' => 'admin',
                'title'  => 'Passkey Auth',
                'status' => 'hidden',
            ],
        ];
    }

    /**
     * Resolve the configured Endpoints instance from the main PasskeyAuth
     * module so we share its construction (DB, RP config, role allow-list,
     * verification settings) instead of duplicating wiring.
     */
    private function endpoints(): \PasskeyAuth\Endpoints
    {
        /** @var PasskeyAuth $main */
        $main = $this->wire('modules')->get('PasskeyAuth');
        return $main->buildEndpoints();
    }

    /**
     * SEC-D H2: short-circuit non-POST requests at the dispatcher. Endpoints
     * also enforces this internally; rejecting here avoids spinning up the
     * full endpoint wiring for trivially-wrong requests and ensures every
     * admin entry point honours the same method contract.
     */
    private function rejectNonPost(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') return;
        http_response_code(405);
        header('Allow: POST');
        header('Content-Type: application/json');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        echo '{"error":"Method not allowed","code":"method_not_allowed"}';
        exit;
    }

    // PW maps URL segments dash-to-camelCase: register-options -> executeRegisterOptions.
    // Each handler echoes the JSON body and exits, bypassing the admin theme's
    // chrome wrapping. ($config->ajax = true is unreliable here — the wrap can
    // still happen depending on theme/version. Emitting + exit is the same
    // pattern PW core uses for its own AJAX endpoints.) The inner Endpoints
    // method has already set the Content-Type header and HTTP status.

    public function ___executeRegisterOptions(): void
    {
        $this->rejectNonPost();
        echo $this->endpoints()->registerOptions();
        exit;
    }

    public function ___executeRegisterFinish(): void
    {
        $this->rejectNonPost();
        echo $this->endpoints()->registerFinish();
        exit;
    }

    public function ___executeRename(): void
    {
        $this->rejectNonPost();
        echo $this->endpoints()->rename();
        exit;
    }

    public function ___executeDelete(): void
    {
        $this->rejectNonPost();
        echo $this->endpoints()->delete();
        exit;
    }

    public function ___executeBannerDismiss(): void
    {
        $this->rejectNonPost();
        echo $this->endpoints()->bannerDismiss();
        exit;
    }
}
