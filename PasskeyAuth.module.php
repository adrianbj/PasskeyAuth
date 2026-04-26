<?php namespace ProcessWire;

use PasskeyAuth\Endpoints;
use ProcessWire\HookEvent;

require_once __DIR__ . '/vendor/autoload.php';

/**
 * PasskeyAuth — WebAuthn passkey login for the ProcessWire admin.
 *
 * SEC-E I-A8: CSP compatibility note. This module emits two kinds of
 * page-level scripts:
 *
 *   1. <script>window.PasskeyAuth = {...}</script>  — inline JSON config
 *      injected by addManageFieldset(), injectBanner(), and addLoginButton().
 *      Requires either `script-src 'unsafe-inline'`, `'unsafe-hashes'`, or a
 *      per-request nonce/hash to be allowed by a strict Content-Security-Policy.
 *
 *   2. <script src="/site/modules/PasskeyAuth/PasskeyAuth.js" defer></script>
 *      — external module bootstrap. Allowed by any policy that whitelists the
 *      module's own origin (typically 'self').
 *
 * If you deploy a strict CSP without 'unsafe-inline', the inline JSON blob
 * (#1) will be blocked and the JS module will receive an empty config,
 * breaking all passkey UI. Workarounds, in order of preference:
 *
 *   - Add a per-request nonce to the policy (`script-src 'nonce-XYZ'`) and
 *     attach the same nonce attribute to each inline tag emitted by this
 *     module. (Not currently implemented — would require a config option for
 *     the nonce source.)
 *   - Move the config to an attribute on the script tag and read it from JS
 *     via dataset. (Future enhancement.)
 *   - Permit `'unsafe-inline'` for the admin URL only.
 */
class PasskeyAuth extends WireData implements Module, ConfigurableModule
{
    const TABLE_NAME = 'passkey_auth';
    const LEGACY_TABLE_NAME = 'loginpasskey';

    public static function getModuleInfo(): array
    {
        return [
            'title'    => 'Passkey Auth',
            'summary'  => 'WebAuthn passkey login for ProcessWire admin',
            'author'   => 'Adrian Jones',
            'version'  => '0.1.0',
            'icon'     => 'key',
            // autoload=true is required: the login URL hooks must be registered
            // before page resolution so guest POSTs to /passkey-auth/login/*
            // reach our handlers (PW dispatches URL hooks before routing pages).
            // The protected endpoints (register/rename/delete/banner-dismiss)
            // live in ProcessPasskeyAuth at /admin/passkey-auth/. The PW admin
            // tree carve-out keeps guests out (they're redirected to login by
            // ProcessPageView), but the page-view permission used to gate the
            // page is held by every non-guest admin role — so the page gate
            // alone is NOT sufficient authorization. The real authorization is
            // the in-endpoint isAllowedByRole + CSRF + ownership checks.
            'autoload' => true,
            'singular' => true,
            'requires' => ['ProcessWire>=3.0.173', 'PHP>=8.1'],
            'installs' => ['ProcessPasskeyAuth'],
        ];
    }

    private ?Endpoints $endpoints = null;

    /** Fixed URL hook path for the guest-reachable login endpoints. */
    public const LOGIN_API_URL = '/passkey-auth/';

    public function __construct()
    {
        parent::__construct();
        $this->set('appName', '');
        $this->set('rpId', '');
        $this->set('allowedRoles', []);
        // userVerification is hardcoded to 'required' in Server.php — see the
        // comment there. It is intentionally not exposed as a config option:
        // this is a passkey module, and the W3C / FIDO Alliance guidance for
        // passkey deployments is UV=required. Lower settings are footguns
        // (`preferred` silently accepts unverified assertions) or contradict
        // the passkey model entirely (`discouraged`).
        // Resident keys (discoverable credentials) are always required: this is a
        // passkey module — the passwordless "Sign in with passkey" flow depends
        // on the authenticator returning a userHandle, which only resident keys
        // guarantee. Non-resident credentials would silently break login.
        $this->set('bannerEnabled', 1);
    }

    /**
     * URL the JS uses for the protected (admin-gated) endpoints. Lives under
     * the admin URL so PW's standard admin-permission gate applies before any
     * of our code runs. Resolved from $config->adminRootPageID so renamed
     * admin URLs (e.g. /cp/) are handled automatically.
     */
    public function manageApiUrl(): string
    {
        $config   = $this->wire('config');
        $adminUrl = $this->wire('pages')->get((int) $config->adminRootPageID)->url;
        return $adminUrl . 'passkey-auth/';
    }

    /**
     * M6: read the configured role allow-list with the guest role stripped.
     * The config UI excludes guest from the option list, but a direct config
     * POST (only superusers can do this) could include it; this filter ensures
     * a hostile or buggy save can never grant passkey access to guest visitors.
     *
     * @return int[]
     */
    private function getAllowedRoleIds(): array
    {
        $guestId = (int) $this->wire('config')->guestUserRolePageID;
        $ids = array_map('intval', (array) ($this->allowedRoles ?: []));
        return array_values(array_filter($ids, fn(int $id) => $id !== $guestId && $id > 0));
    }

    /**
     * Does this user have at least one role on the passkey allow-list?
     * Mirrors Endpoints::isAllowedByRole() so the user-edit UI can decide
     * whether to expose the Passkeys fieldset, without instantiating the
     * full Endpoints stack.
     */
    private function isUserInAllowedRoles(\ProcessWire\User $user): bool
    {
        $allowed = $this->getAllowedRoleIds();
        if (empty($allowed)) return false;
        foreach ($user->roles as $role) {
            if (in_array((int) $role->id, $allowed, true)) return true;
        }
        return false;
    }

    /**
     * Build (and cache) the inner Endpoints instance. Public so
     * ProcessPasskeyAuth can delegate to the same configured logic without
     * duplicating wiring.
     */
    public function buildEndpoints(): Endpoints
    {
        if ($this->endpoints) return $this->endpoints;

        $config = $this->wire('config');
        // SEC-E I-A3: $config->httpHost includes the port for non-standard
        // dev setups (e.g. "localhost:8080"). rpId must be a hostname only —
        // a value with `:8080` would (a) fail the regex check below and break
        // module init outright, or (b) if the regex were loosened, slip into
        // the WebAuthn library where it would never match the origin host
        // (origins use port-less hosts in WebAuthn equality). Strip the port
        // so the fallback works in dev without surfacing a misleading error.
        $hostFallback = (string) $config->httpHost;
        $hostFallback = preg_replace('/:\d+$/', '', $hostFallback);
        $rpName = $this->appName ?: $hostFallback;
        $rpId   = $this->rpId    ?: $hostFallback;

        // SEC-D I6: refuse to construct with an obviously bad rpId. WebAuthn
        // requires the RP ID to be a registrable-suffix of the origin host;
        // a misconfigured rpId either silently breaks login or, when paired
        // with the lbuchs origin-regex bug (mitigated by Server::assertOrigin),
        // could weaken origin checks further. Allow only hostname characters.
        if (!preg_match('/^[a-z0-9.-]+$/i', $rpId) || str_starts_with($rpId, '.') || str_ends_with($rpId, '.')) {
            throw new \RuntimeException('Invalid rpId configuration');
        }

        $storage  = new \PasskeyAuth\Storage($this->wire('database')->pdo(), self::TABLE_NAME);
        $server   = new \PasskeyAuth\Server($rpName, $rpId);
        $allowedRoleIds = $this->getAllowedRoleIds();

        $this->endpoints = new \PasskeyAuth\Endpoints(
            $storage,
            $server,
            $this,
            $allowedRoleIds,
            true,  // requireResidentKey — see __construct comment
        );
        return $this->endpoints;
    }

    public function init(): void
    {
        // Login endpoints are guest-reachable, so they must register as URL
        // hooks (which dispatch before page resolution and don't require a
        // Page object). The other endpoints live in ProcessPasskeyAuth where
        // PW's admin-permission gate guards them.
        $prefix = rtrim(self::LOGIN_API_URL, '/');
        $this->wire()->addHook("{$prefix}/login/options", function() {
            return $this->buildEndpoints()->loginOptions();
        });
        $this->wire()->addHook("{$prefix}/login/finish", function() {
            return $this->buildEndpoints()->loginFinish();
        });

        $this->addHookAfter('ProcessLogin::buildLoginForm', $this, 'addLoginButton');
        // Banner is injected directly into the rendered page (HTML + JS together)
        // via Page::render AFTER. We deliberately do NOT use PW's notice system
        // ($this->warning(...)) because PW persists undisplayed notices across
        // redirects via the session — meaning a banner added during a logged-in
        // request that ends in a redirect (e.g. logout) would surface on the
        // next page load (the login screen), where the user can't act on it.
        // Injecting at render time ties visibility strictly to the current
        // request's shouldShowBanner() result.
        $this->addHookAfter('Page::render', $this, 'injectBanner');
        // Mirrors the wire/core/Tfa.php pattern: hook InputfieldForm::render so we
        // catch both the user edit form (ProcessPageEdit) and the profile form
        // (ProcessProfile, whose buildForm is protected and not hookable directly).
        $this->addHookBefore('InputfieldForm::render', $this, 'addManageFieldset');
        $this->addHookAfter('Pages::deleted', $this, 'onUserDeleted');
        $this->addHookAfter('Pages::trashed', $this, 'onUserTrashed');
        // SEC-D M3 / SEC-E M-A6: clear all PasskeyAuth session state on logout
        // so a stale in-flight registration, banner-dismissal flag, or
        // rate-limit window can't follow the next user that authenticates on
        // this session id. Hook BEFORE Session::logout (not the Success post-
        // hook) because PW destroys the session as part of logout — by the
        // time logoutSuccess fires, our removeFor() calls operate on a
        // brand-new (or nonexistent) session.
        $this->addHookBefore('Session::logout', $this, 'onLogout');
    }

    public function onLogout(HookEvent $event): void
    {
        try {
            $this->buildEndpoints()->clearAllSessionState();
        } catch (\Throwable $e) {
            // Logout must never throw; log and move on.
            $this->wire('log')->save('passkey-auth', 'onLogout cleanup failed: ' . $e->getMessage());
        }
    }

    public function onUserDeleted(HookEvent $event): void
    {
        $page = $event->arguments(0);
        if (!$page || !$page->id) return;
        if (!$page->template || $page->template->name !== 'user') return;

        $storage = new \PasskeyAuth\Storage($this->wire('database')->pdo(), self::TABLE_NAME);
        $storage->deleteAllForUser((int) $page->id);
    }

    // H4: trashing a user (PW soft-delete) means they should no longer be able to
    // log in. Cascade-delete their passkeys here so the credentials are invalidated
    // even before any permanent delete. Mirrors onUserDeleted behaviorally.
    //
    // SEC-E L-A4: trash is reversible from PW's UI ("restore from trash"), but
    // our cascade is not — once we've dropped the credential rows, restoring
    // the user leaves them with no passkeys (and, if password login is also
    // disabled, no way back in). Log the count so an admin who later restores
    // the user can see why login no longer works and re-enrol the user.
    public function onUserTrashed(HookEvent $event): void
    {
        $page = $event->arguments(0);
        if (!$page || !$page->id) return;
        if (!$page->template || $page->template->name !== 'user') return;

        $storage = new \PasskeyAuth\Storage($this->wire('database')->pdo(), self::TABLE_NAME);
        // Count is purely informational for the log; if it fails we still
        // perform the deletion (the security-relevant action) below.
        $count = 0;
        try { $count = $storage->countForUser((int) $page->id); } catch (\Throwable) {}
        $storage->deleteAllForUser((int) $page->id);
        if ($count > 0) {
            $this->wire('log')->save(
                'passkey-auth',
                sprintf('Trashed user %d had %d passkey(s); credentials were removed and will not be restored if the user is un-trashed.', (int) $page->id, $count)
            );
        }
    }

    public function addManageFieldset(HookEvent $event): void
    {
        $form = $event->object;
        if (!$form instanceof \ProcessWire\InputfieldForm) return;

        // Identify the edited user via the current process — mirrors Tfa::getUser().
        // ProcessPageEdit / ProcessUser implement WirePageEditor; ProcessProfile does not.
        $process = $this->wire('process');
        $current = $this->wire('user');
        $editedUser = null;
        if ($process instanceof \ProcessWire\WirePageEditor) {
            $page = $process->getPage();
            if ($page instanceof \ProcessWire\User) $editedUser = $page;
        } elseif ($process instanceof \ProcessWire\ProcessProfile) {
            $editedUser = $current;
        }
        if (!$editedUser || !$editedUser->id) return;

        // Permission: superuser may edit anyone; otherwise only self
        if (!$current->isSuperuser() && $editedUser->id !== $current->id) return;

        // Idempotent — don't double-inject if the form re-renders
        if ($form->getChildByName('passkey_auth_manage')) return;

        // Anchor on the password field (present in both the user edit form and
        // the profile form). Fall back to email or tfa_type if pass isn't shown.
        $anchor = $form->getChildByName('pass')
            ?: $form->getChildByName('email')
            ?: $form->getChildByName('tfa_type');
        if (!$anchor) return;

        $modules = $this->wire('modules');
        $config  = $this->wire('config');
        $session = $this->wire('session');

        $storage = new \PasskeyAuth\Storage($this->wire('database')->pdo(), self::TABLE_NAME);
        $rows    = $storage->listForUser($editedUser->id);
        $count   = count($rows);

        // Hide the fieldset when the edited user has no allow-listed role AND
        // no existing passkeys: registration would be rejected by Endpoints
        // (role_denied) and there's nothing to manage. If they DO have stored
        // passkeys but lost role access, still render the fieldset so the
        // admin can revoke them — never strand credentials in the DB without
        // a UI to remove them.
        if ($count === 0 && !$this->isUserInAllowedRoles($editedUser)) return;

        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->name = 'passkey_auth_manage';
        $fieldset->label = 'Passkeys';
        $fieldset->icon = 'key';
        $fieldset->collapsed = $count > 0
            ? \ProcessWire\Inputfield::collapsedNo
            : \ProcessWire\Inputfield::collapsedYes;

        $apiUrl = $this->manageApiUrl();
        $jsUrl  = $config->urls($this) . 'PasskeyAuth.js';
        $cssUrl = $config->urls($this) . 'PasskeyAuth.css';
        $csrf   = $session->CSRF->getTokenValue('passkey-auth');

        // Render existing rows server-side so they appear immediately with no
        // flash of empty list. JS appends rows for newly-added passkeys using
        // the same markup shape (see renderRow() in PasskeyAuth.js — keep them
        // aligned).
        $rowsHtml = '';
        foreach ($rows as $row) {
            $rowsHtml .= $this->renderManageRow($row);
        }

        $markup = $modules->get('InputfieldMarkup');
        $markup->name = 'passkey_auth_manage_markup';
        $markup->value = '<link rel="stylesheet" href="' . htmlspecialchars($cssUrl) . '">'
            . '<div class="passkey-auth-manage" data-user-id="' . (int) $editedUser->id . '">'
            . '<ul class="passkey-auth-list">' . $rowsHtml . '</ul>'
            . '<button type="button" data-passkey-auth-action="add" class="ui-button">Add a passkey</button>'
            . '<p class="passkey-auth-status" role="status" aria-live="polite"></p>'
            . '</div>';
        try {
            // SEC-E M-A4: do not include userName — JS doesn't read it. Inline
            // payloads should carry only what the client actually consumes to
            // limit passive info leak (browser extensions, CSP report-only
            // collectors).
            $payload = json_encode([
                'apiUrl' => $apiUrl,
                'mode'   => 'manage',
                'csrf'   => $csrf,
                'userId' => (int) $editedUser->id,
            ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
            $markup->value .= '<script>window.PasskeyAuth = ' . $payload . ';</script>'
                . '<script src="' . htmlspecialchars($jsUrl) . '" defer></script>';
        } catch (\JsonException $e) {
            $this->wire('log')->save('passkey-auth', 'addManageFieldset: json_encode failed: ' . $e->getMessage());
            // Skip emitting the inline config + script tag; the rest of the
            // markup (link, container, buttons) still renders.
        }
        $fieldset->add($markup);

        // Insert after the anchor field instead of appending to the form, so the
        // section appears next to related user settings rather than at the bottom.
        $anchor->getParent()->insertAfter($fieldset, $anchor);
    }

    /**
     * Render one passkey list row. Output structure must stay aligned with the
     * JS-side renderRow() in PasskeyAuth.js, which builds the same markup for
     * rows appended after a successful add.
     */
    private function renderManageRow(array $row): string
    {
        $id       = (int) $row['id'];
        $name     = htmlspecialchars((string) ($row['name'] ?? ''), ENT_QUOTES, 'UTF-8');
        $created  = htmlspecialchars(explode(' ', (string) ($row['created'] ?? ''))[0], ENT_QUOTES, 'UTF-8');
        $lastUsed = !empty($row['last_used'])
            ? htmlspecialchars(explode(' ', (string) $row['last_used'])[0], ENT_QUOTES, 'UTF-8')
            : null;
        $meta = $lastUsed
            ? 'Added ' . $created . ', last used ' . $lastUsed
            : 'Added ' . $created . ', never used';

        return '<li data-id="' . $id . '">'
            . '<div class="passkey-auth-row-text">'
            . '<span class="passkey-auth-name" title="Click to rename">' . $name . '</span>'
            . '<span class="passkey-auth-meta">' . $meta . '</span>'
            . '</div>'
            . '<button type="button">Delete</button>'
            . '</li>';
    }

    /**
     * Conditions under which the "Add a passkey" prompt should appear on this
     * admin request. Called from injectBanner() to gate the banner per render.
     */
    private function shouldShowBanner($page): bool
    {
        if (!$page || !$page->template || $page->template->name !== 'admin') return false;
        if (!$this->bannerEnabled) return false;

        $user = $this->wire('user');
        if (!$user->isLoggedin()) return false;

        if (!$this->isUserInAllowedRoles($user)) return false;

        if ($this->wire('session')->getFor('PasskeyAuth', 'banner_dismissed')) return false;

        $storage = new \PasskeyAuth\Storage($this->wire('database')->pdo(), self::TABLE_NAME);
        if ($storage->countForUser($user->id) > 0) return false;

        return true;
    }

    public function injectBanner(HookEvent $event): void
    {
        $page = $event->object;
        if (!$this->shouldShowBanner($page)) return;

        // Bail on AJAX/non-HTML responses. Page::render also fires for the
        // admin's AJAX endpoints (e.g. ProcessPageList tree expansion, which
        // returns JSON). Injecting HTML into a JSON payload corrupts it and
        // surfaces as "Unknown error, please try again later" in the page list.
        $config = $this->wire('config');
        if ($config->ajax) return;
        $output = (string) $event->return;
        // SEC-D M2: only match a real <body…> element-open token (word boundary
        // after `body`) to avoid false-positive matches on attribute values
        // like data-x="<bodyfoo>" or stringified content. Combined with the
        // admin-template gate in shouldShowBanner(), this keeps the injection
        // off pages that don't begin with an HTML document.
        if (!preg_match('/<body\b[^>]*>/i', $output)) return;

        $session = $this->wire('session');
        $apiUrl  = $this->manageApiUrl();
        $jsUrl   = $config->urls($this) . 'PasskeyAuth.js';
        $cssUrl  = $config->urls($this) . 'PasskeyAuth.css';
        $csrf    = $session->CSRF->getTokenValue('passkey-auth');

        try {
            // SEC-E M-A4: strip unused userName from inline payload.
            $payload = json_encode([
                'apiUrl' => $apiUrl,
                'mode'   => 'banner',
                'csrf'   => $csrf,
            ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->wire('log')->save('passkey-auth', 'injectBanner: json_encode failed: ' . $e->getMessage());
            return;
        }

        // Static markup — no user-controlled interpolation. We render our own
        // self-styled container instead of trying to slot into the admin
        // theme's notice list (which has theme-specific structure and risks
        // matching the wrong thing). data-passkey-auth-banner is the JS hook
        // initBanner() looks for; noticeContainer() walks up to .passkey-auth-banner.
        $bannerHtml = '<div class="passkey-auth-banner" data-passkey-auth-banner>'
                    . '<span class="passkey-auth-banner__icon" aria-hidden="true">🔑</span>'
                    . '<span class="passkey-auth-banner__text">Add a passkey for faster, more secure sign-in.</span>'
                    . '<button type="button" class="passkey-auth-banner__btn passkey-auth-banner__btn--primary" data-passkey-auth-action="register">Set up</button>'
                    . '<button type="button" class="passkey-auth-banner__btn" data-passkey-auth-action="dismiss">Don\'t show again</button>'
                    . '</div>';

        // FOUC fix: stylesheet must be parsed BEFORE the banner element is
        // encountered, otherwise the banner paints unstyled while the link
        // is still being fetched.
        //
        // SEC-E L-A1: also inline a minimal critical-CSS block alongside the
        // <link> so even if (a) the link is mis-placed by the regex below,
        // (b) the external CSS is slow to load, or (c) a future change strips
        // it, the banner still paints with sane styling on first frame.
        $criticalCss =
            '.passkey-auth-banner{display:flex;align-items:center;gap:.75em;flex-wrap:wrap;'
          . 'background:#fff8e1;border-bottom:1px solid #f0ad4e;color:#856404;'
          . 'padding:.65em 1.25em;font-size:14px;line-height:1.4}'
          . '.passkey-auth-banner__icon{flex-shrink:0;font-size:16px}'
          . '.passkey-auth-banner__text{flex:1 1 auto;min-width:0}'
          . '.passkey-auth-banner__btn{flex-shrink:0;padding:.35em .9em;font:inherit;font-size:13px;'
          . 'line-height:1.2;color:#57606a;background:#fff;border:1px solid #d0d7de;border-radius:6px;'
          . 'cursor:pointer}'
          . '.passkey-auth-banner__btn--primary{color:#fff;background:#1f883d;border-color:#1f883d}';
        $headInject = '<style>' . $criticalCss . '</style>'
                    . '<link rel="stylesheet" href="' . htmlspecialchars($cssUrl) . '">';
        $tail       = '<script>window.PasskeyAuth = ' . $payload . ';</script>'
                    . '<script src="' . htmlspecialchars($jsUrl) . '" defer></script>';

        // 1) CSS link into <head>. SEC-E L-A1: only match a </head> that
        //    follows a real opening <head ...> token, to avoid false matches
        //    on </head> appearing inside script string literals or comments
        //    emitted by other Page::render hooks earlier in the chain.
        //    If we can't find a clean head element, fall back to placing
        //    the styles immediately before the banner (still earlier in
        //    the document than the previous tail position).
        $output = (string) $event->return;
        $headOpen = preg_match('/<head\b[^>]*>/i', $output, $m, PREG_OFFSET_CAPTURE);
        if ($headOpen) {
            $headStart = $m[0][1] + strlen($m[0][0]);
            $headClose = stripos($output, '</head>', $headStart);
            if ($headClose !== false) {
                $output = substr($output, 0, $headClose) . $headInject . substr($output, $headClose);
            } else {
                $bannerHtml = $headInject . $bannerHtml;
            }
        } else {
            $bannerHtml = $headInject . $bannerHtml;
        }

        // 2) Insert banner right after the opening <body> so it sits above
        //    page chrome regardless of theme. Bail (without partial output)
        //    if we somehow can't find <body> — better no banner than a
        //    broken page.
        $output = preg_replace('/(<body\b[^>]*>)/i', '$1' . $bannerHtml, $output, 1, $count);
        if ($count === 0) return;

        // 3) JS tail before </body>.
        $event->return = str_ireplace('</body>', $tail . '</body>', $output);
    }

    public function addLoginButton(HookEvent $event): void
    {
        // SEC-E L-A2: defensive type guard. The hook is already scoped to
        // ProcessLogin::buildLoginForm by PW's hook dispatcher, but an earlier
        // hook in the chain could in principle replace $event->return with a
        // non-form value, or a future PW change could alter the return type.
        // Bail rather than fatal-error inside the admin login renderer.
        $form = $event->return;
        if (!$form instanceof \ProcessWire\InputfieldForm) return;

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
        $apiUrl = self::LOGIN_API_URL;

        $config->styles->add($cssUrl);

        $scriptMarkup = $modules->get('InputfieldMarkup');
        $scriptMarkup->name = 'passkey_auth_login_js';
        try {
            $payload = json_encode([
                'apiUrl' => $apiUrl,
                'mode'   => 'login',
            ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
            $scriptMarkup->value = '
        <script>window.PasskeyAuth = ' . $payload . ';</script>
        <script src="' . htmlspecialchars($jsUrl) . '" defer></script>';
        } catch (\JsonException $e) {
            $this->wire('log')->save('passkey-auth', 'addLoginButton: json_encode failed: ' . $e->getMessage());
            // Skip emitting the inline config + script tag; the rest of the
            // form (button + status placeholder) still renders.
            $scriptMarkup->value = '';
        }
        $form->add($scriptMarkup);
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
        $modules = $this->wire('modules');
        $config  = $this->wire('config');
        $roles   = $this->wire('roles');
        $fields  = new InputfieldWrapper();

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

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'bannerEnabled';
        $f->label = 'Show registration banner';
        $f->description = 'Auto-prompt logged-in admins without passkeys to register one.';
        if (!empty($data['bannerEnabled'])) $f->attr('checked', 'checked');
        $fields->add($f);

        return $fields;
    }
}
