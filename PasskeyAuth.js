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

    // ---- Dispatch ----
    // DOM-driven, not mode-driven: when both the profile "manage" section and
    // the (0-passkey) banner appear on the same page, both inline scripts set
    // window.PasskeyAuth and only the LAST one wins for `cfg.mode`. Detect each
    // mode by DOM presence so all relevant initializers run.
    document.addEventListener('DOMContentLoaded', () => {
        if (document.getElementById('passkey-auth-signin'))            initLogin();
        if (document.querySelector('[data-passkey-auth-banner]'))      initBanner();
        if (document.querySelector('.passkey-auth-manage'))            initManage();
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

    // ---- Banner mode ----
    // The banner span is rendered inside a PW notice (`<li class="NoticeWarning">`
    // for AdminThemeUikit, similar containers for other themes). To hide the
    // entire notice on dismiss/success we walk up to the closest notice element
    // — falling back to the parent if no known container class is found.
    function noticeContainer(banner) {
        return banner.closest('.NoticeWarning, .NoticeMessage, li, aside') || banner;
    }

    async function initBanner() {
        const banner = document.querySelector('[data-passkey-auth-banner]');
        if (!banner) return;

        banner.querySelector('[data-passkey-auth-action="dismiss"]').addEventListener('click', async () => {
            try { await postJSON('banner-dismiss'); } catch (e) {}
            noticeContainer(banner).remove();
        });

        const registerBtn = banner.querySelector('[data-passkey-auth-action="register"]');
        registerBtn.addEventListener('click', async () => {
            if (registerBtn.disabled) return;
            const name = autoPasskeyName();
            registerBtn.disabled = true;
            const prevError = banner.querySelector('.passkey-auth-banner__error');
            if (prevError) prevError.remove();
            try {
                await registrationFlow(name);
                banner.textContent = '✓ Passkey added';
                setTimeout(() => noticeContainer(banner).remove(), 3000);
            } catch (e) {
                const msg = friendlyRegistrationError(e);
                if (msg) {
                    const status = document.createElement('span');
                    status.className = 'passkey-auth-banner__error';
                    status.style.color = '#c00';
                    status.textContent = ' ' + msg;
                    banner.appendChild(status);
                }
                registerBtn.disabled = false;
            }
        });
    }

    function guessDeviceName() {
        const ua = navigator.userAgent;
        const parts = [];

        // OS + version. Apple freezes Mac OS X at 10_15_7 in modern UAs, so we
        // omit the Mac version (it's not real). iOS/iPadOS/Android/Windows
        // versions in the UA are still meaningful.
        let m;
        if (/iPhone/.test(ua)) {
            m = ua.match(/OS (\d+)_/);
            parts.push(m ? 'iPhone iOS ' + m[1] : 'iPhone');
        } else if (/iPad/.test(ua)) {
            m = ua.match(/OS (\d+)_/);
            parts.push(m ? 'iPad iPadOS ' + m[1] : 'iPad');
        } else if (/Macintosh|Mac OS X/.test(ua)) {
            parts.push('Mac');
        } else if (/Android/.test(ua)) {
            m = ua.match(/Android (\d+)/);
            parts.push(m ? 'Android ' + m[1] : 'Android');
        } else if (/Windows NT/.test(ua)) {
            m = ua.match(/Windows NT (\d+\.\d+)/);
            const winMap = { '10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7' };
            parts.push(m && winMap[m[1]] ? 'Windows ' + winMap[m[1]] : 'Windows');
        } else if (/Linux/.test(ua)) {
            parts.push('Linux');
        } else {
            parts.push('Device');
        }

        // Browser. Order matters — Edge/Opera UAs contain "Chrome", and Chrome's
        // UA contains "Safari", so check the more specific tokens first.
        let browser = '';
        if (/Edg\//.test(ua))                                   browser = 'Edge';
        else if (/OPR\/|Opera/.test(ua))                        browser = 'Opera';
        else if (/Firefox\//.test(ua))                          browser = 'Firefox';
        else if (/Chrome\//.test(ua) && !/Chromium/.test(ua))   browser = 'Chrome';
        else if (/Safari\//.test(ua))                           browser = 'Safari';
        if (browser) parts.push(browser);

        return parts.join(' ');
    }

    function autoPasskeyName() {
        const d = new Date();
        const date = d.getFullYear() + '-'
            + String(d.getMonth() + 1).padStart(2, '0') + '-'
            + String(d.getDate()).padStart(2, '0');
        return guessDeviceName() + ' · ' + date;
    }

    // Map a registration error to a short, user-facing message. Browser-thrown
    // DOMExceptions (NotAllowedError, AbortError, InvalidStateError, ...) carry
    // verbose spec-quoting text that ends with a W3C URL — unhelpful for users.
    // Cancellation isn't an error worth reporting at all.
    // Backend-thrown errors (from postJSON) are plain Error with already-short
    // messages from our error() responses, so we pass those through.
    //
    // Returns '' to indicate "user cancelled, show nothing".
    function friendlyRegistrationError(e) {
        if (e && typeof DOMException !== 'undefined' && e instanceof DOMException) {
            if (e.name === 'NotAllowedError' || e.name === 'AbortError') return '';
            if (e.name === 'InvalidStateError') return 'This device already has a passkey for your account';
            return 'Could not add passkey';
        }
        return (e && e.message) ? e.message : 'Could not add passkey';
    }

    // Note: we do NOT try to detect cross-device (QR/hybrid) registrations and
    // relabel to "Phone". Both signals (authenticatorAttachment, getTransports)
    // are reported inconsistently across browsers — Safari has been observed
    // marking local Touch ID registrations as cross-platform, which produced
    // the opposite bug (local Mac registrations named "Phone"). Instead, the
    // manage UI auto-focuses the rename input on the new row so the user can
    // override the auto-name in two clicks regardless of source device.

    async function registrationFlow(name, userId = null) {
        const optsRes = await postJSON('register-options', { name, userId });
        const opts = decodePublicKeyOptions({ publicKey: optsRes.options.publicKey });
        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        return await postJSON('register-finish', {
            name, userId, credential: serializeAttestation(cred),
        });
    }

    // ---- Manage mode ----
    // Initial rows are rendered server-side by PasskeyAuth.module.php
    // (renderManageRow). This handler attaches behavior via list-level event
    // delegation so it works for both server-rendered rows and rows we append
    // after a successful add. renderRow() below builds new rows in the same
    // shape — keep it aligned with the PHP-side row markup.
    function initManage() {
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

            const text = document.createElement('div');
            text.className = 'passkey-auth-row-text';

            const name = document.createElement('span');
            name.className = 'passkey-auth-name';
            name.textContent = p.name;
            name.title = 'Click to rename';

            const meta = document.createElement('span');
            meta.className = 'passkey-auth-meta';
            const created  = (p.created || '').split(' ')[0];
            const lastUsed = p.lastUsed ? p.lastUsed.split(' ')[0] : null;
            meta.textContent = 'Added ' + created
                + (lastUsed ? ', last used ' + lastUsed : ', never used');

            text.append(name, meta);

            const del = document.createElement('button');
            del.type = 'button';
            del.textContent = 'Delete';

            li.append(text, del);
            return li;
        }

        function beginRename(id, span) {
            const input = document.createElement('input');
            input.type = 'text';
            input.value = span.textContent;
            let cancelled = false;
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') input.blur();
                if (e.key === 'Escape') { input.value = span.textContent; cancelled = true; input.blur(); }
            });
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

        // Single delegated click handler — works for server-rendered rows and
        // rows appended after add. Avoids per-row listener bookkeeping.
        list.addEventListener('click', (e) => {
            const li = e.target.closest('li[data-id]');
            if (!li) return;
            const id = parseInt(li.dataset.id, 10);
            if (!id) return;
            if (e.target.classList.contains('passkey-auth-name')) {
                beginRename(id, e.target);
            } else if (e.target.tagName === 'BUTTON') {
                doDelete(id, li);
            }
        });

        if (addBtn) {
            addBtn.addEventListener('click', async () => {
                if (addBtn.disabled) return;
                const name = autoPasskeyName();
                setStatus('');
                addBtn.disabled = true;
                try {
                    const result = await registrationFlow(name, userId);
                    const p = result && result.passkey;
                    if (p && p.id) {
                        const newRow = renderRow(p);
                        list.appendChild(newRow);
                        // Auto-focus the rename input on the new row so the
                        // user can correct the auto-generated name in two clicks
                        // (covers cross-device QR registrations, where the
                        // local UA-based name guess is wrong).
                        const nameSpan = newRow.querySelector('.passkey-auth-name');
                        if (nameSpan) beginRename(p.id, nameSpan);
                    }
                } catch (e) {
                    const msg = friendlyRegistrationError(e);
                    if (msg) setStatus(msg, true);
                } finally {
                    addBtn.disabled = false;
                }
            });
        }
    }
})();
