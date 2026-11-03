/* kagi — passkey front-end. No frameworks, no build step. */
(() => {
  'use strict';

  const B64 = {
    toBytes(value) {
      let s = String(value).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
    fromBytes(buffer) {
      const bytes = new Uint8Array(buffer);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
  };

  const configEl = document.getElementById('kagi-config');
  const config = configEl ? JSON.parse(configEl.textContent || '{}') : {};
  const msgEl = document.getElementById('msg');

  function setMsg(text, ok = false) {
    if (!msgEl) return;
    msgEl.textContent = text || '';
    msgEl.classList.toggle('ok', !!ok);
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body || {}),
      credentials: 'same-origin',
    });
    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* non-JSON error page */
    }
    if (!res.ok) {
      const detail =
        (data && (data.error_description || data.error)) || `HTTP ${res.status}`;
      throw new Error(detail);
    }
    return data || {};
  }

  function humanError(err) {
    if (!err) return '不明なエラーが発生しました';
    switch (err.name) {
      case 'NotAllowedError':
        return '認証がキャンセルされたか、時間切れになりました。';
      case 'SecurityError':
        return 'このオリジンではパスキーを利用できません。';
      case 'InvalidStateError':
        return 'このパスキーは既に登録されています。';
      case 'NotSupportedError':
        return 'この端末・ブラウザではパスキーを利用できません。';
      case 'AbortError':
        return '';
      default:
        return err.message || String(err);
    }
  }

  function creationOptions(publicKey) {
    const pk = JSON.parse(JSON.stringify(publicKey));
    pk.challenge = B64.toBytes(publicKey.challenge);
    pk.user.id = B64.toBytes(publicKey.user.id);
    (pk.excludeCredentials || []).forEach((c) => {
      c.id = B64.toBytes(c.id);
    });
    return pk;
  }

  function requestOptions(publicKey) {
    const pk = JSON.parse(JSON.stringify(publicKey));
    pk.challenge = B64.toBytes(publicKey.challenge);
    (pk.allowCredentials || []).forEach((c) => {
      c.id = B64.toBytes(c.id);
    });
    return pk;
  }

  function serializeCredential(credential) {
    const r = credential.response;
    const out = {
      id: credential.id,
      rawId: B64.fromBytes(credential.rawId),
      type: credential.type,
      clientExtensionResults:
        typeof credential.getClientExtensionResults === 'function'
          ? credential.getClientExtensionResults()
          : {},
      response: {
        clientDataJSON: B64.fromBytes(r.clientDataJSON),
        userHandle: r.userHandle ? B64.fromBytes(r.userHandle) : null,
      },
    };
    if (r.attestationObject) {
      out.response.attestationObject = B64.fromBytes(r.attestationObject);
      out.response.transports =
        typeof r.getTransports === 'function' ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = B64.fromBytes(r.authenticatorData);
      out.response.signature = B64.fromBytes(r.signature);
    }
    return out;
  }

  function passkeysSupported() {
    if (!window.PublicKeyCredential) {
      setMsg('このブラウザはパスキーに対応していません。');
      return false;
    }
    if (!window.isSecureContext) {
      setMsg('パスキーは HTTPS (または localhost) でのみ利用できます。');
      return false;
    }
    return true;
  }

  // -------------------------------------------------------------------------
  // Sign in
  // -------------------------------------------------------------------------

  function initLogin() {
    const btn = document.getElementById('btn-login');
    const username = document.getElementById('username');
    let controller = null;

    async function finish(credential) {
      const res = await post('/api/webauthn/login/verify', {
        rid: config.rid,
        credential: serializeCredential(credential),
      });
      location.href = res.next || '/';
    }

    async function interactive() {
      setMsg('');
      if (controller) {
        controller.abort();
        controller = null;
      }
      if (!passkeysSupported()) return;
      btn.disabled = true;
      try {
        const { publicKey } = await post('/api/webauthn/login/options', {
          rid: config.rid,
        });
        const credential = await navigator.credentials.get({
          publicKey: requestOptions(publicKey),
        });
        await finish(credential);
      } catch (err) {
        btn.disabled = false;
        setMsg(humanError(err));
      }
    }

    async function conditional() {
      if (!passkeysSupported()) return;
      if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return;
      let available = false;
      try {
        available = await PublicKeyCredential.isConditionalMediationAvailable();
      } catch (_) {
        return;
      }
      if (!available) return;
      try {
        const { publicKey } = await post('/api/webauthn/login/options', {
          rid: config.rid,
        });
        controller = new AbortController();
        const credential = await navigator.credentials.get({
          publicKey: requestOptions(publicKey),
          mediation: 'conditional',
          signal: controller.signal,
        });
        if (credential) {
          controller = null;
          await finish(credential);
        }
      } catch (_) {
        /* user dismissed the sheet or the request was superseded */
      }
    }

    btn.addEventListener('click', interactive);
    if (username) {
      username.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') interactive();
      });
    }
    if (passkeysSupported()) conditional();
  }

  // -------------------------------------------------------------------------
  // Sign up
  // -------------------------------------------------------------------------

  function initSignup() {
    const form = document.getElementById('signup-form');
    const btn = document.getElementById('btn-signup');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      setMsg('');
      if (!passkeysSupported()) return;

      const username = document.getElementById('username').value.trim();
      const displayName = document.getElementById('display_name').value.trim();
      const email = document.getElementById('email').value.trim();
      if (username.length < 3) {
        setMsg('ユーザー名は3文字以上で入力してください。');
        return;
      }

      btn.disabled = true;
      try {
        const start = await post('/api/webauthn/signup/options', {
          username,
          display_name: displayName,
          email: email || null,
          rid: config.rid || null,
        });
        const credential = await navigator.credentials.create({
          publicKey: creationOptions(start.publicKey),
        });
        const res = await post('/api/webauthn/signup/verify', {
          rid: start.rid,
          credential: serializeCredential(credential),
        });
        location.href = res.next || '/';
      } catch (err) {
        btn.disabled = false;
        setMsg(humanError(err));
      }
    });
  }

  // -------------------------------------------------------------------------
  // Account
  // -------------------------------------------------------------------------

  function initAccount() {
    const btnAdd = document.getElementById('btn-add-passkey');

    if (btnAdd) {
      btnAdd.addEventListener('click', async () => {
        setMsg('');
        if (!passkeysSupported()) return;
        btnAdd.disabled = true;
        try {
          const start = await post('/api/webauthn/passkey/options', {});
          const credential = await navigator.credentials.create({
            publicKey: creationOptions(start.publicKey),
          });
          await post('/api/webauthn/passkey/verify', {
            rid: start.rid,
            credential: serializeCredential(credential),
          });
          setMsg('パスキーを追加しました。', true);
          setTimeout(() => location.reload(), 700);
        } catch (err) {
          btnAdd.disabled = false;
          setMsg(humanError(err));
        }
      });
    }

    // Row actions are delegated so that server-rendered lists need no inline JS.
    document.addEventListener('click', async (event) => {
      const el = event.target.closest('[data-action]');
      if (!el) return;
      const action = el.dataset.action;
      try {
        if (action === 'rename-passkey') {
          const next = window.prompt('パスキー名', el.dataset.name || 'パスキー');
          if (next === null) return;
          await post('/api/account/passkey/rename', { id: el.dataset.id, name: next });
          setMsg('パスキー名を変更しました。', true);
          setTimeout(() => location.reload(), 500);
        } else if (action === 'delete-passkey') {
          if (!window.confirm('このパスキーを削除しますか？')) return;
          await post('/api/account/passkey/delete', { id: el.dataset.id });
          setMsg('パスキーを削除しました。', true);
          setTimeout(() => location.reload(), 500);
        } else if (action === 'revoke-session') {
          if (!window.confirm('このデバイスをサインアウトしますか？')) return;
          const res = await post('/api/account/sessions/revoke', {
            id: el.dataset.id,
          });
          if (res.current) {
            location.href = '/login';
            return;
          }
          setMsg('デバイスをサインアウトしました。', true);
          setTimeout(() => location.reload(), 500);
        } else if (action === 'revoke-consent') {
          if (!window.confirm('このアプリへのアクセスを取り消しますか？')) return;
          await post('/api/account/consent/revoke', {
            client_id: el.dataset.client,
          });
          setMsg('アクセスを取り消しました。', true);
          setTimeout(() => location.reload(), 500);
        }
      } catch (err) {
        setMsg(humanError(err));
      }
    });

    const profile = document.getElementById('profile-form');
    if (profile) {
      profile.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = profile.querySelector('button[type="submit"]');
        if (button) button.disabled = true;
        try {
          await post('/api/account/profile', {
            display_name: document
              .getElementById('profile-display-name')
              .value.trim(),
            email:
              document.getElementById('profile-email').value.trim() || null,
          });
          setMsg('プロフィールを保存しました。', true);
          setTimeout(() => location.reload(), 500);
        } catch (err) {
          setMsg(humanError(err));
        } finally {
          if (button) button.disabled = false;
        }
      });
    }

    const revokeOthers = document.getElementById('btn-revoke-others');
    if (revokeOthers) {
      revokeOthers.addEventListener('click', async () => {
        if (!window.confirm('このデバイス以外をすべてサインアウトしますか？')) return;
        revokeOthers.disabled = true;
        try {
          const res = await post('/api/account/sessions/revoke-others', {});
          setMsg(`${res.revoked || 0} 台のデバイスをサインアウトしました。`, true);
          setTimeout(() => location.reload(), 600);
        } catch (err) {
          revokeOthers.disabled = false;
          setMsg(humanError(err));
        }
      });
    }

    const generate = document.getElementById('btn-generate-recovery');
    if (generate) {
      generate.addEventListener('click', async () => {
        if (
          !window.confirm(
            '既存のリカバリーコードはすべて無効になります。新しく生成しますか？'
          )
        )
          return;
        generate.disabled = true;
        try {
          const res = await post('/api/account/recovery/generate', {});
          const list = document.getElementById('recovery-list');
          const output = document.getElementById('recovery-output');
          list.innerHTML = '';
          (res.codes || []).forEach((code) => {
            const li = document.createElement('li');
            li.textContent = code;
            list.appendChild(li);
          });
          output.hidden = false;
          setMsg('新しいリカバリーコードを生成しました。', true);
        } catch (err) {
          setMsg(humanError(err));
        } finally {
          generate.disabled = false;
        }
      });
    }

    const copy = document.getElementById('btn-copy-recovery');
    if (copy) {
      copy.addEventListener('click', async () => {
        const codes = Array.from(
          document.querySelectorAll('#recovery-list li')
        ).map((li) => li.textContent);
        try {
          await navigator.clipboard.writeText(codes.join('\n'));
          setMsg('コピーしました。', true);
        } catch (_) {
          setMsg('コピーできませんでした。手動で選択してください。');
        }
      });
    }

    const del = document.getElementById('delete-form');
    if (del) {
      del.addEventListener('submit', async (event) => {
        event.preventDefault();
        const username = document
          .getElementById('confirm-username')
          .value.trim();
        if (!username) return;
        if (!window.confirm('本当にアカウントを削除しますか？この操作は取り消せません。'))
          return;
        try {
          await post('/api/account/delete', { username });
          location.href = '/login';
        } catch (err) {
          setMsg(humanError(err));
        }
      });
    }
  }

  // -------------------------------------------------------------------------
  // Recovery-code sign in
  // -------------------------------------------------------------------------

  function initRecover() {
    const form = document.getElementById('recover-form');
    if (!form) return;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMsg('');
      const button = document.getElementById('btn-recover');
      button.disabled = true;
      try {
        const res = await post('/api/recover', {
          username: document.getElementById('recover-username').value.trim(),
          code: document.getElementById('recover-code').value.trim(),
          rid: config.rid || null,
        });
        location.href = res.next || '/';
      } catch (err) {
        button.disabled = false;
        setMsg(humanError(err));
      }
    });
  }


  // -------------------------------------------------------------------------
  // Demo relying party (uses the public SDK in /static/kagi.js)
  // -------------------------------------------------------------------------

  function initDemo() {
    const btn = document.getElementById('demo-login');
    const logoutBtn = document.getElementById('demo-logout');
    const out = document.getElementById('demo-output');
    const sdk = window.Kagi;
    if (!btn || !sdk) return;

    sdk.configure({
      issuer: config.issuer,
      clientId: config.client_id,
      redirectUri: config.redirect_uri,
      scope: config.scope,
    });

    async function show(session) {
      const user = await sdk.userinfo(session.tokens.access_token);
      out.hidden = false;
      out.textContent = JSON.stringify(
        {
          id_token_claims: session.claims,
          userinfo: user,
          scope: session.tokens.scope,
          expires_in: session.tokens.expires_in,
        },
        null,
        2
      );
      btn.hidden = true;
      logoutBtn.hidden = false;
    }

    const params = new URLSearchParams(location.search);
    if (params.has('code') || params.has('error')) {
      sdk
        .handleCallback()
        .then((session) => (session ? show(session) : null))
        .catch((err) => setMsg(humanError(err)));
    } else {
      const session = sdk.session();
      if (session) show(session).catch((err) => setMsg(humanError(err)));
    }

    btn.addEventListener('click', () => {
      setMsg('');
      sdk.login().catch((err) => setMsg(humanError(err)));
    });

    logoutBtn.addEventListener('click', () => sdk.logout());
  }

  if (config.flow === 'login') initLogin();
  else if (config.flow === 'signup') initSignup();
  else if (config.flow === 'account') initAccount();
  else if (config.flow === 'recover') initRecover();
  else if (config.flow === 'demo') initDemo();
})();
