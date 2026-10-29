/*!
 * kagi.js — drop-in browser SDK for a kagi OpenID Provider.
 *
 * Works on any site: load this file from the kagi origin, configure it once,
 * and call `Kagi.login()`. Authorization Code + PKCE (S256) is handled for
 * you, including state and nonce checks.
 *
 *   <script src="https://id.example.com/static/kagi.js"></script>
 *   <script>
 *     Kagi.configure({
 *       issuer: "https://id.example.com",
 *       clientId: "your-client-id",
 *       redirectUri: location.origin + "/callback",
 *     });
 *     Kagi.login();
 *   </script>
 *
 * On the callback page:
 *   const session = await Kagi.handleCallback();
 *   const user = await Kagi.userinfo();
 *
 * Notes:
 *  - PKCE and Web Crypto require a secure context (HTTPS, or localhost).
 *  - ID token signature validation belongs on the server (fetch /jwks.json);
 *    this SDK only performs iss/aud/nonce sanity checks for UX.
 */
(function (global) {
  'use strict';

  var STORAGE = 'kagi.sdk.';
  var config = {
    issuer: '',
    clientId: '',
    redirectUri: '',
    scope: 'openid profile email',
  };

  // ---------------------------------------------------------------------
  // Encoding helpers
  // ---------------------------------------------------------------------

  function b64url(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64url(value) {
    var s = String(value).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomString(size) {
    var bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return b64url(bytes);
  }

  function sha256(text) {
    return crypto.subtle
      .digest('SHA-256', new TextEncoder().encode(text))
      .then(function (buffer) {
        return new Uint8Array(buffer);
      });
  }

  function decodeJwt(token) {
    var parts = String(token || '').split('.');
    if (parts.length < 2) throw new Error('invalid ID token');
    return JSON.parse(new TextDecoder().decode(fromB64url(parts[1])));
  }

  function formBody(values) {
    var body = new URLSearchParams();
    Object.keys(values).forEach(function (key) {
      if (values[key] !== undefined && values[key] !== null) {
        body.set(key, values[key]);
      }
    });
    return body;
  }

  // ---------------------------------------------------------------------
  // Storage
  // ---------------------------------------------------------------------

  function storeKey() {
    return STORAGE + config.issuer + '|' + config.clientId;
  }

  function save(name, value) {
    try {
      sessionStorage.setItem(storeKey() + '.' + name, JSON.stringify(value));
    } catch (_) {
      /* private mode */
    }
  }

  function load(name) {
    try {
      var raw = sessionStorage.getItem(storeKey() + '.' + name);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function drop(name) {
    try {
      sessionStorage.removeItem(storeKey() + '.' + name);
    } catch (_) {
      /* ignore */
    }
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------

  function configure(options) {
    options = options || {};
    if (!options.issuer) throw new Error('Kagi.configure: issuer is required');
    if (!options.clientId) throw new Error('Kagi.configure: clientId is required');
    config = {
      issuer: String(options.issuer).replace(/\/+$/, ''),
      clientId: String(options.clientId),
      redirectUri:
        options.redirectUri || location.origin + location.pathname,
      scope: options.scope || 'openid profile email',
    };
    return config;
  }

  async function login(extraParams) {
    if (!config.issuer || !config.clientId) {
      throw new Error('Kagi.login: call Kagi.configure() first');
    }
    var verifier = randomString(32);
    var state = randomString(16);
    var nonce = randomString(16);
    var challenge = b64url(await sha256(verifier));

    save('pending', {
      state: state,
      nonce: nonce,
      verifier: verifier,
      redirectUri: config.redirectUri,
    });

    var query = formBody({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope,
      state: state,
      nonce: nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    Object.keys(extraParams || {}).forEach(function (key) {
      query.set(key, extraParams[key]);
    });

    location.assign(config.issuer + '/authorize?' + query.toString());
    return new Promise(function () {
      /* navigation in progress */
    });
  }

  async function exchange(body) {
    var res = await fetch(config.issuer + '/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: formBody(body),
    });
    var data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* no JSON */
    }
    if (!res.ok) {
      var detail =
        (data && (data.error_description || data.error)) || 'HTTP ' + res.status;
      throw new Error(detail);
    }
    return data || {};
  }

  function verifyClaims(claims, expectedNonce) {
    if (claims.iss !== config.issuer) {
      throw new Error('ID token issuer mismatch');
    }
    var aud = claims.aud;
    var audOk = Array.isArray(aud)
      ? aud.indexOf(config.clientId) !== -1
      : aud === config.clientId;
    if (!audOk) throw new Error('ID token audience mismatch');
    if (expectedNonce && claims.nonce !== expectedNonce) {
      throw new Error('ID token nonce mismatch');
    }
  }

  async function handleCallback(href) {
    var url = new URL(href || location.href);
    var params = url.searchParams;

    if (params.get('error')) {
      throw new Error(
        params.get('error_description') || params.get('error')
      );
    }
    var code = params.get('code');
    var iss = params.get('iss');
    if (iss && iss.replace(/\/+$/, '') !== config.issuer) {
      throw new Error('authorization response issuer mismatch');
    }
    if (!code) return null;

    var pending = load('pending');
    if (!pending) {
      throw new Error('no pending login (session storage was cleared)');
    }
    if (pending.state !== params.get('state')) {
      throw new Error('state mismatch');
    }

    var tokens = await exchange({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: pending.redirectUri,
      client_id: config.clientId,
      code_verifier: pending.verifier,
    });

    var claims = tokens.id_token ? decodeJwt(tokens.id_token) : null;
    if (claims) verifyClaims(claims, pending.nonce);

    var session = {
      tokens: tokens,
      claims: claims,
      obtainedAt: Date.now(),
    };
    save('session', session);
    drop('pending');

    if (url.origin === location.origin) {
      history.replaceState(null, '', url.pathname + url.hash);
    }
    return session;
  }

  function session() {
    return load('session');
  }

  function accessToken() {
    var s = session();
    return s && s.tokens ? s.tokens.access_token : null;
  }

  async function userinfo(token) {
    var bearer = token || accessToken();
    if (!bearer) throw new Error('not signed in');
    var res = await fetch(config.issuer + '/userinfo', {
      headers: { authorization: 'Bearer ' + bearer, accept: 'application/json' },
    });
    var data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* no JSON */
    }
    if (!res.ok) {
      throw new Error((data && data.error) || 'HTTP ' + res.status);
    }
    return data;
  }

  async function refresh() {
    var s = session();
    if (!s || !s.tokens || !s.tokens.refresh_token) {
      throw new Error('no refresh token');
    }
    var tokens = await exchange({
      grant_type: 'refresh_token',
      refresh_token: s.tokens.refresh_token,
      client_id: config.clientId,
    });
    var claims = tokens.id_token ? decodeJwt(tokens.id_token) : s.claims;
    save('session', { tokens: tokens, claims: claims, obtainedAt: Date.now() });
    return session();
  }

  function logout(options) {
    options = options || {};
    var s = session();
    drop('session');
    drop('pending');
    var query = new URLSearchParams();
    if (s && s.tokens && s.tokens.id_token) {
      query.set('id_token_hint', s.tokens.id_token);
    }
    if (options.redirectUri) {
      query.set('post_logout_redirect_uri', options.redirectUri);
    }
    var tail = query.toString();
    location.assign(config.issuer + '/logout' + (tail ? '?' + tail : ''));
  }

  global.Kagi = {
    version: '1.1.0',
    configure: configure,
    login: login,
    handleCallback: handleCallback,
    session: session,
    accessToken: accessToken,
    userinfo: userinfo,
    refresh: refresh,
    logout: logout,
    decodeJwt: decodeJwt,
  };
})(window);
