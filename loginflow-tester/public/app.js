const app = document.querySelector("#app");
const routeBadge = document.querySelector("#route-badge");
const logsList = document.querySelector("#logs-list");
const clearLogs = document.querySelector("#clear-logs");

const localLogs = [];
let currentUser = null;
let activeLoginToken = null;

const routes = {
  "/": renderHome,
  "/login": () => renderLogin({ withAutocomplete: false, identifierType: "email" }),
  "/login-username": () => renderLogin({ withAutocomplete: false, identifierType: "username" }),
  "/login-autocomplete": () => renderLogin({ withAutocomplete: true, identifierType: "email" }),
  "/login-username-autocomplete": () => renderLogin({ withAutocomplete: true, identifierType: "username" }),
  "/login-passkey": renderPasskeyOnlyLogin,
  "/register": () => renderRegister(false),
  "/register-autocomplete": () => renderRegister(true),
  "/register-passkey": renderPasskeyOnlyRegister,
};

window.addEventListener("popstate", renderRoute);
clearLogs.addEventListener("click", async () => {
  clearLogs.disabled = true;
  try {
    await api("/api/logs/clear", {});
    localLogs.length = 0;
    renderLogs([]);
  } finally {
    clearLogs.disabled = false;
  }
});

document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-link]");
  if (!link) return;
  event.preventDefault();
  history.pushState({}, "", link.href);
  renderRoute();
});

await refreshMe();
renderRoute();
setInterval(refreshServerLogs, 5000);

function renderRoute() {
  const path = window.location.pathname;
  routeBadge.textContent = path;
  logClient("route rendered", { path, autocompleteHints: path.endsWith("-autocomplete") });
  (routes[path] || renderHome)();
}

function renderHome() {
  app.innerHTML = `
    <section class="hero">
      <div>
        <h1>Test login, TOTP, passkey, and autofill flows.</h1>
        <p>Use the paired routes to compare forms with explicit autocomplete hints against forms that leave hints unspecified.</p>
      </div>
      <div class="actions">
        <a class="action-link primary" href="/login" data-link>Email login</a>
        <a class="action-link" href="/login-username" data-link>Username login</a>
        <a class="action-link primary" href="/login-autocomplete" data-link>Email login with autocomplete</a>
        <a class="action-link" href="/login-username-autocomplete" data-link>Username login with autocomplete</a>
        <a class="action-link primary" href="/login-passkey" data-link>Passkey-only login</a>
        <a class="action-link primary" href="/register" data-link>Register</a>
        <a class="action-link" href="/register-autocomplete" data-link>Register with autocomplete</a>
        <a class="action-link" href="/register-passkey" data-link>Passkey-only registration</a>
      </div>
      <button id="show-users" class="secondary" type="button">Show stored users, passwords, TOTP, and passkeys</button>
      <div id="users-inspector"></div>
      ${currentUser ? `<p id="current-session" class="status ok">Current session: ${escapeHtml(currentUser.email)} (${currentUser.secondFactor})</p>` : ""}
    </section>
  `;
  document.querySelector("#show-users").addEventListener("click", showStoredUsers);
}

function pageTools() {
  return `<a class="action-link compact" href="/" data-link>Back home</a>`;
}

function warningBanner() {
  return `
    <div class="warning">
      Debug warning: this app stores passwords in clear text on purpose so encoding and autofill behavior can be inspected. Do not use real passwords.
    </div>
  `;
}

function renderPasskeyOnlyLogin() {
  app.innerHTML = `
    <section class="form">
      <div>
        ${pageTools()}
        <h1>Passkey-only login</h1>
        <p>No username, email, or password field is shown. The browser asks for a discoverable passkey for this relying party.</p>
      </div>
      <button id="passkey-only-login" class="primary" type="button">Login with Passkey</button>
      <div id="passkey-only-login-status" class="status" hidden></div>
    </section>
  `;
  document.querySelector("#passkey-only-login").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      logClient("passkey-only login requested", {});
      const result = await api("/api/passkey-only/login/options", {});
      if (!result.ok) return showStatus("#passkey-only-login-status", result.error, "error");
      const credential = await navigator.credentials.get({ publicKey: parseRequestOptions(result.options) });
      const response = credentialToJSON(credential);
      logClient("passkey-only login credential returned", { id: response.id, type: response.type });
      const verify = await api("/api/passkey-only/login/verify", { loginToken: result.loginToken, response });
      if (!verify.ok) return showStatus("#passkey-only-login-status", verify.error, "error");
      currentUser = verify.user;
      showStatus("#passkey-only-login-status", `Passkey login accepted for ${verify.user.username || verify.user.email}.`, "ok");
    } catch (error) {
      logClient("passkey-only login browser error", { name: error.name, message: error.message });
      showStatus("#passkey-only-login-status", `${error.name}: ${error.message}`, "error");
    } finally {
      button.disabled = false;
    }
  });
}

function renderPasskeyOnlyRegister() {
  app.innerHTML = `
    <form id="passkey-register-form" class="form">
      <div>
        ${pageTools()}
        <h1>Passkey-only registration</h1>
        <p>Create an account directly with a discoverable passkey. No password field is present or stored for this account.</p>
      </div>
      <div class="field">
        <label for="name">Name</label>
        <input id="name" name="name" type="text" required autocomplete="name">
      </div>
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" required autocomplete="username">
      </div>
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required autocomplete="email">
      </div>
      <button class="primary" type="submit">Register with Passkey</button>
      <div id="passkey-register-status" class="status" hidden></div>
    </form>
  `;
  document.querySelector("#passkey-register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    try {
      const body = {
        name: form.name.value,
        username: form.username.value,
        email: form.email.value,
      };
      logClient("passkey-only registration submitted", { username: body.username, email: body.email });
      const result = await api("/api/passkey-only/register/options", body);
      if (!result.ok) return showStatus("#passkey-register-status", result.error, "error");
      const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(result.options) });
      const response = credentialToJSON(credential);
      logClient("passkey-only registration credential returned", {
        id: response.id,
        type: response.type,
        transports: response.response?.transports || [],
      });
      const verify = await api("/api/passkey-only/register/verify", { registrationToken: result.registrationToken, response });
      if (!verify.ok) return showStatus("#passkey-register-status", verify.error, "error");
      currentUser = verify.user;
      form.querySelectorAll("input").forEach((node) => {
        node.disabled = true;
      });
      showStatus("#passkey-register-status", `Passkey-only account created for ${verify.user.username || verify.user.email}.`, "ok");
    } catch (error) {
      logClient("passkey-only registration browser error", { name: error.name, message: error.message });
      showStatus("#passkey-register-status", `${error.name}: ${error.message}`, "error");
    } finally {
      button.disabled = false;
    }
  });
}

function renderLogin({ withAutocomplete, identifierType }) {
  const isUsername = identifierType === "username";
  const label = isUsername ? "Username" : "Email";
  const inputType = isUsername ? "text" : "email";
  const autocomplete = withAutocomplete ? `autocomplete="${isUsername ? "username" : "email"}"` : "";
  app.innerHTML = `
    <form id="login-form" class="form">
      <div>
        ${pageTools()}
        <h1>${label} login${withAutocomplete ? " with autocomplete" : ""}</h1>
        <p>${withAutocomplete ? `This route includes explicit ${isUsername ? "username" : "email"} and current-password hints.` : "This route omits explicit autocomplete hints."}</p>
      </div>
      ${warningBanner()}
      <div class="field">
        <label for="identifier">${label}</label>
        <input id="identifier" name="identifier" type="${inputType}" required ${autocomplete}>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required ${withAutocomplete ? 'autocomplete="current-password"' : ""}>
      </div>
      <button class="primary" type="submit">Continue</button>
      <div id="login-status" class="status" hidden></div>
      <div id="second-factor"></div>
    </form>
  `;

  document.querySelector("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    const body = {
      identifier: form.identifier.value,
      identifierType,
      password: form.password.value,
      autocomplete: withAutocomplete,
    };
    logClient("password login submitted", { identifier: body.identifier, identifierType, autocompleteHints: withAutocomplete });
    const result = await api("/api/login/password", body);
    button.disabled = false;
    if (!result.ok) return showStatus("#login-status", result.error, "error");

    if (result.status === "complete") {
      currentUser = result.user;
      showStatus("#login-status", `Logged in as ${result.user.username || result.user.email}. No second factor configured.`, "ok");
      logClient("login completed", { username: result.user.username, email: result.user.email, secondFactor: "none" });
      return;
    }

    activeLoginToken = result.loginToken;
    showStatus("#login-status", `Password accepted. Second factor required: ${result.secondFactor}.`, "ok");
    logClient("second factor selected from user record", {
      email: result.user.email,
      secondFactor: result.secondFactor,
    });
    renderSecondFactor(result.secondFactor, withAutocomplete);
  });
}

function renderSecondFactor(secondFactor, withAutocomplete) {
  const target = document.querySelector("#second-factor");
  if (secondFactor === "totp") {
    target.innerHTML = `
      <div class="field">
        <label for="totp-code">TOTP code</label>
        <input id="totp-code" name="totp" inputmode="numeric" pattern="[0-9]*" maxlength="8" ${withAutocomplete ? 'autocomplete="one-time-code"' : ""}>
      </div>
      <button id="verify-totp" class="primary" type="button">Verify TOTP</button>
    `;
    document.querySelector("#verify-totp").addEventListener("click", async () => {
      const code = document.querySelector("#totp-code").value;
      logClient("totp login submitted", { codeLength: code.length, autocompleteHints: withAutocomplete });
      const result = await api("/api/totp/login", { loginToken: activeLoginToken, code });
      if (!result.ok) return showStatus("#login-status", result.error, "error");
      currentUser = result.user;
      showStatus("#login-status", `TOTP accepted. Drift: ${result.drift}.`, "ok");
    });
    return;
  }

  target.innerHTML = `
    <p class="hint">Use the platform passkey prompt to finish this login.</p>
    <button id="verify-passkey" class="primary" type="button">Use passkey</button>
  `;
  document.querySelector("#verify-passkey").addEventListener("click", async () => {
    try {
      logClient("passkey login requested", { loginToken: activeLoginToken });
      const options = await api("/api/passkey/login/options", { loginToken: activeLoginToken });
      if (!options.ok) return showStatus("#login-status", options.error, "error");
      const credential = await navigator.credentials.get({ publicKey: parseRequestOptions(options) });
      const response = credentialToJSON(credential);
      logClient("passkey login credential returned", {
        id: response.id,
        type: response.type,
      });
      const result = await api("/api/passkey/login/verify", { loginToken: activeLoginToken, response });
      if (!result.ok) return showStatus("#login-status", result.error, "error");
      currentUser = result.user;
      showStatus("#login-status", `Passkey accepted for ${result.user.email}.`, "ok");
    } catch (error) {
      logClient("passkey login browser error", { name: error.name, message: error.message });
      showStatus("#login-status", `${error.name}: ${error.message}`, "error");
    }
  });
}

function renderRegister(withAutocomplete) {
  app.innerHTML = `
    <form id="register-form" class="form">
      <div>
        ${pageTools()}
        <h1>${withAutocomplete ? "Register with autocomplete" : "Register"}</h1>
        <p>${withAutocomplete ? "This route includes explicit name, username, email, and new-password hints." : "This route omits explicit autocomplete hints."}</p>
      </div>
      ${warningBanner()}
      <div class="field">
        <label for="name">Name</label>
        <input id="name" name="name" type="text" required ${withAutocomplete ? 'autocomplete="name"' : ""}>
      </div>
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" required ${withAutocomplete ? 'autocomplete="username"' : ""}>
      </div>
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required ${withAutocomplete ? 'autocomplete="email"' : ""}>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required ${withAutocomplete ? 'autocomplete="new-password"' : ""}>
      </div>
      <button class="primary" type="submit">Create account</button>
      <div id="register-status" class="status" hidden></div>
      <div id="setup-area"></div>
    </form>
  `;

  document.querySelector("#register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    const body = {
      name: form.name.value,
      username: form.username.value,
      email: form.email.value,
      password: form.password.value,
      autocomplete: withAutocomplete,
    };
    logClient("registration submitted", { username: body.username, email: body.email, passwordStorage: "clear-text", autocompleteHints: withAutocomplete });
    const result = await api("/api/register", body);
    button.disabled = false;
    if (!result.ok) return showStatus("#register-status", result.error, "error");
    currentUser = result.user;
    form.querySelectorAll("input, button[type='submit']").forEach((node) => {
      node.disabled = true;
    });
    showStatus("#register-status", `Account created for ${result.user.email}.`, "ok");
    renderSetupChoices();
  });
}

async function showStoredUsers() {
  const target = document.querySelector("#users-inspector");
  target.innerHTML = `<p class="status">Loading stored users...</p>`;
  const result = await fetchWithTimeout("/api/debug/users").then((res) => res.json()).catch((error) => ({ error: error.message }));
  if (result.error) {
    target.innerHTML = `<p class="status error">${escapeHtml(result.error)}</p>`;
    return;
  }
  logClient("stored users inspected", { count: result.users.length });
  target.innerHTML = `
    <div class="users-panel">
      <h2>Stored Debug Users</h2>
      ${warningBanner()}
      ${result.users.length === 0 ? `<p class="status">No users registered yet.</p>` : result.users.map(renderStoredUser).join("")}
    </div>
  `;
  target.querySelectorAll("[data-delete-user]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const userId = event.currentTarget.dataset.deleteUser;
      const label = event.currentTarget.dataset.deleteLabel || "this user";
      if (!window.confirm(`Delete ${label}? This will remove the user, passkeys, and any related debug session data.`)) return;

      event.currentTarget.disabled = true;
      const result = await api(`/api/debug/users/${encodeURIComponent(userId)}`, {}, "DELETE");
      if (!result.ok) {
        target.innerHTML = `<p class="status error">${escapeHtml(result.error)}</p>`;
        event.currentTarget.disabled = false;
        return;
      }

      if (currentUser?.id === userId) currentUser = null;
      const session = document.querySelector("#current-session");
      if (session && !currentUser) session.remove();
      await showStoredUsers();
    });
  });
}

function renderStoredUser(user) {
  return `
    <article class="user-card">
      <div class="user-card-header">
        <h3>${escapeHtml(user.username || user.email)}</h3>
        <button
          class="danger"
          type="button"
          data-delete-user="${escapeHtml(user.id)}"
          data-delete-label="${escapeHtml(user.username || user.email)}"
        >
          Delete
        </button>
      </div>
      <dl>
        <dt>Name</dt><dd>${escapeHtml(user.name)}</dd>
        <dt>Username</dt><dd class="mono">${escapeHtml(user.username || "")}</dd>
        <dt>Email</dt><dd class="mono">${escapeHtml(user.email)}</dd>
        <dt>Password</dt><dd class="mono danger-text">${escapeHtml(user.password)}</dd>
        <dt>Second factor</dt><dd>${escapeHtml(user.secondFactor)}</dd>
        <dt>TOTP secret</dt><dd class="mono">${escapeHtml(user.totpSecret || "none")}</dd>
        <dt>Passkeys</dt><dd>${user.passkeys.length}</dd>
      </dl>
      ${user.passkeys.length ? `
        <pre class="mono passkey-json">${escapeHtml(JSON.stringify(user.passkeys, null, 2))}</pre>
      ` : ""}
    </article>
  `;
}

function renderSetupChoices() {
  document.querySelector("#setup-area").innerHTML = `
    <div>
      <h2>Add a second factor</h2>
      <p>Pick one method for this test user, or skip for password-only login tests.</p>
      <div class="setup-grid">
        <button id="setup-totp" type="button" class="primary">TOTP</button>
        <button id="setup-passkey" type="button" class="primary">Passkey</button>
        <button id="setup-skip" type="button">Skip</button>
      </div>
      <div id="setup-details"></div>
    </div>
  `;
  document.querySelector("#setup-totp").addEventListener("click", startTotpSetup);
  document.querySelector("#setup-passkey").addEventListener("click", startPasskeySetup);
  document.querySelector("#setup-skip").addEventListener("click", () => {
    document.querySelector("#setup-details").innerHTML = `<p class="status ok">Password-only test user is ready.</p>`;
    logClient("second factor skipped", { email: currentUser?.email });
  });
}

async function startTotpSetup() {
  const result = await api("/api/totp/setup", {});
  if (!result.ok) return showStatus("#register-status", result.error, "error");
  logClient("totp setup displayed", {
    account: result.account,
    issuer: result.issuer,
    secretPreview: `${result.secret.slice(0, 6)}...${result.secret.slice(-4)}`,
    uri: result.uri,
  });
  document.querySelector("#setup-details").innerHTML = `
    <div class="totp-box">
      <div class="qr"><img src="${result.qrDataUrl}" alt="TOTP QR code"></div>
      <div>
        <h3>TOTP setup</h3>
        <p><a class="action-link primary" href="${result.uri}">Open otpauth setup</a></p>
        <p class="hint">Manual configure code</p>
        <p class="mono">${escapeHtml(result.secret)}</p>
        <p class="hint">URI</p>
        <p class="mono">${escapeHtml(result.uri)}</p>
        <div class="field">
          <label for="setup-code">Confirmation code</label>
          <input id="setup-code" inputmode="numeric" pattern="[0-9]*" maxlength="8">
        </div>
        <button id="confirm-totp" class="primary" type="button">Confirm TOTP</button>
      </div>
    </div>
  `;
  document.querySelector("#confirm-totp").addEventListener("click", async () => {
    const code = document.querySelector("#setup-code").value;
    const confirm = await api("/api/totp/confirm", { code });
    if (!confirm.ok) return showStatus("#register-status", confirm.error, "error");
    currentUser = confirm.user;
    showStatus("#register-status", `TOTP configured. Drift: ${confirm.drift}.`, "ok");
    logClient("totp setup confirmed", { email: confirm.user.email, drift: confirm.drift });
  });
}

async function startPasskeySetup() {
  try {
    const options = await api("/api/passkey/register/options", {});
    if (!options.ok) return showStatus("#register-status", options.error, "error");
    logClient("passkey registration requested", {
      rp: options.rp,
      user: options.user?.name,
      challenge: options.challenge,
    });
    const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(options) });
    const response = credentialToJSON(credential);
    logClient("passkey registration credential returned", {
      id: response.id,
      type: response.type,
      transports: response.response?.transports || [],
    });
    const result = await api("/api/passkey/register/verify", response);
    if (!result.ok) return showStatus("#register-status", result.error, "error");
    currentUser = result.user;
    document.querySelector("#setup-details").innerHTML = `<p class="status ok">Passkey configured for ${escapeHtml(result.user.email)}.</p>`;
  } catch (error) {
    logClient("passkey registration browser error", { name: error.name, message: error.message });
    showStatus("#register-status", `${error.name}: ${error.message}`, "error");
  }
}

async function refreshMe() {
  const result = await fetch("/api/me").then((res) => res.json()).catch(() => ({ user: null }));
  currentUser = result.user;
}

async function refreshServerLogs() {
  const result = await fetch("/api/logs").then((res) => res.json()).catch(() => ({ logs: [] }));
  renderLogs(result.logs || []);
}

async function api(path, body, method = "POST") {
  try {
    const response = await fetchWithTimeout(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    return response.ok ? { ok: true, ...payload } : { ok: false, error: payload.error || response.statusText };
  } catch (error) {
    return { ok: false, error: error.name === "AbortError" ? "Request timed out." : error.message };
  }
}

async function fetchWithTimeout(path, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(path, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function showStatus(selector, message, type) {
  const target = document.querySelector(selector);
  target.hidden = false;
  target.className = `status ${type}`;
  target.textContent = message;
}

function logClient(event, details = {}) {
  localLogs.unshift({
    ts: new Date().toISOString(),
    source: "client",
    event,
    details,
  });
  localLogs.splice(200);
  renderLogs([]);
}

function renderLogs(serverLogs = []) {
  const merged = [...localLogs, ...serverLogs]
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .slice(0, 200);
  logsList.innerHTML = merged
    .map((entry) => `
      <article class="log-entry">
        <div class="log-meta">
          <span>${escapeHtml(entry.source)}</span>
          <span>${new Date(entry.ts).toLocaleTimeString()}</span>
        </div>
        <div class="log-event">${escapeHtml(entry.event)}</div>
        <pre class="log-details">${escapeHtml(JSON.stringify(entry.details || {}, null, 2))}</pre>
      </article>
    `)
    .join("");
}

function parseCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function parseRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function credentialToJSON(credential) {
  const json = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
    },
  };

  if (credential.response.attestationObject) {
    json.response.attestationObject = bufferToBase64url(credential.response.attestationObject);
    if (typeof credential.response.getTransports === "function") {
      json.response.transports = credential.response.getTransports();
    }
  }

  if (credential.response.authenticatorData) {
    json.response.authenticatorData = bufferToBase64url(credential.response.authenticatorData);
    json.response.signature = bufferToBase64url(credential.response.signature);
    json.response.userHandle = credential.response.userHandle
      ? bufferToBase64url(credential.response.userHandle)
      : null;
  }

  return json;
}

function base64urlToBuffer(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = `${value}${padding}`.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
