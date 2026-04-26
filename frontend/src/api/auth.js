import { TOKEN_EXPIRES_KEY, TOKEN_KEY, clearToken, setToken } from './client'

// FIX(P1#10): switch token storage from localStorage to sessionStorage so
// the token does not persist across browser restarts and is scoped to a
// single tab. localStorage is shared across tabs and persists indefinitely
// until explicitly cleared, which makes any stored XSS payload trivially
// exfiltrate the token. sessionStorage still does not protect against an
// active XSS, but it bounds the blast radius (no cross-tab leak, evicted
// when the tab closes) at zero cost. A proper httpOnly cookie path is
// tracked as a follow-up.
//
// We also clean up any token left over in localStorage from older builds
// so the upgrade does not leave a dangling secret behind.
const _store = window.sessionStorage

function _migrateLegacy() {
  try {
    const legacy = window.localStorage.getItem(TOKEN_KEY)
    if (legacy) {
      window.localStorage.removeItem(TOKEN_KEY)
      window.localStorage.removeItem(TOKEN_EXPIRES_KEY)
    }
  } catch {
    // sessionStorage / localStorage may be disabled (private mode quotas);
    // failing silently keeps the SPA usable on the login page.
  }
}

export function saveAuth(token, expiresIn) {
  _migrateLegacy()
  const expiresAt = Date.now() + (expiresIn * 1000)
  _store.setItem(TOKEN_KEY, token)
  _store.setItem(TOKEN_EXPIRES_KEY, String(expiresAt))
  setToken(token)
}

export function clearStoredAuth() {
  _store.removeItem(TOKEN_KEY)
  _store.removeItem(TOKEN_EXPIRES_KEY)
  clearToken()
}

export function restoreAuth() {
  _migrateLegacy()
  const token = _store.getItem(TOKEN_KEY)
  const expiresAt = parseInt(_store.getItem(TOKEN_EXPIRES_KEY) || '0', 10)
  if (!token || !expiresAt || Date.now() >= expiresAt) {
    clearStoredAuth()
    return false
  }
  setToken(token)
  return true
}
