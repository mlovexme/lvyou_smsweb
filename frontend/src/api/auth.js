import { TOKEN_EXPIRES_KEY, TOKEN_KEY, clearToken, setToken } from './client'

export function saveAuth(token, expiresIn) {
  const expiresAt = Date.now() + (expiresIn * 1000)
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(TOKEN_EXPIRES_KEY, String(expiresAt))
  setToken(token)
}

export function clearStoredAuth() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(TOKEN_EXPIRES_KEY)
  clearToken()
}

export function restoreAuth() {
  const token = localStorage.getItem(TOKEN_KEY)
  const expiresAt = parseInt(localStorage.getItem(TOKEN_EXPIRES_KEY) || '0', 10)
  if (!token || !expiresAt || Date.now() >= expiresAt) {
    clearStoredAuth()
    return false
  }
  setToken(token)
  return true
}
