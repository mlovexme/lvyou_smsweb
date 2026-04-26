import axios from 'axios'

export const api = axios.create({ baseURL: '' })

export const TOKEN_KEY = 'board_mgr_token'
export const TOKEN_EXPIRES_KEY = 'board_mgr_token_expires'

export function setToken(token) {
  api.defaults.headers.common.Authorization = 'Bearer ' + token
}

export function clearToken() {
  delete api.defaults.headers.common.Authorization
}
