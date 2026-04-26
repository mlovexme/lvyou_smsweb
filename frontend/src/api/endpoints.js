import { api } from './client'

export async function loginApi(password) {
  const response = await api.post('/api/login', { username: 'admin', password })
  return response.data || {}
}

export function logoutApi() {
  return api.post('/api/logout')
}

export function healthApi() {
  return api.get('/api/health')
}

export async function fetchDashboard() {
  const [devicesResp, numbersResp] = await Promise.all([
    api.get('/api/devices'),
    api.get('/api/numbers')
  ])
  const devData = devicesResp.data
  const numData = numbersResp.data
  return {
    devices: Array.isArray(devData) ? devData : (devData.items || []),
    numbers: Array.isArray(numData) ? numData : (numData.items || [])
  }
}

export function startScan(payload) {
  return api.post('/api/scan/start', payload)
}

export function getScanStatus(scanId) {
  return api.get('/api/scan/status/' + scanId)
}

export function sendSms(payload) {
  return api.post('/api/sms/send-direct', payload)
}

export function dialDevice(payload) {
  return api.post('/api/tel/dial', payload)
}

export function setDeviceAlias(deviceId, alias) {
  return api.post('/api/devices/' + deviceId + '/alias', { alias })
}

export function setDeviceGroup(deviceId, group) {
  return api.post('/api/devices/' + deviceId + '/group', { group })
}

export function deleteDeviceById(deviceId) {
  return api.delete('/api/devices/' + deviceId)
}

export function checkOtaBatch(deviceIds) {
  return api.post('/api/devices/batch/ota/check', { device_ids: deviceIds })
}

export function upgradeOtaBatch(deviceIds) {
  return api.post('/api/devices/batch/ota/upgrade', { device_ids: deviceIds })
}

export function readDeviceConfigs(deviceIds) {
  return api.post('/api/devices/batch/config/read', { device_ids: deviceIds })
}

export function previewDeviceConfig(payload) {
  return api.post('/api/devices/batch/config/preview', payload)
}

export function previewConfigPreset(deviceIds, preset) {
  return api.post('/api/devices/batch/config/preset/preview', { device_ids: deviceIds, preset })
}

export function writeDeviceConfig(payload) {
  return api.post('/api/devices/batch/config/write', payload)
}

export function writeConfigPreset(deviceIds, preset) {
  return api.post('/api/devices/batch/config/preset/write', { device_ids: deviceIds, preset })
}

export function previewWifiBatch(payload) {
  return api.post('/api/devices/batch/wifi/preview', payload)
}

export function applyWifiBatch(payload) {
  return api.post('/api/devices/batch/wifi', payload)
}

export function batchDeleteDevices(deviceIds) {
  return api.post('/api/devices/batch/delete', { device_ids: deviceIds })
}

export function fetchDeviceDetail(deviceId) {
  return api.get('/api/devices/' + deviceId + '/detail')
}

export function saveDeviceSim(deviceId, payload) {
  return api.post('/api/devices/' + deviceId + '/sim', payload)
}
