// FIX(P2#5): device list state and the actions that mutate it (refresh,
// rename, regroup, delete, batch delete, select toggling) extracted out
// of App.vue. The component keeps the Vue-specific bits (search bar
// `v-model`, click handlers) but no longer owns the data plumbing.
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import {
  batchDeleteDevices,
  deleteDeviceById,
  fetchDashboard,
  setDeviceAlias,
  setDeviceGroup
} from '../api/endpoints'
import { displayName } from '../utils/format'
import { useNoticeStore } from './notice'

export const useDevicesStore = defineStore('devices', () => {
  const devices = ref([])
  const numbers = ref([])
  const devicesTotal = ref(0)
  const searchText = ref('')
  const groupFilter = ref('all')
  const selectedIds = ref([])
  const loading = ref(false)

  const uniqueGroups = computed(() => {
    const groupSet = new Set(['all'])
    devices.value.forEach(device => {
      if (device.grp) groupSet.add(device.grp)
    })
    return Array.from(groupSet)
  })

  const onlineCount = computed(
    () => devices.value.filter(device => device.status === 'online').length
  )
  const offlineCount = computed(
    () => devices.value.filter(device => device.status !== 'online').length
  )
  const selectedCount = computed(() => selectedIds.value.length)

  const filteredDevices = computed(() => {
    return devices.value.filter(device => {
      const keyword = searchText.value.toLowerCase()
      const matchSearch = !keyword
        || (device.ip || '').toLowerCase().includes(keyword)
        || (device.mac || '').toLowerCase().includes(keyword)
        || (device.devId || '').toLowerCase().includes(keyword)
        || (device.alias || '').toLowerCase().includes(keyword)
        || (device.sims && device.sims.sim1 && device.sims.sim1.number || '').includes(keyword)
        || (device.sims && device.sims.sim2 && device.sims.sim2.number || '').includes(keyword)
        || (device.sims && device.sims.sim1 && device.sims.sim1.operator || '').toLowerCase().includes(keyword)
        || (device.sims && device.sims.sim2 && device.sims.sim2.operator || '').toLowerCase().includes(keyword)
      const matchGroup = groupFilter.value === 'all' || device.grp === groupFilter.value
      return matchSearch && matchGroup
    })
  })

  const filteredNumbers = computed(() => {
    return numbers.value.filter(item => {
      const keyword = searchText.value.toLowerCase()
      return !keyword
        || (item.number || '').includes(keyword)
        || (item.operator || '').toLowerCase().includes(keyword)
        || (item.deviceName || '').toLowerCase().includes(keyword)
    })
  })

  function _detail(e, fallback) {
    return (e && e.response && e.response.data && e.response.data.detail) || fallback
  }

  async function refresh() {
    const notice = useNoticeStore()
    loading.value = true
    try {
      const data = await fetchDashboard()
      devices.value = data.devices
      numbers.value = data.numbers
      devicesTotal.value = data.devicesTotal || 0
      // FIX(P1#7): warn the operator when the device list was capped by
      // the server-side pagination window so they aren't silently working
      // with a partial view.
      if (data.devicesTotal && data.devicesTotal > data.devices.length) {
        notice.set(
          `设备总数 ${data.devicesTotal}，仅显示前 ${data.devices.length} 条；请缩小过滤范围`,
          'info'
        )
      }
    } catch (e) {
      if (!(e && e.response && e.response.status === 401)) {
        notice.set('获取数据失败，请检查网络连接', 'err')
      }
    } finally {
      loading.value = false
    }
  }

  function toggleSelect(id) {
    const idx = selectedIds.value.indexOf(id)
    if (idx > -1) {
      selectedIds.value.splice(idx, 1)
    } else {
      selectedIds.value.push(id)
    }
  }

  function toggleSelectAll() {
    const list = filteredDevices.value
    const isAllSelected = selectedCount.value === list.length && list.length > 0
    selectedIds.value = isAllSelected ? [] : list.map(device => device.id)
  }

  function isSelected(id) {
    return selectedIds.value.includes(id)
  }

  function clearSelection() {
    selectedIds.value = []
  }

  async function rename(device, alias) {
    const notice = useNoticeStore()
    try {
      await setDeviceAlias(device.id, alias)
      notice.set('已更新别名', 'ok')
      await refresh()
    } catch (e) {
      notice.set(_detail(e, '更新失败'), 'err')
    }
  }

  async function regroup(device, group) {
    const notice = useNoticeStore()
    try {
      await setDeviceGroup(device.id, group)
      notice.set('已更新分组', 'ok')
      await refresh()
    } catch (e) {
      notice.set(_detail(e, '更新失败'), 'err')
    }
  }

  async function deleteOne(device) {
    const notice = useNoticeStore()
    loading.value = true
    try {
      await deleteDeviceById(device.id)
      notice.set('已删除', 'ok')
      await refresh()
    } catch (e) {
      notice.set(_detail(e, '删除失败'), 'err')
    } finally {
      loading.value = false
    }
  }

  async function batchDeleteSelected() {
    const notice = useNoticeStore()
    const total = selectedCount.value
    loading.value = true
    try {
      const response = await batchDeleteDevices(selectedIds.value)
      const deleted = response.data && response.data.deleted ? response.data.deleted : 0
      notice.set(`删除完成：${deleted}/${total}`, deleted ? 'ok' : 'warn')
      selectedIds.value = []
      await refresh()
    } catch (e) {
      notice.set(_detail(e, e.message || '删除失败'), 'err')
    } finally {
      loading.value = false
    }
  }

  return {
    devices,
    numbers,
    devicesTotal,
    searchText,
    groupFilter,
    selectedIds,
    loading,
    uniqueGroups,
    onlineCount,
    offlineCount,
    selectedCount,
    filteredDevices,
    filteredNumbers,
    refresh,
    toggleSelect,
    toggleSelectAll,
    isSelected,
    clearSelection,
    rename,
    regroup,
    deleteOne,
    batchDeleteSelected,
    displayName
  }
})
