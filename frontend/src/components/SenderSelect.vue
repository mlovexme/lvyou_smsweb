<template>
  <select :value="value" class="form-select" @change="emit('update:value', $event.target.value)">
    <option value="">选择发送卡号</option>
    <option
      v-for="n in numbers"
      :key="String(n.deviceId) + '-' + String(n.slot)"
      :value="String(n.deviceId) + '|' + String(n.slot)"
    >
      {{ n.number }} ({{ n.operator || '未知' }})
    </option>
  </select>
</template>

<script setup>
defineProps({
  numbers: { type: Array, default: () => [] },
  value: { type: String, default: '' }
})

const emit = defineEmits(['update:value'])
</script>
