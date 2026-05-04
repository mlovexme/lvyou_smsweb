const { createApp, ref, computed, nextTick, onMounted, watch } = Vue;

// Configure marked for safe rendering
marked.setOptions({
  highlight: function (code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    }
    return hljs.highlightAuto(code).value;
  },
  breaks: true,
});

const app = createApp({
  setup() {
    const sidebarCollapsed = ref(false);
    const conversations = ref([]);
    const currentConvId = ref(null);
    const messages = ref([]);
    const userInput = ref('');
    const loading = ref(false);
    const showModelDropdown = ref(false);
    const deepThinking = ref(false);
    const relayConnected = ref(false);
    const selectedModel = ref('mimo-v2.5-pro');
    const chatMessages = ref(null);
    const inputArea = ref(null);

    const models = ref([
      { id: 'mimo-v2.5-pro', name: 'MiMo-v2.5-Pro', desc: '最强推理能力' },
      { id: 'mimo-v2-flash', name: 'MiMo-v2-Flash', desc: '快速响应' },
      { id: 'mimo-v2-pro', name: 'MiMo-v2-Pro', desc: '均衡模型' },
    ]);

    const currentModelName = computed(() => {
      const m = models.value.find(x => x.id === selectedModel.value);
      return m ? m.name || m.id : selectedModel.value;
    });

    // ── API helpers ──────────────────────────────────

    async function api(method, path, body) {
      const opts = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) opts.body = JSON.stringify(body);
      const resp = await fetch(path, opts);
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`${resp.status}: ${text}`);
      }
      return resp.json();
    }

    // ── Conversations ────────────────────────────────

    async function loadConversations() {
      try {
        conversations.value = await api('GET', '/api/conversations');
      } catch (e) {
        console.error('Failed to load conversations:', e);
      }
    }

    async function newConversation() {
      currentConvId.value = null;
      messages.value = [];
      userInput.value = '';
      nextTick(() => inputArea.value?.focus());
    }

    async function selectConversation(id) {
      try {
        const data = await api('GET', `/api/conversations/${id}`);
        currentConvId.value = id;
        messages.value = data.messages || [];
        if (data.model) selectedModel.value = data.model;
        nextTick(scrollToBottom);
      } catch (e) {
        console.error('Failed to load conversation:', e);
      }
    }

    async function deleteConversation(id) {
      try {
        await api('DELETE', `/api/conversations/${id}`);
        if (currentConvId.value === id) {
          currentConvId.value = null;
          messages.value = [];
        }
        await loadConversations();
      } catch (e) {
        console.error('Failed to delete conversation:', e);
      }
    }

    // ── Chat ─────────────────────────────────────────

    async function sendMessage() {
      const text = userInput.value.trim();
      if (!text || loading.value) return;

      // Optimistic: add user message immediately
      messages.value.push({ role: 'user', content: text });
      userInput.value = '';
      loading.value = true;
      nextTick(scrollToBottom);

      // Reset textarea height
      if (inputArea.value) inputArea.value.style.height = 'auto';

      try {
        const data = await api('POST', '/api/chat', {
          conversation_id: currentConvId.value,
          message: text,
          model: selectedModel.value,
          enable_thinking: deepThinking.value,
        });

        // If new conversation was created, set it
        if (!currentConvId.value && data.conversation_id) {
          currentConvId.value = data.conversation_id;
        }

        messages.value.push(data.message);
        await loadConversations();
      } catch (e) {
        messages.value.push({
          role: 'assistant',
          content: `**Error:** ${e.message}\n\n请检查 AI 服务是否已启动 (mimo_relay)。`,
        });
      } finally {
        loading.value = false;
        nextTick(scrollToBottom);
      }
    }

    // ── Helpers ───────────────────────────────────────

    function renderMarkdown(text) {
      if (!text) return '';
      return marked.parse(text);
    }

    function scrollToBottom() {
      if (chatMessages.value) {
        chatMessages.value.scrollTop = chatMessages.value.scrollHeight;
      }
    }

    function autoResize(e) {
      const el = e.target;
      el.style.height = 'auto';
      el.style.height = Math.min(el.scrollHeight, 200) + 'px';
    }

    function selectModel(id) {
      selectedModel.value = id;
      showModelDropdown.value = false;
    }

    async function checkHealth() {
      try {
        const data = await api('GET', '/api/health');
        relayConnected.value = data.relay_connected;
      } catch {
        relayConnected.value = false;
      }
    }

    async function loadModels() {
      try {
        const data = await api('GET', '/api/models');
        if (data.data && data.data.length > 0) {
          models.value = data.data.map(m => ({
            id: m.id,
            name: m.name || m.id,
            desc: m.desc || '',
          }));
        }
      } catch {
        // use defaults
      }
    }

    // Close model dropdown on outside click
    document.addEventListener('click', () => {
      showModelDropdown.value = false;
    });

    onMounted(async () => {
      await Promise.all([loadConversations(), checkHealth(), loadModels()]);
      // Periodic health check
      setInterval(checkHealth, 30000);
    });

    return {
      sidebarCollapsed,
      conversations,
      currentConvId,
      messages,
      userInput,
      loading,
      showModelDropdown,
      deepThinking,
      relayConnected,
      selectedModel,
      models,
      currentModelName,
      chatMessages,
      inputArea,
      newConversation,
      selectConversation,
      deleteConversation,
      sendMessage,
      renderMarkdown,
      autoResize,
      selectModel,
    };
  },
});

app.mount('#app');
