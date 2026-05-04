# MiMo AI 聊天助手

一个类似 [SCNet AI 助手](https://www.scnet.cn/ui/chatbot/) 的 Web 聊天界面，后端对接 `mimo_relay.py` 的 OpenAI 兼容 API。

## 功能

- 多轮对话，支持对话历史管理（新建、切换、删除）
- 模型选择（MiMo-v2.5-Pro / v2-Flash / v2-Pro）
- 深度思考开关
- Markdown 渲染 + 代码高亮
- AI 服务连接状态检测
- 响应式布局，支持移动端

## 架构

```
浏览器 (Vue 3 SPA)
   │
   ▼
chatbot/server.py (FastAPI, 默认 9000 端口)
   │  • 提供前端静态文件
   │  • 代理聊天请求
   │  • 管理对话历史 (JSON 存储)
   ▼
mimo_relay.py (OpenAI 兼容 API, 默认 8800 端口)
   │
   ▼
小米 MiMo Chat API
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r chatbot/requirements.txt
```

### 2. 启动 mimo_relay（AI 后端）

```bash
python3 mimo_relay.py --accounts accounts.json --port 8800
```

### 3. 启动聊天服务

```bash
python3 -m chatbot.server --relay-url http://localhost:8800 --port 9000
```

### 4. 访问

打开浏览器访问 `http://localhost:9000`

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MIMO_RELAY_URL` | `http://localhost:8800` | mimo_relay 代理地址 |

## 目录结构

```
chatbot/
├── server.py          # FastAPI 后端服务
├── requirements.txt   # Python 依赖
├── README.md          # 本文档
├── __init__.py
├── data/              # 对话数据（自动创建）
│   └── conversations.json
└── static/            # 前端静态文件
    ├── index.html     # 主页面
    ├── style.css      # 样式
    └── app.js         # Vue 3 应用逻辑
```
