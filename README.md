# README - 蓝屏发生了什么？(Blue Screen What Happen)

> Windows 蓝屏转储文件分析工具，利用 AI 告诉你为什么会蓝屏

一个Vibe Coding项目，帮快速分析 Windows 蓝屏崩溃的根因。

---

## 快速开始

```bash
# 安装
pip install -e .

# 配置 AI 密钥（获取：https://open.bigmodel.cn/usercenter/proj-mgmt/apikeys）
cp .env.example .env
# 编辑 .env 填入 ZHIPU_API_KEY
```

---

## 核心命令

### 1️⃣ 自动扫描并分析（推荐）

```bash
# 扫描系统崩溃文件目录，列出所有 dump 文件
bsod scan

# 扫描并分析最新的崩溃文件
bsod scan --analyze

# 扫描 + AI 分析 + 保存结果（推荐使用）
bsod scan -a --ai --save
```

### 2️⃣ AI 深度分析（单个文件）

```bash
# 基础分析
bsod analyze crash.dmp

# AI 深度分析（推荐）
bsod analyze crash.dmp --ai

# 分析并保存到数据库
bsod analyze crash.dmp --ai --save
```

### 3️⃣ 批量分析

```bash
# 分析整个目录
bsod batch "C:/Windows/Minidump"

# 限制数量 + AI + 保存
bsod batch "C:/Windows/Minidump" --limit 5 --ai --save
```

### 4️⃣ 查看历史

```bash
# 查看最近的崩溃记录
bsod history

# 最近 7 天的记录
bsod history --days 7

# AI 模式分析
bsod patterns --ai
```

### 5️⃣ 其他命令

```bash
bsod config          # 查看当前配置
bsod patterns        # 分析崩溃模式
```

---

## 扫描路径

`bsod scan` 会自动扫描以下位置：

| 路径 | 说明 |
|------|------|
| `C:\Windows\Minidump` | 标准 minidump 位置 |
| `C:\Windows\MEMORY.DMP` | 完整内存转储 |
| `C:\Windows\LiveKernelReports` | 实时内核报告 |
| `~\.bsod_analyzer\dumps\` | 用户目录 |

---

## AI 输出示例

```
╭─────────────────────────────────────────────────────────────────╮
│                      AI 深度分析                                │
╞═══════════════════════════════════════════════════════════════╡
│                                                                 │
│  根本原因分析：                                                 │
│    崩溃由 NVIDIA 显卡驱动 nvlddmkm.sys 在 IRQL 错误级别        │
│    访问无效内存地址导致。这是典型的驱动程序内存管理错误。       │
│                                                                 │
│  修复步骤：                                                     │
│    1. 打开设备管理器 → 显示适配器 → NVIDIA GeForce              │
│    2. 右键 → 卸载设备 → 勾选"删除驱动程序软件"                 │
│    3. 重启后从 NVIDIA 官网下载最新驱动并安装                   │
│    4. 如果问题依旧，尝试使用 DDU 工具彻底清理驱动              │
│                                                                 │
│  验证方法：                                                     │
│    运行 3-7 天，观察是否再次蓝屏                               │
│                                                                 │
│  备选方案：                                                     │
│    - 暂时使用 Windows Update 提供的驱动版本                    │
│    - 检查显卡是否超频，恢复默认设置                             │
│                                                                 │
╰─────────────────────────────────────────────────────────────────╯
```

---

## 配置说明

编辑 `.env` 文件：

```bash
# 必需：智谱 AI API 密钥
ZHIPU_API_KEY=your_api_key_here

# 可选：AI 模型（默认 glm-4.7）
AI_MODEL=glm-4.7

# 可选：数据库路径
DATABASE_PATH=~/.bsod_analyzer/crashes.db
```

---

## 项目结构

```
bsod_analyzer/
├── cli/          # 命令行接口
├── core/         # 解析和分析引擎
├── ai/           # AI 分析模块
├── database/     # SQLite 存储
└── knowledge/    # 驱动问题知识库
```

---

## 支持的崩溃代码

- `0x0A` - IRQL_NOT_LESS_OR_EQUAL
- `0x3B` - SYSTEM_SERVICE_EXCEPTION
- `0xD1` - DRIVER_IRQL_NOT_LESS_OR_EQUAL
- `0x50` - PAGE_FAULT_IN_NONPAGED_AREA
- `0x124` - WHEA_UNCORRECTABLE_ERROR
- ……

---

## 依赖

- Python 3.10+
- [minidump](https://github.com/skelsec/minidump) - 转储文件解析
- [zhipuai](https://github.com/MetaGLM/zhipuai-python) - 智谱 AI

---

## 免责声明

这是一个Vibe Coding项目，不提供任何保证。AI 分析结果仅供参考，请结合实际情况判断。

---

## 协议

MIT License 
