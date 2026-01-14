# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 提供在此代码库中工作的指导。

## 项目概述

BSOD Analyzer 是一个 Windows 蓝屏崩溃转储分析工具，用于识别系统崩溃的根本原因。它可以解析 Windows minidump 文件、完整内存转储文件（PAGEDU64），检测问题驱动程序，并提供 AI 驱动的技术分析。

### 常用开发命令

```bash
# 安装依赖
pip install -r requirements.txt

# 以开发模式安装
pip install -e .

# 运行工具
bsod analyze crash.dmp              # 分析单个文件
bsod analyze crash.dmp --ai --save # 带 AI 分析并保存
bsod scan                           # 扫描系统崩溃文件
bsod scan --analyze                 # 扫描并分析最新崩溃
bsod scan -a --ai --save           # 扫描、AI 分析并保存
bsod batch "C:/Windows/Minidump" --limit 5  # 批量分析目录
bsod history --days 7               # 查看崩溃历史

# 运行测试
pytest

# 代码格式化
black bsod_analyzer/

# 类型检查
mypy bsod_analyzer/
```

### 配置

#### 环境变量配置

通过 Windows 系统环境变量配置（推荐）：
- `ZHIPU_API_KEY` - AI 分析密钥（从 https://open.bigmodel.cn/ 获取）
- `DATABASE_PATH` - SQLite 数据库路径
- `AI_MODEL` - 模型名称（默认：`glm-4.7`）

#### .env 文件配置

或复制 `.env.example` 到 `.env` 并配置。

配置优先级：环境变量 > .env 文件 > 代码默认值

## 架构

### 核心组件

**`bsod_analyzer/core/`** - 核心分析引擎

- **`parser.py`** - 包含 `IMinidumpParser` 接口和 `create_parser()` 工厂函数。`create_parser()` 自动检测转储文件格式并返回相应解析器：
  - `MDMP` → `MinidumpParser`（标准 minidump）
  - `PAGEDU64` → `PageDumpParser`（完整内存转储）

- **`pagedump_parser.py`** - `PageDumpParser` 类，用于 Windows 完整内存转储文件（PAGEDU64 格式）。可从转储头提取崩溃信息（bugcheck 代码、参数）。**限制**：未实现驱动列表和堆栈跟踪提取（需要遍历内核内存结构）。

- **`kernel_dump_parser.py`** - `KernelDumpParser` 类，使用 `kdmp-parser` 库处理内核转储格式。

- **`analyzer.py`** - `BSODAnalyzer` 协调完整的分析流程：
  1. 解析 minidump 信息
  2. 提取崩溃信息
  3. 获取已加载的驱动程序
  4. 获取堆栈跟踪
  5. 查找可疑驱动程序（多策略：堆栈顶部帧 → 已知问题驱动 → 崩溃地址）
  6. 确定原因
  7. 生成建议
  8. 计算置信度分数

- **`driver_detector.py`** - `DriverDetector` 使用以下方式识别问题驱动程序：
  - 内置的 `KNOWN_BAD_DRIVERS` 字典
  - 从 `knowledge/known_bad_drivers.json` 加载的自定义数据库
  - 驱动分类（图形、网络、存储、音频、安全、虚拟化、系统）

- **`bugcheck_kb.py`** - `BugcheckKnowledgeBase` 提供 bugcheck 代码描述和建议。

### 数据模型 (`bsod_analyzer/database/models.py`)

核心数据类：
- `MinidumpInfo` - 基本转储文件信息
- `CrashInfo` - 崩溃详细信息（bugcheck 代码、地址、参数）
- `DriverInfo` - 驱动程序/模块信息
- `StackFrame`, `StackTrace` - 堆栈跟踪数据
- `AnalysisResult` - 完整的分析结果，包含置信度分数
- `CrashHistory` - 数据库记录格式

### AI 分析 (`bsod_analyzer/ai/`)

- **`providers.py`** - `IAIProvider` 接口和 `AIProviderFactory`，用于创建 AI 提供程序实例
  - `max_tokens` 设置为 8192，确保响应完整
  - 系统提示设置为中文，要求提供具体可操作的修复建议

- **`prompts.py`** - `PromptTemplates`，用于生成 AI 提示
  - 要求 AI 按结构化格式输出：根因分析、技术解释、具体修复步骤、验证方法、备选方案
  - 要求每个步骤包含 GUI 和命令行两种操作方式
  - 要求提供完整的注册表路径、命令示例等具体信息

- **`analyzer.py`** - `AIAnalyzer` 封装 AI 提供程序，执行崩溃分析、模式分析和特定驱动程序分析

**AI 输出特点**：
- 全中文输出
- 具体可操作的修复步骤
- 每步包含：目的、具体操作、命令行方式、预期结果
- 提供验证修复的方法和观察时间
- 提供备选方案

### CLI (`bsod_analyzer/cli/main.py`)

基于 Click 的 CLI，支持 UTF-8 中文输出。包含命令：

| 命令 | 说明 | 示例 |
|------|------|------|
| `analyze` | 分析单个转储文件 | `bsod analyze crash.dmp --ai` |
| `scan` | **自动扫描系统崩溃文件** | `bsod scan --analyze` |
| `batch` | 批量分析目录 | `bsod batch "C:/Windows/Minidump"` |
| `history` | 查看崩溃历史 | `bsod history --days 7` |
| `patterns` | 分析崩溃模式 | `bsod patterns --ai` |
| `config` | 显示当前配置 | `bsod config` |

### 数据库 (`bsod_analyzer/database/`)

基于 SQLite 的存储，用于崩溃历史和模式分析。

## 重要说明

### 转储格式支持

该工具支持：
- **Minidump** 文件（签名 `MDMP`），通过 `minidump` 库
- **完整内存转储** 文件（签名 `PAGEDU64`），通过自定义 `PageDumpParser`
- **内核转储** 文件，通过 `kdmp-parser` 库（有限支持）

`parser.py` 中的 `create_parser()` 工厂函数通过读取前 8 个字节自动检测格式：
- `MDMP` → `MinidumpParser`
- `PAGEDU64` → `PageDumpParser`
- `PAGEDU48` → 错误（不支持 32 位内核转储）

**PAGEDU64 格式限制：**
- 可提取基本崩溃信息（bugcheck 代码、参数）
- 未实现驱动列表和堆栈跟踪提取（需要遍历内核内存结构）
- 对于完整分析，请使用 WinDbg

### 系统崩溃文件扫描

`scan` 命令会自动扫描以下位置：

| 位置 | 说明 |
|------|------|
| `C:\Windows\Minidump` | Minidump 文件（默认位置） |
| `C:\Windows\MEMORY.DMP` | 完整内存转储 |
| `C:\Windows\LiveKernelReports` | 实时内核崩溃报告 |
| `~\.bsod_analyzer\dumps\` | 用户配置目录 |
| 当前工作目录 | 用于开发测试 |

**使用示例**：
```bash
# 扫描并列出崩溃文件
bsod scan

# 扫描并分析最新崩溃
bsod scan --analyze

# 扫描、AI 分析并保存
bsod scan -a --ai --save

# 显示所有文件
bsod scan --all
```

### 驱动检测策略

`BSODAnalyzer._find_suspected_driver()` 按顺序使用三种策略：
1. **堆栈顶部帧** - 检查顶部堆栈帧，尽可能排除系统驱动
2. **已知问题驱动** - 检查 `KNOWN_BAD_DRIVERS` 数据库
3. **崩溃地址** - 查找包含崩溃地址的驱动程序

### 置信度计算

基础置信度从 0.5 开始，然后：
- +0.15 如果存在带有帧的堆栈跟踪
- +0.15 如果找到可疑驱动程序
- +0.25 如果可疑驱动程序是已知问题驱动
- +0.1 如果是常见 bugcheck 代码（0x0A、0x3B、0xD1、0x50、0x7E、0x1E）
- 上限为 1.0

### 扩展驱动知识库

将问题驱动程序添加到以下任一位置：
1. `bsod_analyzer/core/driver_detector.py` - `KNOWN_BAD_DRIVERS` 字典（代码）
2. `bsod_analyzer/knowledge/known_bad_drivers.json` - JSON 文件（用户可自定义）

格式：
```json
{
  "drivername.sys": {
    "issue": "问题描述",
    "recommendation": "修复方法"
  }
}
```

### 支持的 Bugcheck 代码

工具支持所有常见的 Windows bugcheck 代码，包括：

- `0x0A` - IRQL_NOT_LESS_OR_EQUAL
- `0x3B` - SYSTEM_SERVICE_EXCEPTION
- `0xD1` - DRIVER_IRQL_NOT_LESS_OR_EQUAL
- `0x50` - PAGE_FAULT_IN_NONPAGED_AREA
- `0x124` - WHEA_UNCORRECTABLE_ERROR
- `0x2D` - HARDWARE_PROFILE_DISK_SIZE_ERROR
- 以及更多...
