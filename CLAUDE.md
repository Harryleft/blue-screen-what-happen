# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 提供在此代码库中工作的指导。

## 项目概述

BSOD Analyzer 是一个 Windows 蓝屏崩溃转储分析工具，用于识别系统崩溃的根本原因。它可以解析 Windows minidump 文件，检测问题驱动程序，并提供 AI 驱动的技术分析。

### 常用开发命令

```bash
# 安装依赖
pip install -r requirements.txt

# 以开发模式安装
pip install -e .

# 运行工具
bsod analyze crash.dmp
bsod analyze crash.dmp --ai --save
bsod batch "C:/Windows/Minidump" --limit 5
bsod history --days 7

# 运行测试
pytest

# 代码格式化
black bsod_analyzer/

# 类型检查
mypy bsod_analyzer/
```

### 配置

复制 `.env.example` 到 `.env` 并配置：
- `ZHIPU_API_KEY` - AI 分析所需的密钥（从 https://open.bigmodel.cn/ 获取）
- `DATABASE_PATH` - SQLite 数据库位置，用于崩溃历史
- `AI_MODEL` - 使用的模型（默认：`glm-4.7`）

## 架构

### 核心组件

**`bsod_analyzer/core/`** - 核心分析引擎

- **`parser.py`** - 包含 `IMinidumpParser` 接口和 `create_parser()` 工厂函数。包含使用 `skelsec/minidump` 库的 `MinidumpParser` 类，用于标准 minidump 文件（签名：`MDMP`）。工厂函数自动检测转储格式并返回相应的解析器。

- **`pagedump_parser.py`** - `PageDumpParser` 类，用于 Windows 完整内存转储文件（PAGEDU64 格式）。实现 `IMinidumpParser` 接口。可以从转储头提取基本崩溃信息（bugcheck 代码、参数）。限制：由于内核内存遍历的复杂性，未实现驱动列表和堆栈跟踪提取。

- **`kernel_dump_parser.py`** - 使用 `kdmp-parser` 库的 `KernelDumpParser` 类。处理内核转储格式。注意：不支持完整内存转储（`PAGEDU64` 签名）——仅支持通过 WinDbg `.dump /f` 创建的 minidump 和内核转储。

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
- **`prompts.py`** - `PromptTemplates`，用于生成 AI 提示
- **`analyzer.py`** - `AIAnalyzer` 封装 AI 提供程序，执行崩溃分析、模式分析和特定驱动程序分析

### CLI (`bsod_analyzer/cli/main.py`)

基于 Click 的 CLI，包含命令：
- `bsod analyze <dump>` - 分析单个转储文件
- `bsod batch <dir>` - 批量分析目录
- `bsod history` - 查看崩溃历史
- `bsod patterns` - 分析崩溃模式（带 AI 选项）

### 数据库 (`bsod_analyzer/database/`)

基于 SQLite 的存储，用于崩溃历史和模式分析。

## 重要说明

### 转储格式支持

该工具目前支持：
- **Minidump** 文件（签名 `MDMP`），通过 `minidump` 库
- **完整内存转储** 文件（签名 `PAGEDU64`），通过自定义 `PageDumpParser`
- **内核转储** 文件，通过 `kdmp-parser` 库（有限支持）

`parser.py` 中的 `create_parser()` 工厂函数通过读取前 8 个字节自动检测格式：
- `MDMP` → MinidumpParser（标准 minidump 文件）
- `PAGEDU64` → PageDumpParser（Windows 完整内存转储）
- `PAGEDU48` → 错误（不支持 32 位内核转储）

**关于 PAGEDU64 格式的说明：**
- `PageDumpParser`（`pagedump_parser.py`）为 PAGEDU64 文件提供基本解析功能
- 它可以从转储头提取崩溃信息（bugcheck 代码、参数）
- **限制**：未实现 PAGEDU64 的驱动列表和堆栈跟踪提取
  - 这些需要遍历内核内存结构（PS_LOADED_MODULE_LIST），这很复杂
  - 对于 PAGEDU64 文件的完整分析，请使用 WinDbg 或类似工具
- 当你需要从完整内存转储获取基本崩溃信息（bugcheck 代码、参数）时，使用 PAGEDU64 解析器

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
