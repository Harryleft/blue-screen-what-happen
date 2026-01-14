# BSOD Analyzer - Windows蓝屏分析工具

一个强大的Windows蓝屏(BSOD)转储文件分析工具，帮助你快速定位导致系统崩溃的程序或驱动程序。

## 功能特性

- **智能驱动定位** - 多策略精确定位问题驱动程序
- **基础分析** - 解析minidump文件，显示蓝屏代码、崩溃原因
- **历史记录** - SQLite数据库存储并分析多次崩溃
- **AI辅助诊断** - 集成智谱AI GLM-4.7提供深度技术分析
- **置信度评估** - 帮助你判断分析结果的可信度
- **模式识别** - 识别系统性的重复崩溃问题

## 安装

### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/blue-screen-what-happen.git
cd blue-screen-what-happen

# 安装依赖
pip install -r requirements.txt

# 安装工具
pip install -e .
```

### 配置AI功能（可选）

复制 `.env.example` 到 `.env` 并配置你的API密钥：

```bash
cp .env.example .env
```

编辑 `.env` 文件：

```
ZHIPU_API_KEY=your_api_key_here
AI_MODEL=glm-4.7
```

获取API密钥：https://open.bigmodel.cn/

## 使用方法

### 分析单个dump文件

```bash
# 基础分析
bsod analyze dump.dmp

# 启用AI分析
bsod analyze dump.dmp --ai

# 保存结果到数据库
bsod analyze dump.dmp --save

# 输出JSON格式
bsod analyze dump.dmp -o report.json -f json
```

### 批量分析

```bash
# 分析默认目录（C:/Windows/Minidump）
bsod batch "C:/Windows/Minidump"

# 限制文件数量
bsod batch "./dumps" --limit 5

# 保存所有结果
bsod batch "./dumps" --save
```

### 查看历史记录

```bash
# 显示最近20条记录
bsod history

# 显示最近7天的记录
bsod history --days 7

# 显示更多记录
bsod history --limit 50
```

### 分析崩溃模式

```bash
# 分析最近30天的崩溃模式
bsod patterns

# 使用AI进行模式分析
bsod patterns --days 7 --ai
```

### 查看配置

```bash
bsod config
```

## 输出示例

```
╭─────────────────────────────────────────────────────────────────╮
│                        基本信息                                 │
╞═══════════════════════════════════════════════════════════════╡
│   文件:     C:/Windows/Minidump/011524-12345-01.dmp            │
│   时间:     2024-01-15 14:32:18                                │
│   系统:     10.0.22621                                         │
│   CPU:      AMD64 (8 核心)                                     │
╰─────────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 崩溃信息  ┃                                                      ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 项目      │ 值                                                  │
├───────────┼────────────────────────────────────────────────────┤
│ Bugcheck  │ 0xD1                                               │
│ 名称      │ DRIVER_IRQL_NOT_LESS_OR_EQUAL                      │
│ 崩溃地址  │ 0xFFFFF80D12345678                                 │
└───────────┴────────────────────────────────────────────────────┘

╭─────────────────────────────────────────────────────────────────╮
│                      疑似问题驱动                               │
╞═══════════════════════════════════════════════════════════════╡
│   名称:     nvlddmkm.sys                                       │
│   基地址:   0xFFFFF80012345000                                 │
│   已知问题: 是                                                  │
╰─────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────────────────────────────╮
│                       崩溃原因                                  │
╞═══════════════════════════════════════════════════════════════╡
│ A driver tried to access a memory address using an invalid     │
│ IRQL. Known issue: NVIDIA GPU driver - known to cause BSOD     │
╰─────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────────────────────────────╮
│                       修复建议                                  │
╞═══════════════════════════════════════════════════════════════╡
│ 1. Update all device drivers                                   │
│ 2. Driver-specific: Update to latest NVIDIA driver or          │
│    perform clean install                                       │
│ 3. Check Event Viewer for driver errors                        │
╰─────────────────────────────────────────────────────────────────╯

分析置信度: 85%
```

## 项目结构

```
bsod_analyzer/
├── cli/              # CLI命令行接口
├── core/             # 核心分析引擎
│   ├── parser.py     # Minidump解析器
│   ├── analyzer.py   # 分析引擎
│   ├── driver_detector.py  # 驱动检测器
│   └── bugcheck_kb.py      # Bugcheck代码知识库
├── ai/               # AI分析模块
├── database/         # 数据库管理
├── utils/            # 工具模块
└── knowledge/        # 知识库数据
```

## 支持的Bugcheck代码

工具支持所有常见的Windows bugcheck代码，包括：

- `0x0A` - IRQL_NOT_LESS_OR_EQUAL
- `0x3B` - SYSTEM_SERVICE_EXCEPTION
- `0xD1` - DRIVER_IRQL_NOT_LESS_OR_EQUAL
- `0x50` - PAGE_FAULT_IN_NONPAGED_AREA
- `0x124` - WHEA_UNCORRECTABLE_ERROR
- 以及更多...

## 依赖项

- Python 3.10+
- minidump - Minidump文件解析
- Click - CLI框架
- Rich - 终端美化
- zhipuai - 智谱AI SDK (可选)

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 代码格式化
black bsod_analyzer/

# 类型检查
mypy bsod_analyzer/
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 致谢

- [skelsec/minidump](https://github.com/skelsec/minidump) - Minidump解析库
- 智谱AI - 提供AI分析能力
