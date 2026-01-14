# 变更日志

本文件记录 BSOD Analyzer 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2024-01-XX

### 新增
- **核心分析引擎**
  - Minidump 文件解析（通过 `minidump` 库）
  - 完整内存转储文件支持（PAGEDU64 格式）
  - 内核转储文件支持（通过 `kdmp-parser` 库）
  - 自动检测转储文件格式

- **智能驱动检测**
  - 多策略问题驱动定位（堆栈分析 → 已知问题库 → 地址匹配）
  - 内置已知问题驱动数据库
  - 驱动程序分类（图形、网络、存储、音频等）
  - 可扩展的 JSON 驱动知识库

- **崩溃分析功能**
  - Bugcheck 代码识别与描述
  - 堆栈跟踪分析
  - 置信度评分系统
  - 修复建议生成

- **AI 辅助诊断**
  - 集成智谱 AI GLM-4.7 模型
  - 深度技术分析
  - 中文可操作的修复步骤
  - GUI 和命令行双模式指导

- **命令行工具**
  - `analyze` - 分析单个转储文件
  - `scan` - 自动扫描系统崩溃文件
  - `batch` - 批量分析目录
  - `history` - 查看崩溃历史记录
  - `patterns` - 崩溃模式分析
  - `config` - 显示当前配置

- **数据存储**
  - SQLite 数据库存储分析历史
  - 崩溃模式识别与统计
  - JSON 格式报告导出

- **配置管理**
  - 环境变量支持
  - .env 文件配置
  - 配置优先级：环境变量 > .env > 默认值

### 系统扫描位置
- `C:\Windows\Minidump` - Minidump 文件默认位置
- `C:\Windows\MEMORY.DMP` - 完整内存转储
- `C:\Windows\LiveKernelReports` - 实时内核崩溃报告
- `~\.bsod_analyzer\dumps\` - 用户配置目录
- 当前工作目录 - 开发测试

### 支持的 Bugcheck 代码
- `0x0A` - IRQL_NOT_LESS_OR_EQUAL
- `0x3B` - SYSTEM_SERVICE_EXCEPTION
- `0xD1` - DRIVER_IRQL_NOT_LESS_OR_EQUAL
- `0x50` - PAGE_FAULT_IN_NONPAGED_AREA
- `0x124` - WHEA_UNCORRECTABLE_ERROR
- `0x2D` - HARDWARE_PROFILE_DISK_SIZE_ERROR
- 以及更多...

### 已知限制
- PAGEDU64 格式仅支持提取基本崩溃信息（bugcheck 代码、参数）
- 完整内存转储的驱动列表和堆栈跟踪提取未实现
- 32 位内核转储（PAGEDU48）不支持

---

## [未来版本]

### 计划新增
- [ ] 更多 AI 模型支持
- [ ] Web 界面
- [ ] 实时监控功能
- [ ] 自动驱动更新检测
- [ ] 社区驱动知识库

### 计划改进
- [ ] 完整内存转储的完整分析支持
- [ ] 更详细的堆栈跟踪解析
- [ ] 性能优化
- [ ] 多语言支持

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

---

## 链接

- [GitHub 仓库](https://github.com/Harryleft/blue-screen-what-happen)
- [问题反馈](https://github.com/Harryleft/blue-screen-what-happen/issues)
