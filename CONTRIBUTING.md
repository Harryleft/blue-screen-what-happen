# 贡献指南

感谢你对 BSOD Analyzer 的关注！我们欢迎任何形式的贡献。

## 如何贡献

### 报告问题

如果你发现了 Bug 或有功能建议：

1. 在 [Issues](https://github.com/Harryleft/blue-screen-what-happen/issues) 页面搜索是否已存在相似问题
2. 如果没有，创建新的 Issue，包含：
   - 清晰的标题
   - 详细的问题描述
   - 复现步骤（针对 Bug）
   - 系统环境信息（Windows 版本、Python 版本等）
   - 相关日志或截图

### 提交代码

#### 开发环境设置

```bash
# 1. Fork 并克隆仓库
git clone https://github.com/YOUR_USERNAME/blue-screen-what-happen.git
cd blue-screen-what-happen

# 2. 创建虚拟环境
python -m venv venv
venv\Scripts\activate  # Windows
# 或
source venv/bin/activate  # Linux/Mac

# 3. 安装开发依赖
pip install -e ".[dev]"

# 4. 安装 pre-commit hooks（可选）
pip install pre-commit
pre-commit install
```

#### 代码规范

本项目遵循以下规范：

- **Python 版本**: Python 3.10+
- **代码风格**: PEP 8，使用 `black` 格式化
- **行长度**: 100 字符
- **类型检查**: 使用 `mypy` 进行类型检查
- **导入顺序**: 使用 `ruff` 检查

```bash
# 格式化代码
black bsod_analyzer/

# 类型检查
mypy bsod_analyzer/

# 代码检查
ruff check bsod_analyzer/
```

#### 提交流程

1. **创建分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/your-bug-fix
   ```

2. **编写代码**
   - 添加必要的类型注解
   - 编写或更新测试
   - 更新相关文档

3. **运行测试**
   ```bash
   # 运行所有测试
   pytest

   # 运行特定测试文件
   pytest tests/test_parser.py

   # 生成覆盖率报告
   pytest --cov=bsod_analyzer --cov-report=html
   ```

4. **提交代码**
   ```bash
   git add .
   git commit -m "类型: 简短描述

   详细说明（可选）

   - 变更点 1
   - 变更点 2"
   ```

   **提交类型**:
   - `feat`: 新功能
   - `fix`: Bug 修复
   - `docs`: 文档更新
   - `style`: 代码格式调整
   - `refactor`: 重构
   - `test`: 测试相关
   - `chore`: 构建/工具相关

5. **推送并创建 PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   然后在 GitHub 上创建 Pull Request

#### Pull Request 检查清单

在提交 PR 前，请确认：

- [ ] 代码符合项目规范
- [ ] 所有测试通过
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] PR 描述清晰说明了变更内容
- [ ] CI 检查通过

## 添加已知问题驱动

如果你发现某个特定驱动程序经常导致蓝屏，可以将其添加到知识库：

### 方式一：修改代码

编辑 `bsod_analyzer/core/driver_detector.py`，在 `KNOWN_BAD_DRIVERS` 字典中添加：

```python
KNOWN_BAD_DRIVERS = {
    "problematic_driver.sys": {
        "issue": "驱动程序在特定情况下导致系统崩溃",
        "recommendation": "更新到最新版本或卸载该驱动",
    },
    # ... 添加你的条目
}
```

### 方式二：使用 JSON 文件

编辑 `bsod_analyzer/knowledge/known_bad_drivers.json`：

```json
{
  "problematic_driver.sys": {
    "issue": "驱动程序在特定情况下导致系统崩溃",
    "recommendation": "更新到最新版本或卸载该驱动"
  }
}
```

然后提交 PR 包含你的改动。

## 开发相关文档

- [项目架构](CLAUDE.md) - 详细的架构说明
- [变更日志](CHANGELOG.md) - 版本变更记录

## 获取帮助

如果你有任何问题：

- 查看 [现有 Issues](https://github.com/Harryleft/blue-screen-what-happen/issues)
- 创建新的 Discussion 或 Issue
- 查看 [CLAUDE.md](CLAUDE.md) 了解项目架构

## 行为准则

请尊重所有贡献者，保持友好和专业的交流。任何形式的骚扰或不当行为都将导致贡献权限被撤销。

---

**感谢你的贡献！**
