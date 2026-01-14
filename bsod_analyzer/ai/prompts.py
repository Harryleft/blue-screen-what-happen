"""
AI prompt templates for crash analysis.
"""

from typing import Dict, Any, List


class PromptTemplates:
    """Templates for AI prompts."""

    def generate_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Generate prompt for single crash analysis.

        Args:
            context: Dictionary containing crash information

        Returns:
            Formatted prompt string
        """
        return f"""你是一位Windows崩溃转储分析专家。请分析以下蓝屏(BSOD)崩溃信息，并提供详细的分析报告。

## 崩溃信息
- Bugcheck代码: {context['bugcheck_code']}
- Bugcheck名称: {context['bugcheck_name']}
- 描述: {context['bugcheck_description']}
- 崩溃地址: {context['crash_address']}
- 参数: {context['crash_parameters']}

## 疑似驱动
{context['suspected_driver']}

## 系统信息
- 计算机名: {context['computer_name']}
- 操作系统: {context['os_version']}
- CPU架构: {context['cpu_architecture']}
- 内存: {context['physical_memory']} MB
- 处理器数量: {context['number_of_processors']}

## 已加载驱动 (共{context['driver_count']}个)
{context['driver_list']}

## 堆栈跟踪
{context['stack_traces']}

---

请严格按照以下格式，用中文提供分析报告：

## 一、根因分析
简要说明最可能的崩溃原因（1-2句话）

## 二、技术解释
用技术术语解释发生了什么（100字以内）

## 三、具体修复步骤（按优先级排序）

### 第一步：[操作标题]
**目的**：简述此步骤目的
**具体操作**：
1. 打开[具体路径/界面]
2. 点击[具体按钮/选项]
3. 输入/选择[具体内容]
4. 点击[确认/应用]

**命令行方式**（如适用）：
```
命令示例
```

**预期结果**：完成后的状态

### 第二步：[操作标题]
（同上格式）

### 第三步：[操作标题]
（同上格式）

## 四、验证修复
提供验证问题是否解决的具体方法：

1. **检查方法**：如何确认修复成功
2. **观察时间**：建议观察多久
3. **成功标志**：什么现象表示修复成功

## 五、如果问题仍未解决
提供备选方案（2-3个具体方案）

---

**重要要求**：
1. 必须使用中文回答
2. 每个步骤必须包含具体的操作路径、按钮名称、命令示例
3. 提供Windows GUI和命令行两种操作方式（当都适用时）
4. 步骤必须可执行，避免"更新驱动"、"检查系统"等模糊表述
5. 对于涉及注册表的操作，必须提供完整的注册表路径和键值
6. 对于涉及命令行的操作，必须提供完整的命令
7. 所有步骤按优先级排序，从最可能有效的方案开始"""

    def generate_history_analysis_prompt(self, crashes: List[Dict[str, Any]]) -> str:
        """Generate prompt for crash history pattern analysis.

        Args:
            crashes: List of crash records

        Returns:
            Formatted prompt string
        """
        crash_summaries = "\n".join([
            f"- {c['timestamp']}: 0x{c['bugcheck_code']:02X} ({c['bugcheck_name']}) - 驱动: {c['suspected_driver']}"
            for c in crashes
        ])

        return f"""你是一位Windows蓝屏分析专家。系统在过去一段时间内经历了{len(crashes)}次蓝屏崩溃。

## 崩溃历史
{crash_summaries}

请用中文分析并提供以下内容：

## 一、模式识别
这些崩溃是否存在重复模式？

## 二、常见原因
最频繁的崩溃原因是什么？

## 三、根本问题
是否有单一的根本问题？

## 四、系统性问题
是否存在硬件或软件的系统性问题？

## 五、综合解决方案（按优先级排序）

### 方案一：[具体操作]
**具体步骤**：
1. [详细操作步骤1]
2. [详细操作步骤2]
...

**预期效果**：[说明]

### 方案二：[具体操作]
（同上格式）

---

**要求**：
1. 必须使用中文
2. 提供具体的操作步骤，包含路径、命令、参数
3. 按优先级排序方案"""

    def generate_driver_analysis_prompt(self, driver_name: str, crash_context: Dict[str, Any]) -> str:
        """Generate prompt for specific driver analysis.

        Args:
            driver_name: Name of the driver
            crash_context: Context of the crash

        Returns:
            Formatted prompt string
        """
        return f"""请分析以下驱动程序在Windows蓝屏崩溃中的作用。

## 驱动信息
- 驱动名称: {driver_name}
- 基地址: 0x{crash_context.get('base_address', 0):X}
- 大小: {crash_context.get('size', 0):,} 字节

## 崩溃上下文
- Bugcheck代码: {crash_context.get('bugcheck_code', 'Unknown')}
- 崩溃地址: 0x{crash_context.get('crash_address', 0):X}

---

请用中文提供以下分析：

## 一、驱动作用
这个驱动是做什么的？属于哪类硬件/软件？

## 二、问题分析
它可能导致蓝屏的常见原因有哪些？

## 三、具体修复方法

### 方法一：更新驱动（推荐）
**步骤**：
1. [具体操作步骤]
2. [具体操作步骤]

**下载来源**：[具体的下载网站或方法]

### 方法二：回滚驱动
**步骤**：
1. 打开设备管理器（Win+X → 设备管理器）
2. 找到[具体硬件类别] → [具体设备名称]
3. 右键 → 属性 → 驱动程序选项卡
4. 点击"回滚驱动程序"按钮
5. 按照提示完成回滚

### 方法三：禁用驱动（如适用）
**步骤**：
1. [具体操作步骤]

**注意事项**：[可能的影响]

## 四、验证方法
如何确认驱动问题已解决？

---

**要求**：
1. 必须使用中文
2. 提供完整的操作步骤，包括具体的菜单路径和按钮名称
3. 提供命令行方式（如适用）"""

    def format_driver_list(self, drivers: List[Any], max_drivers: int = 20) -> str:
        """Format driver list for prompt.

        Args:
            drivers: List of DriverInfo objects
            max_drivers: Maximum number of drivers to include

        Returns:
            Formatted driver list string
        """
        lines = []
        for i, driver in enumerate(drivers[:max_drivers]):
            lines.append(
                f"  {i+1}. {driver.name} @ 0x{driver.base_address:X} "
                f"(大小: {driver.size:,} 字节)"
            )

        if len(drivers) > max_drivers:
            lines.append(f"  ... 还有 {len(drivers) - max_drivers} 个驱动")

        return "\n".join(lines) if lines else "  (无驱动信息)"

    def format_stack_traces(self, stack_traces: List[Any], max_threads: int = 3, max_frames: int = 10) -> str:
        """Format stack traces for prompt.

        Args:
            stack_traces: List of StackTrace objects
            max_threads: Maximum number of threads to include
            max_frames: Maximum frames per thread

        Returns:
            Formatted stack traces string
        """
        if not stack_traces:
            return "  (无堆栈跟踪信息)"

        lines = []
        for i, trace in enumerate(stack_traces[:max_threads]):
            lines.append(f"线程 {trace.thread_id}:")

            for j, frame in enumerate(trace.frames[:max_frames]):
                offset = frame.offset if frame.offset > 0 else 0
                lines.append(f"  {j+1}. {frame.module_name} + 0x{offset:X}")

        if len(stack_traces) > max_threads:
            lines.append(f"... 还有 {len(stack_traces) - max_threads} 个线程")

        return "\n".join(lines)
