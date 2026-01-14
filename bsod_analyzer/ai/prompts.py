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

请提供以下分析:

1. **根因分析**: 识别最可能的崩溃原因
2. **技术解释**: 用技术术语解释发生了什么
3. **驱动评估**: 评估疑似驱动是否存在问题
4. **可执行建议**: 提供具体的修复步骤
5. **预防措施**: 如何防止将来发生类似的崩溃

请用中文回答，提供具体、可操作的建议。"""

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

请分析:

1. **模式识别**: 这些崩溃是否存在重复模式？
2. **常见原因**: 最频繁的崩溃原因是什么？
3. **根本问题**: 是否有单一的根本问题？
4. **系统性问题**: 是否存在硬件或软件的系统性问题？
5. **综合解决方案**: 解决这些崩溃的整体方法是什么？

请用中文提供详细分析和优先级建议。"""

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

请分析:
1. 这个驱动的作用是什么？
2. 它可能导致蓝屏的常见原因有哪些？
3. 如何更新或修复这个驱动？
4. 如果不是必需的，如何安全地禁用它？

请用中文提供详细分析。"""

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
