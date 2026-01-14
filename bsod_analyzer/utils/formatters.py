"""
Output formatters for analysis results.

Provides functions to format results for different output types.
"""

import json
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from bsod_analyzer.database.models import AnalysisResult


console = Console()


def format_analysis_result(result: AnalysisResult) -> Dict[str, Any]:
    """Format analysis result as dictionary.

    Args:
        result: AnalysisResult to format

    Returns:
        Dictionary representation
    """
    return {
        "dump_file": result.dump_file,
        "timestamp": result.minidump_info.timestamp.isoformat(),
        "computer_name": result.minidump_info.computer_name,
        "os_version": result.minidump_info.os_version,
        "bugcheck": {
            "code": f"0x{result.crash_info.bugcheck_code:02X}",
            "name": result.crash_info.bugcheck_name,
            "description": result.crash_info.bugcheck_description,
            "crash_address": f"0x{result.crash_info.crash_address:X}",
            "parameters": [f"0x{p:X}" for p in result.crash_info.parameters],
        },
        "suspected_driver": {
            "name": result.suspected_driver.name if result.suspected_driver else None,
            "base_address": f"0x{result.suspected_driver.base_address:X}" if result.suspected_driver else None,
            "is_problematic": result.suspected_driver.is_problematic if result.suspected_driver else False,
        },
        "suspected_cause": result.suspected_cause,
        "recommendations": result.recommendations,
        "confidence": f"{result.confidence:.1%}",
        "ai_analysis": result.ai_analysis,
    }


def format_text_output(result: AnalysisResult) -> str:
    """Format analysis result as plain text.

    Args:
        result: AnalysisResult to format

    Returns:
        Formatted text string
    """
    lines = [
        "=" * 70,
        "Windows蓝屏分析报告",
        "=" * 70,
        "",
        "【基本信息】",
        f"  文件: {result.dump_file}",
        f"  时间: {result.minidump_info.timestamp}",
        f"  计算机: {result.minidump_info.computer_name}",
        f"  系统: {result.minidump_info.os_version}",
        f"  CPU: {result.minidump_info.cpu_architecture} ({result.minidump_info.number_of_processors} 核心)",
        f"  内存: {result.minidump_info.physical_memory // (1024*1024)} MB",
        "",
        "【崩溃信息】",
        f"  Bugcheck代码: 0x{result.crash_info.bugcheck_code:02X}",
        f"  名称: {result.crash_info.bugcheck_name}",
        f"  描述: {result.crash_info.bugcheck_description}",
        f"  崩溃地址: 0x{result.crash_info.crash_address:X}",
        "",
    ]

    if result.suspected_driver:
        lines.extend([
            "【疑似问题驱动】",
            f"  名称: {result.suspected_driver.name}",
            f"  基地址: 0x{result.suspected_driver.base_address:X}",
            f"  大小: {result.suspected_driver.size:,} 字节",
            f"  已知问题: {'是' if result.suspected_driver.is_problematic else '否'}",
            "",
        ])

    lines.extend([
        "【崩溃原因】",
        f"  {result.suspected_cause}",
        "",
        "【修复建议】",
    ])

    for i, rec in enumerate(result.recommendations, 1):
        lines.append(f"  {i}. {rec}")

    lines.append("")
    lines.append(f"【分析置信度】: {result.confidence:.1%}")

    if result.ai_analysis:
        lines.extend([
            "",
            "【AI分析】",
            result.ai_analysis,
        ])

    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


def display_analysis_result_rich(result: AnalysisResult):
    """Display analysis result using Rich formatting.

    Args:
        result: AnalysisResult to display
    """
    # Basic info panel
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_row("文件:", result.dump_file)
    info_table.add_row("时间:", str(result.minidump_info.timestamp))
    info_table.add_row("系统:", result.minidump_info.os_version)
    info_table.add_row("CPU:", result.minidump_info.cpu_architecture)

    # Crash info
    crash_table = Table(title="崩溃信息", show_header=True, box=None)
    crash_table.add_column("项目", style="cyan")
    crash_table.add_column("值", style="yellow")
    crash_table.add_row("Bugcheck代码", f"0x{result.crash_info.bugcheck_code:02X}")
    crash_table.add_row("名称", result.crash_info.bugcheck_name)
    crash_table.add_row("崩溃地址", f"0x{result.crash_info.crash_address:X}")

    # Suspected driver
    if result.suspected_driver:
        driver_style = "red" if result.suspected_driver.is_problematic else "yellow"
        driver_table = Table(title="疑似问题驱动", show_header=True, box=None)
        driver_table.add_column("项目", style="cyan")
        driver_table.add_column("值", style=driver_style)
        driver_table.add_row("名称", result.suspected_driver.name)
        driver_table.add_row("基地址", f"0x{result.suspected_driver.base_address:X}")
        driver_table.add_row("已知问题", "是" if result.suspected_driver.is_problematic else "否")

    # Cause panel
    cause_panel = Panel(
        result.suspected_cause,
        title="崩溃原因",
        border_style="bold red",
    )

    # Recommendations
    rec_text = "\n".join(f"{i+1}. {rec}" for i, rec in enumerate(result.recommendations))
    rec_panel = Panel(
        rec_text,
        title="修复建议",
        border_style="bold green",
    )

    # AI analysis
    if result.ai_analysis:
        ai_panel = Panel(
            result.ai_analysis,
            title="AI分析",
            border_style="bold blue",
        )

    # Print all sections
    console.print(Panel(info_table, title="基本信息", border_style="bold cyan"))
    console.print(crash_table)

    if result.suspected_driver:
        console.print(driver_table)

    console.print(cause_panel)
    console.print(rec_panel)

    if result.ai_analysis:
        console.print(ai_panel)

    # Confidence meter
    confidence_color = "green" if result.confidence >= 0.7 else "yellow" if result.confidence >= 0.5 else "red"
    console.print(f"\n分析置信度: [{confidence_color}]{result.confidence:.1%}[/{confidence_color}]")


def display_crash_history(records):
    """Display crash history using Rich formatting.

    Args:
        records: List of CrashHistory records
    """
    table = Table(title="崩溃历史记录", show_header=True)
    table.add_column("时间", style="cyan")
    table.add_column("Bugcheck", style="red")
    table.add_column("疑似驱动", style="yellow")
    table.add_column("置信度", style="green")

    for record in records:
        table.add_row(
            record.crash_time.strftime("%Y-%m-%d %H:%M"),
            f"0x{record.bugcheck_code:02X}",
            record.suspected_driver or "未知",
            f"{record.confidence:.0%}",
        )

    console.print(table)


def display_statistics(stats: dict):
    """Display statistics using Rich formatting.

    Args:
        stats: Statistics dictionary
    """
    console.print(Panel(f"统计周期: {stats['period_days']} 天", title="崩溃统计"))

    # Total crashes
    console.print(f"\n总崩溃次数: [bold red]{stats['total_crashes']}[/bold red]")

    # Bugcheck distribution
    if stats["bugcheck_distribution"]:
        table = Table(title="常见Bugcheck代码", show_header=True)
        table.add_column("代码", style="red")
        table.add_column("名称")
        table.add_column("次数", style="yellow")

        for item in stats["bugcheck_distribution"]:
            table.add_row(item["code"], item["name"], str(item["count"]))

        console.print(table)

    # Driver distribution
    if stats["driver_distribution"]:
        table = Table(title="常见问题驱动", show_header=True)
        table.add_column("驱动", style="yellow")
        table.add_column("次数", style="red")

        for item in stats["driver_distribution"]:
            table.add_row(item["driver"], str(item["count"]))

        console.print(table)


def save_result_to_file(result: AnalysisResult, output_path: str, output_format: str = "text"):
    """Save analysis result to file.

    Args:
        result: AnalysisResult to save
        output_path: Path to output file
        output_format: Format type (text, json, html)
    """
    if output_format == "json":
        data = format_analysis_result(result)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    elif output_format == "text":
        text = format_text_output(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
