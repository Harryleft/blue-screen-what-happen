"""
CLI main entry point for BSOD Analyzer.

Command-line interface for analyzing Windows crash dump files.
"""

import os
import sys

# 设置 UTF-8 输出编码（Windows 兼容）
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import click
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from bsod_analyzer.core.parser import create_parser
from bsod_analyzer.core.analyzer import BSODAnalyzer
from bsod_analyzer.core.bugcheck_kb import BugcheckKnowledgeBase
from bsod_analyzer.core.driver_detector import DriverDetector
from bsod_analyzer.ai.analyzer import AIAnalyzer
from bsod_analyzer.ai.providers import AIProviderFactory
from bsod_analyzer.database.manager import DatabaseManager
from bsod_analyzer.utils.config import get_config
from bsod_analyzer.utils.formatters import (
    display_analysis_result_rich,
    display_crash_history,
    display_statistics,
    save_result_to_file,
    format_text_output,
)

console = Console()


@click.group()
@click.version_option(version="1.0.0")
@click.option("--verbose", "-v", is_flag=True, help="启用详细日志")
def cli(verbose: bool):
    """BSOD Analyzer - Windows蓝屏转储分析工具

    分析Windows minidump文件，识别崩溃原因和问题驱动程序。
    """
    if verbose:
        from loguru import logger

        logger.remove()
        logger.add(sys.stderr, level="DEBUG")


@cli.command()
@click.argument("dump_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="输出文件路径")
@click.option("--format", "-f", type=click.Choice(["json", "text"]), default="text", help="输出格式")
@click.option("--ai", is_flag=True, help="启用AI分析")
@click.option("--save", is_flag=True, help="保存分析结果到数据库")
def analyze(dump_file: str, output: Optional[str], format: str, ai: bool, save: bool):
    """分析单个dump文件

    示例:
        bsod analyze dump.dmp
        bsod analyze dump.dmp --ai --save
        bsod analyze dump.dmp -o report.json -f json
    """
    try:
        # Initialize parser - auto-detect format (Minidump or PAGEDU64)
        with console.status("[bold green]解析dump文件...", spinner="dots"):
            parser = create_parser(dump_file)

        # Initialize components
        kb = BugcheckKnowledgeBase()
        driver_detector = DriverDetector()
        ai_analyzer = None

        # Initialize AI if requested
        if ai:
            with console.status("[bold blue]初始化AI分析器...", spinner="dots"):
                config = get_config()
                if config.zhipu_api_key:
                    provider = AIProviderFactory.create_from_config(config)
                    ai_analyzer = AIAnalyzer(provider=provider)
                else:
                    console.print("[yellow]警告: ZHIPU_API_KEY未配置，AI分析已禁用[/yellow]")

        # Run analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("分析崩溃中...", total=None)
            analyzer = BSODAnalyzer(parser, kb, driver_detector)
            result = analyzer.analyze(dump_file)

            # Run AI analysis if enabled
            if ai_analyzer and ai_analyzer.enabled:
                progress.update(task, description="AI分析中...")
                result.ai_analysis = ai_analyzer.analyze(
                    crash_info=result.crash_info,
                    drivers=result.loaded_drivers,
                    stack_traces=result.stack_traces,
                    minidump_info=result.minidump_info,
                    suspected_driver=result.suspected_driver,
                )

        # Display result
        if format == "json":
            import json

            from bsod_analyzer.utils.formatters import format_analysis_result

            data = format_analysis_result(result)
            console.print_json(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            display_analysis_result_rich(result)

        # Save to database
        if save:
            db = DatabaseManager()
            db.save_analysis(result)
            console.print("\n[green]✓[/green] 分析结果已保存到数据库")

        # Save to file
        if output:
            save_result_to_file(result, output, format)
            console.print(f"[green]✓[/green] 结果已保存到: {output}")

    except FileNotFoundError as e:
        console.print(f"[red]错误: 文件未找到 - {e}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]错误: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]错误: {e}[/red]")
        import traceback

        console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.argument("dump_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--limit", "-n", type=int, default=10, help="最多分析的文件数")
@click.option("--pattern", "-p", default="*.dmp", help="文件匹配模式")
@click.option("--save", is_flag=True, help="保存所有结果到数据库")
def batch(dump_dir: str, limit: int, pattern: str, save: bool):
    """批量分析目录中的dump文件

    示例:
        bsod batch "C:/Windows/Minidump"
        bsod batch ./dumps --limit 5 --save
    """
    dump_files = list(Path(dump_dir).glob(pattern))[:limit]

    if not dump_files:
        console.print("[yellow]未找到dump文件[/yellow]")
        return

    console.print(f"找到 [cyan]{len(dump_files)}[/cyan] 个dump文件")

    results = []
    for i, dump_file in enumerate(dump_files, 1):
        console.print(f"\n[{i}/{len(dump_files)}] 分析 [cyan]{dump_file.name}[/cyan]...")

        try:
            parser = create_parser(str(dump_file))
            kb = BugcheckKnowledgeBase()
            driver_detector = DriverDetector()
            analyzer = BSODAnalyzer(parser, kb, driver_detector)

            result = analyzer.analyze(str(dump_file))
            results.append(result)

            # Display brief result
            driver_name = result.suspected_driver.name if result.suspected_driver else "未知"
            console.print(
                f"  [green]✓[/green] {result.crash_info.bugcheck_name}: "
                f"[yellow]{driver_name}[/yellow] (置信度: {result.confidence:.0%})"
            )

            # Save if requested
            if save:
                db = DatabaseManager()
                db.save_analysis(result)

        except Exception as e:
            console.print(f"  [red]✗[/red] 分析失败: {e}")

    # Display summary
    console.print(f"\n[bold]批量分析完成: {len(results)}/{len(dump_files)} 成功[/bold]")


@cli.command()
@click.option("--limit", "-n", type=int, default=20, help="最大记录数")
@click.option("--days", "-d", type=int, help="仅显示最近N天的记录")
def history(limit: int, days: Optional[int]):
    """查看崩溃历史记录

    示例:
        bsod history
        bsod history --limit 50
        bsod history --days 7
    """
    db = DatabaseManager()
    records = db.get_crash_history(limit=limit, days=days)

    if not records:
        console.print("[yellow]未找到崩溃历史记录[/yellow]")
        return

    display_crash_history(records)


@cli.command()
@click.option("--days", "-d", type=int, default=30, help="分析最近N天的崩溃")
@click.option("--ai", is_flag=True, help="使用AI进行模式分析")
def patterns(days: int, ai: bool):
    """分析崩溃模式

    示例:
        bsod patterns
        bsod patterns --days 7 --ai
    """
    db = DatabaseManager()
    records = db.get_crash_history(limit=1000, days=days)

    if len(records) < 2:
        console.print("[yellow]崩溃记录不足，无法进行模式分析[/yellow]")
        return

    # Get statistics
    stats = db.get_statistics(days=days)
    display_statistics(stats)

    # AI pattern analysis
    if ai:
        config = get_config()
        ai_analyzer = AIAnalyzer.from_config(config)

        if ai_analyzer.enabled:
            console.print("\n[bold blue]AI模式分析[/bold blue]")

            # Prepare crash data
            crash_data = [
                {
                    "timestamp": r.crash_time.isoformat(),
                    "bugcheck_code": r.bugcheck_code,
                    "bugcheck_name": r.bugcheck_name,
                    "suspected_driver": r.suspected_driver or "未知",
                }
                for r in records
            ]

            with console.status("[bold blue]AI分析中...", spinner="dots"):
                analysis = ai_analyzer.analyze_history(crash_data)

            console.print(Panel(analysis, title="AI模式分析", border_style="bold blue"))
        else:
            console.print("[yellow]AI分析未启用。请配置ZHIPU_API_KEY。[/yellow]")


@cli.command()
def config():
    """显示当前配置"""
    cfg = get_config()

    table = Table(title="当前配置", show_header=True)
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="yellow")

    table.add_row("AI模型", cfg.ai_model)
    table.add_row("数据库路径", str(cfg.get_database_path()))
    table.add_row("默认转储目录", cfg.default_dump_dir)
    table.add_row("日志级别", cfg.log_level)
    table.add_row("最大堆栈帧", str(cfg.max_stack_frames))
    table.add_row("置信度阈值", f"{cfg.confidence_threshold:.0%}")
    table.add_row("API Key", "已配置" if cfg.zhipu_api_key else "未配置")

    console.print(table)
    console.print("\n提示: 通过.env文件或环境变量配置ZHIPU_API_KEY")


def find_system_dump_files() -> List[Path]:
    """查找系统中的所有崩溃转储文件。

    Returns:
        找到的 dump 文件列表（按修改时间降序排列）
    """
    dump_files = []

    # Windows 系统中的常见 dump 文件位置
    dump_locations = [
        # Minidump 文件（最常见）
        Path("C:/Windows/Minidump"),
        # 完整内存转储
        Path("C:/Windows"),
        # 实时内核崩溃报告
        Path("C:/Windows/LiveKernelReports"),
        # 用户配置目录中的 dump
        Path.home() / ".bsod_analyzer" / "dumps",
        # 当前工作目录（用于开发测试）
        Path.cwd(),
    ]

    console.print("[cyan]扫描系统崩溃转储文件...[/cyan]")

    for location in dump_locations:
        if not location.exists():
            continue

        console.print(f"  扫描: {location}")

        try:
            # 查找所有 .dmp 和 .mdmp 文件
            for pattern in ["*.dmp", "*.DMP", "*.mdmp", "*.MDMP"]:
                for file_path in location.glob(pattern):
                    # 跳过目录
                    if file_path.is_dir():
                        continue
                    # 跳过正在使用的文件（大小为0）
                    if file_path.stat().st_size == 0:
                        continue
                    dump_files.append(file_path)
        except PermissionError:
            console.print(f"    [yellow]权限不足，跳过[/yellow]")
        except Exception as e:
            console.print(f"    [yellow]扫描错误: {e}[/yellow]")

    # 按修改时间降序排序（最新的在前）
    dump_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    # 去重（可能在不同目录中找到同一个文件）
    seen = set()
    unique_files = []
    for f in dump_files:
        # 使用文件路径作为唯一标识
        file_key = (f.name, f.stat().st_size)
        if file_key not in seen:
            seen.add(file_key)
            unique_files.append(f)

    return unique_files


def format_file_size(size_bytes: int) -> str:
    """格式化文件大小。"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


@cli.command()
@click.option("--analyze", "-a", is_flag=True, help="找到文件后自动分析最新的")
@click.option("--limit", "-n", type=int, default=10, help="最多显示的文件数")
@click.option("--all", is_flag=True, help="显示所有找到的文件")
@click.option("--save", is_flag=True, help="自动分析时保存结果到数据库")
@click.option("--ai", is_flag=True, help="自动分析时启用 AI 分析")
def scan(analyze: bool, limit: int, all: bool, save: bool, ai: bool):
    """自动扫描并分析系统崩溃转储文件

    示例:
        bsod scan                    # 扫描并列出崩溃文件
        bsod scan --analyze          # 扫描并自动分析最新的崩溃
        bsod scan -a --ai --save    # 扫描，用 AI 分析最新的并保存
        bsod scan --all              # 显示所有找到的文件
    """
    console.print(Panel.fit(
        "[bold cyan]系统崩溃转储文件扫描器[/bold cyan]\n"
        "将扫描以下位置:\n"
        "- C:\\Windows\\Minidump\n"
        "- C:\\Windows\\MEMORY.DMP\n"
        "- C:\\Windows\\LiveKernelReports\n"
        "- 用户目录下的 dump 文件",
        border_style="cyan"
    ))

    # 查找所有 dump 文件
    dump_files = find_system_dump_files()

    if not dump_files:
        console.print("\n[yellow]未找到任何崩溃转储文件[/yellow]")
        console.print("\n提示:")
        console.print("• 确保系统已发生过蓝屏崩溃")
        console.print("• 检查是否启用了崩溃转储功能")
        console.print("• 以管理员身份运行此工具")
        return

    display_limit = len(dump_files) if all else min(limit, len(dump_files))

    console.print(f"\n[green]找到 {len(dump_files)} 个崩溃转储文件[/green]")
    console.print(f"显示最新的 {display_limit} 个:\n")

    # 显示文件列表表格
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("文件名", style="cyan")
    table.add_column("大小", justify="right", style="yellow")
    table.add_column("修改时间", style="green")
    table.add_column("类型", style="blue")

    for i, file_path in enumerate(dump_files[:display_limit], 1):
        # 获取文件信息
        stat = file_path.stat()
        size_str = format_file_size(stat.st_size)

        # 获取修改时间
        mtime = datetime.fromtimestamp(stat.st_mtime)
        time_str = mtime.strftime("%Y-%m-%d %H:%M:%S")

        # 确定文件类型
        with open(file_path, "rb") as f:
            signature = f.read(8)
            if signature[:4] == b"MDMP":
                file_type = "Minidump"
            elif signature[:8] == b"PAGEDU64":
                file_type = "完整内存转储"
            elif signature[:8] == b"PAGEDU48":
                file_type = "内核转储(x86)"
            else:
                file_type = "未知"

        table.add_row(
            str(i),
            file_path.name,
            size_str,
            time_str,
            file_type
        )

    console.print(table)

    # 如果用户请求自动分析
    if analyze and dump_files:
        latest_file = dump_files[0]

        console.print(f"\n[bold]分析最新的崩溃文件:[/bold] [cyan]{latest_file.name}[/cyan]")
        console.print(f"路径: {latest_file}\n")

        try:
            # 使用现有的 analyze 逻辑
            parser = create_parser(str(latest_file))
            kb = BugcheckKnowledgeBase()
            driver_detector = DriverDetector()
            ai_analyzer = None

            # 初始化 AI（如果请求）
            if ai:
                config = get_config()
                if config.zhipu_api_key:
                    provider = AIProviderFactory.create_from_config(config)
                    ai_analyzer = AIAnalyzer(provider=provider)
                else:
                    console.print("[yellow]警告: ZHIPU_API_KEY未配置，AI分析已禁用[/yellow]")

            # 运行分析
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("分析崩溃中...", total=None)
                analyzer = BSODAnalyzer(parser, kb, driver_detector)
                result = analyzer.analyze(str(latest_file))

                # AI 分析（如果请求）
                if ai_analyzer and ai_analyzer.enabled:
                    progress.update(task, description="AI分析中...")
                    result.ai_analysis = ai_analyzer.analyze(
                        crash_info=result.crash_info,
                        drivers=result.loaded_drivers,
                        stack_traces=result.stack_traces,
                        minidump_info=result.minidump_info,
                        suspected_driver=result.suspected_driver,
                    )

            # 显示结果
            console.print()
            display_analysis_result_rich(result)

            # 保存到数据库（如果请求）
            if save:
                db = DatabaseManager()
                db.save_analysis(result)
                console.print("\n[green]✓[/green] 分析结果已保存到数据库")

        except Exception as e:
            console.print(f"\n[red]分析失败: {e}[/red]")
            import traceback
            console.print(traceback.format_exc())

    elif not analyze and dump_files:
        console.print(f"\n提示: 使用 [cyan]--analyze[/cyan] 或 [cyan]-a[/cyan] 选项自动分析最新的崩溃文件")
        console.print(f"示例: [cyan]bsod scan --analyze[/cyan]")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
