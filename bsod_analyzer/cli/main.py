"""
CLI main entry point for BSOD Analyzer.

Command-line interface for analyzing Windows crash dump files.
"""

import sys
import click
from pathlib import Path
from typing import Optional
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


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
