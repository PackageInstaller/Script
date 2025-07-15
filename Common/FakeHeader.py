import os
import sys
import time
from pathlib import Path
from multiprocessing import Pool, cpu_count
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    SpinnerColumn,
    MofNCompleteColumn,
)
from rich.console import Console
from rich.table import Table

console = Console()

def process_file(file_info):
    file_path, _ = file_info
    result = {
        'modified': False,
        'size': 0,
        'error': None
    }

    try:
        if not os.path.exists(file_path):
            return result

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return result

        with open(file_path, 'rb') as f:
            content = f.read()
            
        pos = content.rfind(b'UnityFS')
        if pos == -1:
            return result
            
        if pos > 0:
            with open(file_path, 'wb') as f:
                f.write(content[pos:])
            result['modified'] = True
            result['size'] = file_size

    except Exception as e:
        result['error'] = (str(file_path), str(e))

    return result

def print_summary(results, start_time, total_files):
    total_time = time.time() - start_time
    
    modified_count = sum(1 for r in results if r['modified'])
    skipped_count = sum(1 for r in results if not r['modified'])
    errors = [r['error'] for r in results if r['error'] is not None]
    
    table = Table(title="处理结果统计", show_header=True, header_style="bold magenta")
    table.add_column("项目", style="cyan", width=12)
    table.add_column("结果", justify="right", style="green", width=12)
    
    table.add_row("总用时", f"{total_time:.2f}秒")
    table.add_row("总文件数", str(total_files))
    table.add_row("成功修改", str(modified_count))
    table.add_row("无需修改", str(skipped_count))
    
    console.print("\n")
    console.print(table)
    
    if errors:
        error_table = Table(title="处理失败的文件", show_header=True, header_style="bold red")
        error_table.add_column("文件名", style="red")
        error_table.add_column("错误信息", style="yellow")
        
        for file_path, error in errors:
            error_table.add_row(Path(file_path).name, error)
        
        console.print("\n")
        console.print(error_table)

def main():
    try:
        with console.status("[bold green]正在统计文件...") as status:
            current_dir = Path(os.path.dirname(os.path.realpath(__file__ or sys.argv[0])))
            files = [(str(f), 0) for f in current_dir.rglob('*') 
                    if f.is_file() and f.name != os.path.basename(__file__)]
            total_files = len(files)
        
        if total_files == 0:
            console.print("[yellow]没有找到需要处理的文件")
            return

        console.print(f"\n[bold cyan]找到 {total_files} 个文件")
        start_time = time.time()
        
        files = [(f, total_files) for f, _ in files]
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TextColumn("已用时间: "),
            TimeElapsedColumn(),
            TextColumn("预计剩余: "),
            TimeRemainingColumn(),
            console=console
        )
        
        all_results = []
        with progress:
            task = progress.add_task("[cyan]处理文件...", total=total_files)
            
            with Pool(min(cpu_count(), 256)) as pool:
                for result in pool.imap_unordered(process_file, files):
                    all_results.append(result)
                    progress.advance(task)
        
        print_summary(all_results, start_time, total_files)

    except KeyboardInterrupt:
        console.print("\n[red]程序被中断")
    except Exception as e:
        console.print(f"\n[red]程序出现错误: {e}")

if __name__ == '__main__':
    main()