import PyInstaller.__main__
import os

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(__file__))
script_path = os.path.join(current_dir, 'analyze_windows_events.py')

# PyInstaller参数
params = [
    script_path,  # 主脚本
    '--name=Windows事件日志分析工具',  # 生成的exe名称
    '--onefile',  # 打包成单个文件
    '--noconsole',  # 不显示控制台窗口
    '--icon=icon.ico',  # 程序图标（如果有的话）
    '--add-data=README.md;.',  # 添加说明文档
    '--clean',  # 清理临时文件
    '--noconfirm',  # 不确认覆盖
]

# 运行PyInstaller
PyInstaller.__main__.run(params) 