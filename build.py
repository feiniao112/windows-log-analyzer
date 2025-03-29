#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import PyInstaller.__main__
import sys
import os

def build():
    """
    打包程序为可执行文件
    """
    # 获取当前目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 根据操作系统选择路径分隔符
    path_separator = ':' if sys.platform == 'darwin' else ';'
    
    # 定义打包参数
    params = [
        'gui.py',  # 主程序文件
        '--name=Windows日志分析工具V1.0',  # 程序名称
        '--noconsole',  # 不显示控制台窗口
        '--onefile',    # 打包成单个文件
        '--clean',      # 清理临时文件
        f'--add-data=README.md{path_separator}.',  # 添加README文件
        f'--add-data=analyze_windows_events.py{path_separator}.',  # 添加分析脚本
        '--hidden-import=python_evtx',
        '--hidden-import=Evtx.Evtx',
        '--hidden-import=tkcalendar',
        '--hidden-import=tkinter',
        '--hidden-import=json',
        '--hidden-import=datetime',
        '--hidden-import=xml.etree.ElementTree',
    ]
    
    # 根据操作系统添加特定参数
    if sys.platform == 'darwin':  # macOS
        params.extend([
            '--windowed',  # macOS下使用窗口模式
            '--target-arch=x86_64',  # 64位架构
            '--codesign-identity=-',  # 跳过签名
        ])
    elif sys.platform == 'win32':  # Windows
        params.extend([
            '--uac-admin',  # 请求管理员权限
            '--version-file=version.txt',  # 版本信息文件
            '--add-binary=python3*.dll;.',  # 添加Python DLL
        ])
    
    print("正在使用以下参数打包：")
    for param in params:
        print(f"  {param}")
    
    try:
        # 执行打包
        PyInstaller.__main__.run(params)
        print("\n打包完成！")
        print(f"可执行文件位于: {os.path.join(current_dir, 'dist')}")
    except Exception as e:
        print(f"\n打包过程中出现错误：{str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    build() 