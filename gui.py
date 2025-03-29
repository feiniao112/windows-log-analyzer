#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import json
import sys
import traceback
import os
import threading
import queue
import time
import multiprocessing as mp
from tkcalendar import DateEntry

try:
    from analyze_windows_events import analyze_events, EVENT_TYPES, LOGON_TYPES
except ImportError as e:
    print(f"导入错误: {str(e)}")
    print("当前工作目录:", os.getcwd())
    print("Python路径:", sys.path)
    sys.exit(1)

class TextRedirector:
    def __init__(self, text_widget, queue):
        self.text_widget = text_widget
        self.queue = queue
    
    def write(self, string):
        self.queue.put(string)
    
    def flush(self):
        pass

class WindowsEventAnalyzerGUI:
    def __init__(self, root):
        try:
            self.root = root
            self.root.title("Windows日志分析工具V1.0 - by 飞鸟")
            self.root.geometry("800x600")
            
            # 创建主框架
            self.main_frame = ttk.Frame(self.root, padding="10")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # 文件选择区域
            file_frame = ttk.LabelFrame(self.main_frame, text="选择日志文件", padding="5")
            file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
            
            self.file_path = tk.StringVar()
            ttk.Entry(file_frame, textvariable=self.file_path, width=50).grid(row=0, column=0, padx=5)
            ttk.Button(file_frame, text="浏览", command=self.browse_file).grid(row=0, column=1)
            
            # 筛选条件区域
            filter_frame = ttk.LabelFrame(self.main_frame, text="筛选条件", padding="5")
            filter_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
            
            # 事件ID选择
            self.use_event_ids = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_frame, text="事件ID:", variable=self.use_event_ids, 
                          command=self.toggle_event_ids).grid(row=0, column=0, sticky=tk.W)
            self.event_ids = tk.StringVar()
            self.event_ids_entry = ttk.Entry(filter_frame, textvariable=self.event_ids, width=50)
            self.event_ids_entry.grid(row=0, column=1, padx=5)
            self.event_ids_button = ttk.Button(filter_frame, text="选择事件", command=self.show_event_dialog)
            self.event_ids_button.grid(row=0, column=2)
            self.toggle_event_ids()
            
            # 登录类型选择
            self.use_logon_types = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_frame, text="登录类型:", variable=self.use_logon_types,
                          command=self.toggle_logon_types).grid(row=1, column=0, sticky=tk.W)
            self.logon_types = tk.StringVar()
            self.logon_types_entry = ttk.Entry(filter_frame, textvariable=self.logon_types, width=50)
            self.logon_types_entry.grid(row=1, column=1, padx=5)
            self.logon_types_button = ttk.Button(filter_frame, text="选择类型", command=self.show_logon_dialog)
            self.logon_types_button.grid(row=1, column=2)
            self.toggle_logon_types()
            
            # 账号筛选
            self.use_account = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_frame, text="账号筛选:", variable=self.use_account,
                          command=self.toggle_account).grid(row=2, column=0, sticky=tk.W)
            self.account = tk.StringVar()
            self.account_entry = ttk.Entry(filter_frame, textvariable=self.account, width=50)
            self.account_entry.grid(row=2, column=1, padx=5)
            self.toggle_account()
            
            # IP地址筛选
            self.use_ip = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_frame, text="IP地址:", variable=self.use_ip,
                          command=self.toggle_ip).grid(row=3, column=0, sticky=tk.W)
            self.ip = tk.StringVar()
            self.ip_entry = ttk.Entry(filter_frame, textvariable=self.ip, width=50)
            self.ip_entry.grid(row=3, column=1, padx=5)
            self.toggle_ip()
            
            # 时间范围
            self.use_time_range = tk.BooleanVar(value=False)
            ttk.Checkbutton(filter_frame, text="时间范围:", variable=self.use_time_range,
                          command=self.toggle_time_range).grid(row=4, column=0, sticky=tk.W)
            time_frame = ttk.Frame(filter_frame)
            time_frame.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E))
            
            # 开始时间
            start_frame = ttk.Frame(time_frame)
            start_frame.grid(row=0, column=0, sticky=tk.W)
            ttk.Label(start_frame, text="开始:").grid(row=0, column=0, sticky=tk.W)
            self.start_date = DateEntry(start_frame, width=12, background='darkblue',
                                     foreground='white', borderwidth=2, locale='zh_CN',
                                     date_pattern='yyyy/mm/dd')
            self.start_date.grid(row=0, column=1, padx=5)
            
            # 开始时间的时分秒选择
            time_select_frame = ttk.Frame(start_frame)
            time_select_frame.grid(row=0, column=2, padx=5)
            
            # 小时选择
            self.start_hour = ttk.Combobox(time_select_frame, width=2, values=[str(i).zfill(2) for i in range(24)])
            self.start_hour.set("00")
            self.start_hour.grid(row=0, column=0)
            ttk.Label(time_select_frame, text=":").grid(row=0, column=1)
            
            # 分钟选择
            self.start_minute = ttk.Combobox(time_select_frame, width=2, values=[str(i).zfill(2) for i in range(60)])
            self.start_minute.set("00")
            self.start_minute.grid(row=0, column=2)
            ttk.Label(time_select_frame, text=":").grid(row=0, column=3)
            
            # 秒选择
            self.start_second = ttk.Combobox(time_select_frame, width=2, values=[str(i).zfill(2) for i in range(60)])
            self.start_second.set("00")
            self.start_second.grid(row=0, column=4)
            
            # 结束时间
            end_frame = ttk.Frame(time_frame)
            end_frame.grid(row=0, column=1, sticky=tk.W, padx=10)
            ttk.Label(end_frame, text="结束:").grid(row=0, column=0, sticky=tk.W)
            self.end_date = DateEntry(end_frame, width=12, background='darkblue',
                                   foreground='white', borderwidth=2, locale='zh_CN',
                                   date_pattern='yyyy/mm/dd')
            self.end_date.grid(row=0, column=1, padx=5)
            
            # 结束时间的时分秒选择
            end_time_select_frame = ttk.Frame(end_frame)
            end_time_select_frame.grid(row=0, column=2, padx=5)
            
            # 小时选择
            self.end_hour = ttk.Combobox(end_time_select_frame, width=2, values=[str(i).zfill(2) for i in range(24)])
            self.end_hour.set("23")
            self.end_hour.grid(row=0, column=0)
            ttk.Label(end_time_select_frame, text=":").grid(row=0, column=1)
            
            # 分钟选择
            self.end_minute = ttk.Combobox(end_time_select_frame, width=2, values=[str(i).zfill(2) for i in range(60)])
            self.end_minute.set("59")
            self.end_minute.grid(row=0, column=2)
            ttk.Label(end_time_select_frame, text=":").grid(row=0, column=3)
            
            # 秒选择
            self.end_second = ttk.Combobox(end_time_select_frame, width=2, values=[str(i).zfill(2) for i in range(60)])
            self.end_second.set("59")
            self.end_second.grid(row=0, column=4)
            
            self.toggle_time_range()
            
            # 输出文件
            self.use_output = tk.BooleanVar(value=False)
            ttk.Checkbutton(self.main_frame, text="输出文件:", variable=self.use_output,
                          command=self.toggle_output).grid(row=5, column=0, sticky=tk.W)
            self.output_file = tk.StringVar()
            self.output_entry = ttk.Entry(self.main_frame, textvariable=self.output_file, width=50)
            self.output_entry.grid(row=5, column=1, padx=5)
            self.output_button = ttk.Button(self.main_frame, text="选择", command=self.browse_output)
            self.output_button.grid(row=5, column=2)
            self.toggle_output()
            
            # 分析按钮
            self.analyze_button = ttk.Button(self.main_frame, text="开始分析", command=self.start_analysis)
            self.analyze_button.grid(row=6, column=1, pady=20)
            
            # 进度显示框架
            progress_frame = ttk.LabelFrame(self.main_frame, text="分析进度", padding="5")
            progress_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
            
            # 进度条
            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
            self.progress_bar.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
            
            # 进度信息
            self.progress_label = ttk.Label(progress_frame, text="就绪")
            self.progress_label.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
            
            # 结果显示区域
            result_frame = ttk.LabelFrame(self.main_frame, text="分析结果", padding="5")
            result_frame.grid(row=8, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # 创建Treeview
            self.result_tree = ttk.Treeview(result_frame, columns=(
                "时间", "事件ID", "事件类型", "账户", "域", "工作站", "IP地址", "登录类型"
            ), show="headings", height=15)
            
            # 设置列标题
            self.result_tree.heading("时间", text="时间", anchor="center")
            self.result_tree.heading("事件ID", text="事件ID", anchor="center")
            self.result_tree.heading("事件类型", text="事件类型", anchor="center")
            self.result_tree.heading("账户", text="账户", anchor="center")
            self.result_tree.heading("域", text="域", anchor="center")
            self.result_tree.heading("工作站", text="工作站", anchor="center")
            self.result_tree.heading("IP地址", text="IP地址", anchor="center")
            self.result_tree.heading("登录类型", text="登录类型", anchor="center")
            
            # 设置列宽和对齐方式
            self.result_tree.column("时间", width=150, anchor="center")
            self.result_tree.column("事件ID", width=70, anchor="center")
            self.result_tree.column("事件类型", width=150, anchor="center")
            self.result_tree.column("账户", width=100, anchor="center")
            self.result_tree.column("域", width=100, anchor="center")
            self.result_tree.column("工作站", width=100, anchor="center")
            self.result_tree.column("IP地址", width=100, anchor="center")
            self.result_tree.column("登录类型", width=150, anchor="center")
            
            # 创建滚动条
            tree_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_tree.yview)
            self.result_tree.configure(yscrollcommand=tree_scroll.set)
            
            # 水平滚动条
            tree_scroll_x = ttk.Scrollbar(result_frame, orient="horizontal", command=self.result_tree.xview)
            self.result_tree.configure(xscrollcommand=tree_scroll_x.set)
            
            # 放置Treeview和滚动条
            self.result_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
            tree_scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
            
            # 配置result_frame的网格权重
            result_frame.grid_rowconfigure(0, weight=1)
            result_frame.grid_columnconfigure(0, weight=1)
            
            # 创建统计信息显示区域
            stats_frame = ttk.LabelFrame(self.main_frame, text="统计信息", padding="5")
            stats_frame.grid(row=9, column=0, columnspan=3, pady=5, sticky=(tk.W, tk.E))
            
            self.stats_text = tk.Text(stats_frame, height=3, width=80)
            self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
            stats_scroll = ttk.Scrollbar(stats_frame, orient="vertical", command=self.stats_text.yview)
            stats_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
            self.stats_text.configure(yscrollcommand=stats_scroll.set)
            
            print("GUI初始化完成")
            
        except Exception as e:
            print(f"GUI初始化错误: {str(e)}")
            print("错误详情:")
            traceback.print_exc()
            messagebox.showerror("错误", f"GUI初始化失败：{str(e)}")
            raise

    def update_progress(self, value, message):
        """更新进度条和进度信息"""
        self.progress_var.set(value)
        self.progress_label.configure(text=message)
        self.root.update()

    def toggle_event_ids(self):
        state = 'normal' if self.use_event_ids.get() else 'disabled'
        self.event_ids_entry.configure(state=state)
        self.event_ids_button.configure(state=state)

    def toggle_logon_types(self):
        state = 'normal' if self.use_logon_types.get() else 'disabled'
        self.logon_types_entry.configure(state=state)
        self.logon_types_button.configure(state=state)

    def toggle_account(self):
        state = 'normal' if self.use_account.get() else 'disabled'
        self.account_entry.configure(state=state)

    def toggle_ip(self):
        state = 'normal' if self.use_ip.get() else 'disabled'
        self.ip_entry.configure(state=state)

    def toggle_time_range(self):
        state = 'normal' if self.use_time_range.get() else 'disabled'
        self.start_date.configure(state=state)
        self.start_hour.configure(state=state)
        self.start_minute.configure(state=state)
        self.start_second.configure(state=state)
        self.end_date.configure(state=state)
        self.end_hour.configure(state=state)
        self.end_minute.configure(state=state)
        self.end_second.configure(state=state)

    def toggle_output(self):
        state = 'normal' if self.use_output.get() else 'disabled'
        self.output_entry.configure(state=state)
        self.output_button.configure(state=state)

    def browse_file(self):
        try:
            file_path = filedialog.askopenfilename(
                title="选择EVTX日志文件",
                filetypes=[("EVTX文件", "*.evtx"), ("所有文件", "*.*")]
            )
            if file_path:
                self.file_path.set(file_path)
        except Exception as e:
            messagebox.showerror("错误", f"选择文件时出错：{str(e)}")

    def browse_output(self):
        try:
            file_path = filedialog.asksaveasfilename(
                title="选择保存位置",
                defaultextension=".json",
                filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
            )
            if file_path:
                self.output_file.set(file_path)
        except Exception as e:
            messagebox.showerror("错误", f"选择保存位置时出错：{str(e)}")

    def show_event_dialog(self):
        try:
            dialog = tk.Toplevel(self.root)
            dialog.title("选择事件ID")
            dialog.geometry("400x500")
            
            # 创建列表框
            listbox = tk.Listbox(dialog, selectmode=tk.MULTIPLE)
            listbox.pack(fill=tk.BOTH, expand=True)
            
            # 添加事件ID和描述
            for event_id, desc in sorted(EVENT_TYPES.items()):
                listbox.insert(tk.END, f"{event_id}: {desc}")
            
            def on_select():
                try:
                    selected = listbox.curselection()
                    event_ids = []
                    for index in selected:
                        event_id = int(listbox.get(index).split(':')[0])
                        event_ids.append(event_id)
                    self.event_ids.set(','.join(map(str, event_ids)))
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("错误", f"选择事件ID时出错：{str(e)}")
            
            ttk.Button(dialog, text="确定", command=on_select).pack(pady=10)
        except Exception as e:
            messagebox.showerror("错误", f"创建事件选择对话框时出错：{str(e)}")

    def show_logon_dialog(self):
        try:
            dialog = tk.Toplevel(self.root)
            dialog.title("选择登录类型")
            dialog.geometry("400x500")
            
            # 创建列表框
            listbox = tk.Listbox(dialog, selectmode=tk.MULTIPLE)
            listbox.pack(fill=tk.BOTH, expand=True)
            
            # 添加登录类型和描述
            for logon_type, desc in sorted(LOGON_TYPES.items()):
                listbox.insert(tk.END, f"{logon_type}: {desc}")
            
            def on_select():
                try:
                    selected = listbox.curselection()
                    logon_types = []
                    for index in selected:
                        logon_type = int(listbox.get(index).split(':')[0])
                        logon_types.append(logon_type)
                    self.logon_types.set(','.join(map(str, logon_types)))
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("错误", f"选择登录类型时出错：{str(e)}")
            
            ttk.Button(dialog, text="确定", command=on_select).pack(pady=10)
        except Exception as e:
            messagebox.showerror("错误", f"创建登录类型选择对话框时出错：{str(e)}")

    def update_results(self, results):
        """更新结果显示"""
        # 清空现有结果
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        
        # 添加新结果
        for result in results:
            self.result_tree.insert("", "end", values=(
                result.get("时间", ""),
                result.get("事件ID", ""),
                result.get("事件类型", ""),
                result.get("账户", ""),
                result.get("域", ""),
                result.get("工作站", ""),
                result.get("IP地址", ""),
                result.get("登录类型", "")
            ))

    def update_stats(self, event_id_counts, total_events, filtered_events):
        """更新统计信息"""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, f"总事件数: {total_events}\n")
        self.stats_text.insert(tk.END, f"符合筛选条件的事件数: {filtered_events}\n\n")
        self.stats_text.insert(tk.END, "事件ID统计:\n")
        for event_id, count in sorted(event_id_counts.items()):
            self.stats_text.insert(tk.END, f"事件ID {event_id}: {count} 条\n")

    def analysis_thread(self):
        """分析线程"""
        try:
            # 更新进度
            self.root.after(0, lambda: self.update_progress(0, "正在初始化分析..."))
            
            # 解析事件ID
            event_ids = None
            if self.use_event_ids.get() and self.event_ids.get():
                event_ids = [int(x.strip()) for x in self.event_ids.get().split(',')]
            
            # 解析登录类型
            logon_types = None
            if self.use_logon_types.get() and self.logon_types.get():
                logon_types = [int(x.strip()) for x in self.logon_types.get().split(',')]
            
            # 解析时间
            start_time = None
            end_time = None
            if self.use_time_range.get():
                try:
                    # 获取开始时间
                    start_date = self.start_date.get_date()
                    start_time = datetime.combine(
                        start_date,
                        datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}:{self.start_second.get()}", 
                                        "%H:%M:%S").time()
                    )
                    
                    # 获取结束时间
                    end_date = self.end_date.get_date()
                    end_time = datetime.combine(
                        end_date,
                        datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}:{self.end_second.get()}", 
                                        "%H:%M:%S").time()
                    )
                except Exception as e:
                    raise ValueError(f"时间格式错误：{str(e)}")
            
            # 开始分析
            self.root.after(0, lambda: self.update_progress(10, "正在打开EVTX文件..."))
            
            # 创建临时文件用于保存结果
            temp_file = "temp_result.json"
            
            # 统计信息变量
            event_id_counts = {}
            total_events = 0
            filtered_events = 0
            
            analyze_events(
                self.file_path.get(),
                event_ids,
                logon_types,
                self.account.get() if self.use_account.get() else None,
                temp_file,  # 使用临时文件
                start_time,
                end_time,
                progress_callback=self.update_progress,
                target_ip=self.ip.get() if self.use_ip.get() else None  # 添加IP筛选
            )
            
            # 读取分析结果
            if os.path.exists(temp_file):
                with open(temp_file, 'r', encoding='utf-8') as f:
                    results = json.load(f)
                    
                # 计算统计信息
                filtered_events = len(results)
                event_id_counts = {}
                for event in results:
                    event_id = event.get('事件ID')
                    if event_id:
                        event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                
                # 更新结果显示
                self.root.after(0, lambda: self.update_results(results))
                
                # 更新统计信息
                self.root.after(0, lambda: self.update_stats(event_id_counts, total_events, filtered_events))
                
                # 如果需要保存到指定文件
                if self.use_output.get() and self.output_file.get():
                    with open(self.output_file.get(), 'w', encoding='utf-8') as f:
                        json.dump(results, f, ensure_ascii=False, indent=2)
                
                # 删除临时文件
                os.remove(temp_file)
            
            # 更新进度到100%
            self.root.after(0, lambda: self.update_progress(100, "分析完成！"))
            
            # 在主线程中显示完成消息
            self.root.after(0, lambda: messagebox.showinfo("完成", "分析完成！"))
            
        except Exception as e:
            error_msg = f"分析过程中出现错误：{str(e)}\n\n{traceback.format_exc()}"
            print(error_msg)  # 直接打印错误信息
            self.root.after(0, lambda: messagebox.showerror("错误", error_msg))
        finally:
            # 在主线程中恢复按钮状态
            self.root.after(0, lambda: self.analyze_button.configure(state='normal'))

    def start_analysis(self):
        try:
            if not self.file_path.get():
                messagebox.showerror("错误", "请选择EVTX文件")
                return
            
            # 清空结果显示区域
            for item in self.result_tree.get_children():
                self.result_tree.delete(item)
            
            # 清空统计信息
            self.stats_text.delete(1.0, tk.END)
            
            # 重置进度
            self.progress_var.set(0)
            self.progress_label.configure(text="准备开始分析...")
            
            # 禁用分析按钮
            self.analyze_button.configure(state='disabled')
            
            # 启动分析线程
            thread = threading.Thread(target=self.analysis_thread)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            error_msg = f"启动分析时出错：{str(e)}\n\n{traceback.format_exc()}"
            print(error_msg)
            messagebox.showerror("错误", error_msg)
            self.analyze_button.configure(state='normal')

def main():
    try:
        print("正在启动GUI...")
        # 设置多进程启动方法
        if sys.platform == 'darwin':  # macOS
            mp.set_start_method('fork')
        else:  # Windows
            mp.set_start_method('spawn')
            
        root = tk.Tk()
        app = WindowsEventAnalyzerGUI(root)
        print("GUI启动完成，开始主循环")
        root.mainloop()
        print("程序正常退出")
    except Exception as e:
        print(f"程序启动错误: {str(e)}")
        print("错误详情:")
        traceback.print_exc()
        messagebox.showerror("错误", f"程序启动失败：{str(e)}")

if __name__ == "__main__":
    main() 