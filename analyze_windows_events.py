#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import xml.etree.ElementTree as ET
import json
from datetime import datetime
import Evtx.Evtx as evtx
import multiprocessing as mp
from multiprocessing import Pool, cpu_count
import os

# 常见的Windows事件ID及其描述
EVENT_TYPES = {
    # 登录相关事件
    4624: "登录成功",
    4625: "登录失败",
    4634: "注销",
    4647: "用户启动的注销",
    4648: "使用明确凭据进行登录",
    4649: "已为用户配置了Kerberos约束委派",
    4672: "使用特权账号登录",
    4769: "请求了Kerberos服务票证",
    4771: "Kerberos预身份验证失败",
    4778: "重新连接到Windows会话",
    4779: "断开Windows会话连接",
    
    # 进程和服务事件
    4688: "进程创建",
    4696: "主要令牌分配",
    4697: "服务安装",
    
    # 计划任务事件
    4698: "计划任务创建",
    4699: "计划任务删除",
    4700: "计划任务启用",
    4701: "计划任务禁用",
    4702: "计划任务更新",
    
    # 用户账户管理
    4720: "用户账户创建",
    4722: "用户账户启用",
    4723: "用户尝试更改密码",
    4724: "密码重置尝试",
    4725: "用户账户禁用",
    4726: "用户账户删除",
    4727: "安全启用的全局组被删除",
    4728: "成员添加到安全启用的全局组",
    4729: "成员从安全启用的全局组移除",
    4730: "安全启用的本地组被删除",
    4731: "创建安全启用的本地组",
    4732: "成员添加到安全启用的本地组",
    4733: "成员从安全启用的本地组移除",
    4735: "安全启用的本地组被更改",
    4737: "安全启用的全局组被更改",
    4738: "用户账户更改",
    4740: "用户账户锁定",
    4741: "计算机账户创建",
    4742: "计算机账户更改",
    4743: "计算机账户删除",
    4776: "计算机尝试验证账户凭据",
    4798: "枚举用户的本地组成员身份",
    4799: "枚举安全启用的本地组的成员",
    
    # 系统事件
    4608: "Windows正在启动",
    4609: "Windows正在关闭",
    4616: "系统时间已更改",
    
    # 审核和策略事件
    4902: "每用户审核策略表被创建",
    4904: "尝试注册安全事件源",
    4905: "尝试注销安全事件源",
    4906: "事件日志已清除",
    4907: "审核设置已更改",
    4908: "特殊组的成员资格已列出",
    4912: "每用户审核策略已更改",
    5379: "凭据验证",
}

# 登录类型及其描述
LOGON_TYPES = {
    2: "交互式登录",
    3: "网络登录",
    4: "批处理登录",
    5: "服务登录",
    7: "解锁登录",
    8: "网络明文登录",
    9: "新凭据登录",
    10: "远程交互式登录",
    11: "缓存交互式登录",
}

def parse_xml_event(xml_string):
    """
    解析事件的XML数据
    返回 (事件ID, 事件数据字典, 时间戳)
    """
    try:
        root = ET.fromstring(xml_string)
        
        # 定义命名空间
        namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # 从System节点获取EventID和时间
        system_node = root.find('.//ns:System', namespaces)
        if system_node is None:
            return None, None, None
            
        event_id_node = system_node.find('.//ns:EventID', namespaces)
        if event_id_node is None:
            return None, None, None
            
        event_id = int(event_id_node.text)
        
        time_created_node = system_node.find('.//ns:TimeCreated', namespaces)
        if time_created_node is None:
            timestamp = None
        else:
            sys_time = time_created_node.get('SystemTime')
            if sys_time:
                try:
                    timestamp = datetime.strptime(sys_time.split('.')[0], '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        timestamp = datetime.fromisoformat(sys_time.replace('Z', '+00:00'))
                    except:
                        timestamp = None
            else:
                timestamp = None
        
        # 从EventData节点获取事件详细数据
        data = {}
        event_data = root.find('.//ns:EventData', namespaces)
        if event_data is not None:
            for data_item in event_data.findall('.//ns:Data', namespaces):
                name = data_item.get('Name')
                if name and data_item.text:
                    data[name] = data_item.text
        
        return event_id, data, timestamp
    except Exception as e:
        print(f"解析XML错误: {str(e)}")
        return None, None, None

def process_chunk(chunk_data, event_ids=None, logon_types=None, target_account=None, start_time=None, end_time=None):
    """
    处理事件数据块
    """
    try:
        print(f"开始处理数据块，包含 {len(chunk_data)} 条记录")
        results = []
        event_id_counts = {}
        event_count = 0
        filtered_count = 0
        
        for i, record in enumerate(chunk_data):
            try:
                event_count += 1
                event_id, data, timestamp = record  # 直接使用已解析的数据
                
                if event_id is None:
                    continue
                
                # 更新事件ID计数
                event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                
                # 检查是否符合时间范围
                if timestamp:
                    if start_time and timestamp < start_time:
                        continue
                    if end_time and timestamp > end_time:
                        continue
                
                # 如果没有设置任何筛选条件，或者事件ID在筛选列表中
                if not event_ids or event_id in event_ids:
                    filtered_count += 1
                    
                    # 检查登录类型筛选
                    if logon_types and data.get('LogonType'):
                        logon_type = int(data.get('LogonType'))
                        if logon_type not in logon_types:
                            continue
                    
                    # 检查账号筛选
                    if target_account:
                        target_username = data.get('TargetUserName', '')
                        subject_username = data.get('SubjectUserName', '')
                        
                        if not (target_username and target_account.lower() in target_username.lower() or
                               subject_username and target_account.lower() in subject_username.lower()):
                            continue
                    
                    # 创建事件信息字典
                    event_info = {
                        '时间': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f') if timestamp else '未知',
                        '事件ID': event_id,
                        '事件类型': get_event_description(event_id),
                        '账户': data.get('TargetUserName', '未知'),
                        '域': data.get('TargetDomainName', '未知'),
                        '工作站': data.get('WorkstationName', '未知'),
                        'IP地址': data.get('IpAddress', '未知'),
                        '进程名称': data.get('ProcessName', '未知'),
                        '登录进程': data.get('LogonProcessName', '未知'),
                    }
                    
                    # 添加登录类型信息
                    if data.get('LogonType'):
                        logon_type = int(data.get('LogonType'))
                        event_info['登录类型'] = f"{logon_type} ({get_logon_type_description(logon_type)})"
                    
                    results.append(event_info)
                
                if i % 1000 == 0:  # 每处理1000条记录打印一次进度
                    print(f"已处理 {i + 1}/{len(chunk_data)} 条记录")
                    
            except Exception as e:
                print(f"处理记录时出错: {str(e)}")
                continue
        
        print(f"数据块处理完成，共处理 {event_count} 条记录，符合条件 {filtered_count} 条")
        return results, event_id_counts, event_count, filtered_count
        
    except Exception as e:
        print(f"处理数据块时出错: {str(e)}")
        import traceback
        print("详细错误信息:")
        print(traceback.format_exc())
        return [], {}, 0, 0

def save_to_excel(results, output_file):
    """
    将分析结果保存为Excel文件
    """
    if not EXCEL_SUPPORT:
        raise ImportError("未安装openpyxl库，无法导出Excel文件。请运行 'pip install openpyxl' 安装。")
    
    # 创建工作簿和工作表
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "事件分析结果"
    
    # 定义表头
    headers = ['时间', '事件ID', '事件类型', '账户', '域', '工作站', 'IP地址', '登录类型']
    
    # 写入表头
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col)
        cell.value = header
        cell.font = Font(bold=True)
        cell.alignment = Alignment(horizontal='center')
    
    # 写入数据
    for row, event in enumerate(results, 2):
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=row, column=col)
            cell.value = str(event.get(header, ''))
            cell.alignment = Alignment(horizontal='center')
    
    # 调整列宽
    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = (max_length + 2)
        ws.column_dimensions[column].width = adjusted_width
    
    # 保存文件
    wb.save(output_file)

def analyze_events(evtx_file, event_ids=None, logon_types=None, target_account=None, output_file=None, start_time=None, end_time=None, progress_callback=None, target_ip=None):
    """
    分析Windows事件日志
    """
    try:
        print("正在打开EVTX文件...")
        with evtx.Evtx(evtx_file) as log:
            print(f"开始分析事件日志: {evtx_file}")
            print(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            print("正在计算总记录数...")
            # 获取总记录数
            total_records = sum(1 for _ in log.records())
            print(f"总记录数: {total_records}")
            if progress_callback:
                progress_callback(10, f"总记录数: {total_records}")
            
            print("开始分析记录...")
            # 初始化结果列表和计数器
            results = []
            event_id_counts = {}
            processed_count = 0
            filtered_count = 0
            
            # 直接处理所有记录
            for record in log.records():
                try:
                    processed_count += 1
                    xml_data = record.xml()
                    event_id, data, timestamp = parse_xml_event(xml_data)
                    
                    if event_id is None:
                        continue
                    
                    # 更新事件ID计数
                    event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                    
                    # 检查是否符合时间范围
                    if timestamp:
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue
                    
                    # 如果没有设置任何筛选条件，或者事件ID在筛选列表中
                    if not event_ids or event_id in event_ids:
                        filtered_count += 1
                        
                        # 检查登录类型筛选
                        if logon_types and data.get('LogonType'):
                            logon_type = int(data.get('LogonType'))
                            if logon_type not in logon_types:
                                continue
                        
                        # 检查账号筛选
                        if target_account:
                            target_username = data.get('TargetUserName', '')
                            subject_username = data.get('SubjectUserName', '')
                            
                            if not (target_username and target_account.lower() in target_username.lower() or
                                   subject_username and target_account.lower() in subject_username.lower()):
                                continue
                        
                        # 检查IP地址筛选
                        if target_ip:
                            ip_address = data.get('IpAddress', '')
                            if not (ip_address and target_ip.lower() in ip_address.lower()):
                                continue
                        
                        # 创建事件信息字典
                        event_info = {
                            '时间': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f') if timestamp else '未知',
                            '事件ID': event_id,
                            '事件类型': get_event_description(event_id),
                            '账户': data.get('TargetUserName', '未知'),
                            '域': data.get('TargetDomainName', '未知'),
                            '工作站': data.get('WorkstationName', '未知'),
                            'IP地址': data.get('IpAddress', '未知'),
                            '进程名称': data.get('ProcessName', '未知'),
                            '登录进程': data.get('LogonProcessName', '未知'),
                        }
                        
                        # 添加登录类型信息
                        if data.get('LogonType'):
                            logon_type = int(data.get('LogonType'))
                            event_info['登录类型'] = f"{logon_type} ({get_logon_type_description(logon_type)})"
                        
                        results.append(event_info)
                    
                    # 更新进度
                    if processed_count % 1000 == 0:
                        progress = 10 + int((processed_count / total_records) * 80)
                        if progress_callback:
                            progress_callback(progress, f"已处理 {processed_count}/{total_records} 条记录")
                        print(f"已处理 {processed_count}/{total_records} 条记录")
                        
                except Exception as e:
                    print(f"处理记录时出错: {str(e)}")
                    continue
            
            print("分析完成")
            # 打印事件ID统计信息
            print("\n事件ID统计:")
            for event_id, count in sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"事件ID {event_id}: {count} 条")
            
            print(f"\n统计信息:")
            print(f"总事件数: {processed_count}")
            print(f"符合事件ID筛选的事件数: {filtered_count}")
            print(f"最终匹配的事件数: {len(results)}")

            # 如果指定了输出文件，将结果保存为JSON
            if output_file:
                print(f"正在保存结果到文件: {output_file}")
                if progress_callback:
                    progress_callback(90, "正在保存分析结果...")
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2, default=str)
                
                print(f"\n分析结果已保存到: {output_file}")

    except Exception as e:
        print(f"错误: {str(e)}")
        import traceback
        print("详细错误信息:")
        print(traceback.format_exc())
        sys.exit(1)

def get_event_description(event_id):
    """
    获取事件ID的描述
    """
    return EVENT_TYPES.get(event_id, "未知事件")

def get_logon_type_description(logon_type):
    """
    获取登录类型的描述
    """
    return LOGON_TYPES.get(logon_type, "未知登录类型")

def main():
    parser = argparse.ArgumentParser(description='Windows日志分析工具V1.0')
    parser.add_argument('evtx_file', help='EVTX日志文件路径')
    parser.add_argument('--event-ids', type=int, nargs='+', help='要分析的事件ID列表')
    parser.add_argument('--logon-types', type=int, nargs='+', help='要分析的登录类型列表')
    parser.add_argument('--account', help='要筛选的特定账号')
    parser.add_argument('--output', help='输出结果到JSON文件')
    parser.add_argument('--start-time', help='开始时间 (格式: YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--end-time', help='结束时间 (格式: YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--list-events', action='store_true', help='列出所有支持的事件ID及其描述')
    parser.add_argument('--list-logon-types', action='store_true', help='列出所有登录类型及其描述')
    
    args = parser.parse_args()
    
    if args.list_events:
        print("支持的事件ID列表:")
        for event_id, desc in sorted(EVENT_TYPES.items()):
            print(f"{event_id}: {desc}")
        return
    
    if args.list_logon_types:
        print("登录类型列表:")
        for logon_type, desc in sorted(LOGON_TYPES.items()):
            print(f"{logon_type}: {desc}")
        return
    
    start_time = None
    end_time = None
    
    if args.start_time:
        start_time = datetime.strptime(args.start_time, '%Y-%m-%d %H:%M:%S')
    
    if args.end_time:
        end_time = datetime.strptime(args.end_time, '%Y-%m-%d %H:%M:%S')
    
    analyze_events(args.evtx_file, args.event_ids, args.logon_types, args.account, args.output, start_time, end_time)

if __name__ == "__main__":
    main() 