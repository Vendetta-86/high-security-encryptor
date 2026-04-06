import requests

cookies = {
    'Hm_lvt_1f23ddb44f391dc286e2ca51cee23527': '1774084027',
    'Hm_lpvt_1f23ddb44f391dc286e2ca51cee23527': '1774084027',
    'HMACCOUNT': 'E17DFB187CDE4590',
}

headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'zh-CN,zh;q=0.9',
    'cache-control': 'max-age=0',
    'priority': 'u=0, i',
    'referer': 'https://www.google.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    # 'cookie': 'Hm_lvt_1f23ddb44f391dc286e2ca51cee23527=1774084027; Hm_lpvt_1f23ddb44f391dc286e2ca51cee23527=1774084027; HMACCOUNT=E17DFB187CDE4590',
}

response = requests.get('https://pns.kurogames.com/picture', cookies=cookies, headers=headers)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-db482f72.js',
    headers=headers,
)


headers = {
    'accept': 'text/css,*/*;q=0.1',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'priority': 'u=0',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'style',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-1ea16201.css',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/content.js-e4490f5d.js', headers=headers)


cookies = {
    'HMACCOUNT_BFESS': 'E17DFB187CDE4590',
}

headers = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'If-None-Match': 'f69e90f9b4aa4dfb94ce370bfe2eb0e6',
    'Referer': 'https://pns.kurogames.com/',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-Fetch-Storage-Access': 'active',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    # 'Cookie': 'HMACCOUNT_BFESS=E17DFB187CDE4590',
}

response = requests.get('https://hm.baidu.com/hm.js?1f23ddb44f391dc286e2ca51cee23527', cookies=cookies, headers=headers)


headers = {
    'Referer': '',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/KV-AvantGarde-267b8e23.woff2',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get('chrome-extension://mjdbhokoopacimoekfgkcoogikbfgngb/assets/eduser.css', headers=headers)


headers = {
    'accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'accept-language': 'zh-CN,zh;q=0.9',
    'priority': 'i',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'image',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-storage-access': 'active',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://ali-sh-datareceiver.kurogame.xyz/sync_js?&data=eyJkYXRhIjpbeyIjdHlwZSI6InRyYWNrIiwiI3RpbWUiOiIyMDI2LTAzLTIxIDE3OjA5OjUzLjgwOSIsIiNkaXN0aW5jdF9pZCI6IjE5ZDBmYTVmMGFjN2Q0LTBkZGE0MTBjZGE1Y2M5OC0yNjA2MWY1MS0xNzY0MDAwLTE5ZDBmYTVmMGFkMTk1MSIsIiNldmVudF9uYW1lIjoicGFnZV92aWV3IiwicHJvcGVydGllcyI6eyIjZGV2aWNlX2lkIjoiMTlkMGZhNWYwYWM3ZDQtMGRkYTQxMGNkYTVjYzk4LTI2MDYxZjUxLTE3NjQwMDAtMTlkMGZhNWYwYWQxOTUxIiwiI3pvbmVfb2Zmc2V0Ijo4LCIjb3MiOiJXaW5kb3dzIiwiI2xpYl92ZXJzaW9uIjoiMi4wLjAiLCIjbGliIjoianMiLCIjc2NyZWVuX2hlaWdodCI6MTA1MCwiI3NjcmVlbl93aWR0aCI6MTY4MCwiI2Jyb3dzZXIiOiJjaHJvbWUiLCIjYnJvd3Nlcl92ZXJzaW9uIjoiMTQ2LjAuMC4wIiwiI3N5c3RlbV9sYW5ndWFnZSI6InpoIiwiI3VhIjoibW96aWxsYS81LjAgKHdpbmRvd3MgbnQgMTAuMDsgd2luNjQ7IHg2NCkgYXBwbGV3ZWJraXQvNTM3LjM2IChraHRtbCwgbGlrZSBnZWNrbykgY2hyb21lLzE0Ni4wLjAuMCBzYWZhcmkvNTM3LjM2IiwiI3V0bSI6Int9IiwiZXZlbnRfdXVpZCI6ImRrdGVzbnA5M3JndW55cWMiLCJldmVudCI6InBuc0d1YW5XYW5nIiwidXJsIjoiaHR0cHM6Ly9wbnMua3Vyb2dhbWVzLmNvbS9waWN0dXJlIiwicHJvamVjdCI6IndlYnNpdGUiLCJldmVudF9pZCI6IjEwMDAxIn19XSwiI2FwcF9pZCI6IjJiNmMxZmNiNWUwZDQ4YzBhNDk5MjZmOGUxODczNTk3IiwiI2ZsdXNoX3RpbWUiOjE3NzQwODQxOTM4MTB9&ext=crc%3D-630269930&version=2.0.0',
    headers=headers,
)


headers = {
    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'Referer': 'https://pns.kurogames.com/',
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'same-site',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

response = requests.get(
    'https://mp-cn-sdklog.kurogames.com/sync_js?&data=eyJkYXRhIjpbeyIjdHlwZSI6InRyYWNrIiwiI3RpbWUiOiIyMDI2LTAzLTIxIDE3OjA5OjUzLjgxMSIsIiNkaXN0aW5jdF9pZCI6IjE5ZDBmYTVmMGFjN2Q0LTBkZGE0MTBjZGE1Y2M5OC0yNjA2MWY1MS0xNzY0MDAwLTE5ZDBmYTVmMGFkMTk1MSIsIiNldmVudF9uYW1lIjoicGFnZV92aWV3IiwicHJvcGVydGllcyI6eyIjZGV2aWNlX2lkIjoiMTlkMGZhNWYwYWM3ZDQtMGRkYTQxMGNkYTVjYzk4LTI2MDYxZjUxLTE3NjQwMDAtMTlkMGZhNWYwYWQxOTUxIiwiI3pvbmVfb2Zmc2V0Ijo4LCIjb3MiOiJXaW5kb3dzIiwiI2xpYl92ZXJzaW9uIjoiMy4wLjAtYWxwaGEuNCIsIiNsaWIiOiJqcyIsIiNzY3JlZW5faGVpZ2h0IjoxMDUwLCIjc2NyZWVuX3dpZHRoIjoxNjgwLCIjYnJvd3NlciI6ImNocm9tZSIsIiNicm93c2VyX3ZlcnNpb24iOiIxNDYuMC4wLjAiLCIjc3lzdGVtX2xhbmd1YWdlIjoiemgtQ04iLCIjdWEiOiJtb3ppbGxhLzUuMCAod2luZG93cyBudCAxMC4wOyB3aW42NDsgeDY0KSBhcHBsZXdlYmtpdC81MzcuMzYgKGtodG1sLCBsaWtlIGdlY2tvKSBjaHJvbWUvMTQ2LjAuMC4wIHNhZmFyaS81MzcuMzYiLCIjdXRtIjoie30iLCJldmVudF91dWlkIjoiZGt0ZXNucDkzcmd1bnlxYyIsImV2ZW50IjoicG5zR3VhbldhbmciLCJ1cmwiOiJodHRwczovL3Bucy5rdXJvZ2FtZXMuY29tL3BpY3R1cmUiLCJwcm9qZWN0Ijoid2Vic2l0ZSIsImV2ZW50X2lkIjoiMTAwMDEifX1dLCIjYXBwX2lkIjoiMmI2YzFmY2I1ZTBkNDhjMGE0OTkyNmY4ZTE4NzM1OTciLCIjZmx1c2hfdGltZSI6MTc3NDA4NDE5MzgxMX0%3D&ext=crc%3D-1143623123&version=3.0.0-alpha.4&X-Data-Appid=2b6c1fcb5e0d48c0a49926f8e1873597',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-bfb4e8d9.js',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:32 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/back-f172128a.js',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:31 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/PhoneWallpaper-5d0e504b.js',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:31 GMT',
    'if-none-match': '"25E3A5DCAF00FB2B1BA0C8ECEA6D2560"',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/_plugin-vue_export-helper-c27b6911.js',
    headers=headers,
)


headers = {
    'accept': 'text/css,*/*;q=0.1',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:31 GMT',
    'priority': 'u=0',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'style',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/PhoneWallpaper-53e30db1.css',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-5c74d884.js',
    headers=headers,
)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-a8f4e769.js',
    headers=headers,
)


headers = {
    'accept': 'text/css,*/*;q=0.1',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'priority': 'u=0',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'style',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-199401d8.css',
    headers=headers,
)


headers = {
    'accept': 'text/css,*/*;q=0.1',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:35 GMT',
    'priority': 'u=0',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'style',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-0e180a61.css',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get(
    'chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/runtime-dom.esm-bundler-90e72f46.js',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/util-ff1b650c.js', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/index-9000aff5.js', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/Jsq-4d01198b.js', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/stat-e9139785.js', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Origin': 'https://pns.kurogames.com',
    'Referer': '',
}

response = requests.get('chrome-extension://ncennffkjdiamlpmcbajkmaiiiddgioo/assets/tool-13238bfa.js', headers=headers)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get('https://hmcdn.baidu.com/static/tongji/plugins/UrlChangeTracker.js', headers=headers)


cookies = {
    'HMACCOUNT_BFESS': 'E17DFB187CDE4590',
}

headers = {
    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'Referer': 'https://pns.kurogames.com/',
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-Fetch-Storage-Access': 'active',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    # 'Cookie': 'HMACCOUNT_BFESS=E17DFB187CDE4590',
}

params = {
    'hca': 'E17DFB187CDE4590',
    'cc': '1',
    'ck': '1',
    'cl': '32-bit',
    'ds': '1680x1050',
    'vl': '829',
    'et': '0',
    'ja': '0',
    'ln': 'zh-cn',
    'lo': '0',
    'lt': '1774084027',
    'rnd': '1503692125',
    'si': '1f23ddb44f391dc286e2ca51cee23527',
    'su': 'https://www.google.com/',
    'v': '1.3.2',
    'lv': '2',
    'sn': '51744',
    'r': '0',
    'ww': '1125',
    'u': 'https://pns.kurogames.com/picture',
    'tt': '游戏壁纸 - 战双帕弥什',
}

response = requests.get('https://hm.baidu.com/hm.gif', params=params, cookies=cookies, headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get('chrome-extension://mjdbhokoopacimoekfgkcoogikbfgngb/assets/edreader.css', headers=headers)


headers = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9',
    'origin': 'https://pns.kurogames.com',
    'priority': 'u=1, i',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

params = {
    't': '1774084193972',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/json/G144/MainMenu.json',
    params=params,
    headers=headers,
)


headers = {
    'accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:39 GMT',
    'if-none-match': '"6C9372968F0E8347566C06F41905AAE9"',
    'priority': 'u=1, i',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'image',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get('https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/favicon.png', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJkAAAA7CAQAAADCgeDUAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAKqNIzIAAAAHdElNRQflCAoPJhF3om/fAAAEK0lEQVR42u2a3ZmiSBiF39pnAqgQyGDZCJrJgIlg6QhGI2g6Ap6NwM5AJwLcCHQisDPADM5eUCAq0LIKzth1uGi7LIri5furEiM+mZ5I+XrNAF/ufQeT6omU6NpBPg+ym+CCz4LsZrjgMyC7KS54dGQ3xwWPjGwUXPCoyEbDBWAeri4bFRc8mpWNjgse0crGleCPe8/h95NHNlge2WB5ZIPlkQ2WRzZYHtlgjV7Kmot6yZp9xzdT0rhIk1T/SlmZ7VlrQIAl5E9CAj2bt7r3ZVqznoTR2cTHPkLtJBUK3fUy5dqpTYnrcanS0ed+fkga3zG3WpNgyfXVbIHwbBW4Z8s7P3m/i80M1gSOaZ4VEmJZ6q86Yr0Ca2B/7rCNHl16Gn/x3aOxTRlAVoWkDEC5pN6YXnpd7/zSh3ZMALPXN4IqvENriF/x3pU1fy1NtF9m1icNL2ddXsxZPaKM8KzfnO00c+7Sr7PFuGppC1tilr33REdH1rCUrZlXrcYcilelvAA/OodYu7/h/XHBFFZ2aikBsFVIrhVzs5flO9BuZaWqNyjyu+bJWtOvMQMAllgScllesMDb1aE/r4+M5NBsICMnJzQcDhI2CLEhBiAs+wBgycmbY5xoiiLDFQ45KJAkLWW1kSS3DigUNGZUFxllQVKPVf4XdRQZx1rU7da1ZI0rLI76xkJRPXZ5nU13kTG1lUUA/DR7vrKube7VvPeeUx72w9FfMRjmQFJH0JjS6eMaWEoCzI0xhmfeTkJCRsSebz1XmdjKlpJUrjcV1s95djSjUys7Vp+VpY3Pkfu8lBRrV10VVEhanNx/ZWXx0bn3tzIFxMDebGWVsjk82cMt3EAz4N3lWUsMZsUa+BtApbX+03pmwAKY9++QTFuXlWDelPLdudmKf8mARJjns/7zFmfc9oz/4krkfZ1lY0q3/EFCzBwXGjpWthmWjyu/CR1zo0xSIevcsygdUon71jb6Dl9jlskkV66iHK12yxlVEghx557df3Tk/EGfY06ATKHLjoUShUpAVjstDllSiZYVsKuQVS25pKwlj87ARaugFVmhULmk/K7InA1V2ilTVAViN+lAkSLFSl1auFTdyFJ32/HJGZu6zElakc3qT/H9kJXbPtJCScdebFP2JsgC7ZyVLQ650eXnwOVht0uswFVwzbpsIWnnHPtuVpbXDtiHLW86pvKeY9eB7KBCgcpy4mBPhXPNwD3G3BUx6Qmy8jGnrXczBTLQ8qi2DzVTeoJgoVSpoqtjWeX8CwW1Wx5i5LJ0TVDQqPgWsifIqvHDdmSjvyxlen5wu0TXzq/rR0FZQmDLsLnJv182VP79sv8jj2ywPLLB8sgGyyMbLI9ssDyywfLIBssjGyyPbLA8ssHyyAbrS71VcNl7wF4tvzD5rY0P5B1zsM6tzDvoB/oPEXqr4v9Db2UAAAAASUVORK5CYII=',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/mk36p5pxifhwvf43yp-17739965641462.png',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAn1BMVEUAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8Kd3m4AAAANHRSTlMA9/v67Br9yL5NSEMJ49fDpJWMfGpbPzAgDwTx3a+aj3dzZlY1KyfntaGHg2BROzcVAtCoXXSBCAAAASVJREFUOMuFkldigzAQRJFEaMbgbtx7b3Hy7n+22EmMhJXg+dphH5J2JCfXNTtHyzfnP1VqLgCbevev9ipAa2Qv0xYArr/1B99F56k/90COl/ey36ndjKgU+h0JyUrbKgzWRj8egt8zPmQ3IjX8DNzisZYKQm2HMHeKqsM2N11w+0/Am4eIH6YFNWtuH6JH3YCpBYxhbuzXsoAGzB71BJoWsIOjcYadBaSQh3nBnuJdofLorlVoPwF7CLRrQrVX6K8FnLTtbSCIzQ3ul2P+EHqQ6ttYJSCKz2oKDA4/SDZR2NnOJCA/PsejBEB5VrjnBK103ZZWeP1FIAEQo+hmNWEovoTHsPs7zkJycEq1UOzLiZOiUU6EL4lIMHlJ1MuJiqD1ggiyLxamKAou+6g1AAAAAElFTkSuQmCC',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/1bjlirsh8rcews5fuq-17739965466693.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/q6z9jz0zgt4d8l80h4-17739965853691.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/kydt41ub6hntypa2f5-17739965329824.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/fkyf9r8eszh647bdzw-17739965189635.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/bik5m82rknj2sx2zrz-17739964855607.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/c95czdwjvgkmyp0tfa-17739964686628.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/qbqrlroprbab2ev5xz-17739965010806.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/01xeqy6li7xn0nrwgx-17739964300029.png',
    headers=headers,
)


headers = {
    'sec-ch-ua-platform': '"Windows"',
    'Referer': 'https://pns.kurogames.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
}

response = requests.get(
    'https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/ho2k0w9vo6how4keob-177399640427910.png',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFsAAABeCAQAAADm8qChAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAKqNIzIAAAAHdElNRQflCxEOKh0T26yBAAAElUlEQVR42u2aX2hbVRzHP2nHLGUJyobYDIW2LiljSm3cg4oYik9i+iKI7cNqIWv2oIOFsTpUYh4cG3R1SKu2tS2b2IoPvqQP+mQKvrVxTxsksvqWPk2mEa3IVh/u7bzJPaf3pjm5vYXzfUnv+Z0/n3P6O7/zuycJbD3BPtQBju41wm7UstcAGtv/0tgaW2P7ShpbY2tsX0lje6kDTeq3jTHgCpv7CbuTy3QDx7nIejMGaIaTJPiKbgC6uUGiGdiBrZjS/toYs4Hm1DuL2tXu4roJvUmWrAmb4Dpd/sVOcMN0jl8ZJkeOYdOzlTuLSidZMz+tTmF1mufVYauOJJtcIVf1nOVnxmhTO4xa315nuAra0P/O4kvsHKe4I7Tc4ZRgOg1IdQD0SI2udgvpXbRKNzpuY80Pcokhia2NiLTdEJc4uFfYIabo56rQ1s6nzPOypOVV+pkitBfYYebo4QJLkgn10cY4rwnbLnGBHuYIe40dZZ4QZ8gLbI/xOc8A0EpW4kR5zhBigR4vsV9glj8Y4ZbAdoQZog+fAqR5h4Cg3i1G+J0ZXvQKe4BPuE2SssDWwZd01pS9zQfCccokuc0EA/UjtH5Ur3+Nco7vucjfAttTTAv9tYenWeG+rfwffuAoSQIUmondyocMMsuEAAG6mOZxSctOevmRf23lD1gBTtPBT2y5B6nnlGznMif5mGWhtYdJHt2xfZF3+U1oeZ33WeU9/nKL4t63DzPDCc5KoJ/lCwdoiEpD3jJnOcEMh1Vjd7JAiCSrQutJJjnkopcnmeeY0LJKkhALtu3cEHYvc9xjRJJ+vsQ12l1O/wjT9Aot64xwjzmeU4Xdz2fcJMVdiXWcR1xCA4SYlBz6d0lxkylede7EeUsOco5vmeCB0NrOG7uI/ff5TrL9WkjzJtdYbBTbl9qnd4AaW2NrbF9JY2tsje0r7VNs5/vtGDsnWxu2u9QEfUSJAAWKrAhfb0drnkuUKbnHds4AR21DVKtAqmqSGduLV4Gs7XJiTdBTmWWWqLjBdl7tjarVihCEqpKi5e8EGRO0QIEgfcQJE+NrUoK1rFjKYkCYUeKk3IDXm29PE0P2LUyMaaBCtuqKLc0QUGGgCmeN2v9TnFEiQI6sM4bKLWmsdLbmXnCCHBB0vAfPk6IMJAh6iZ0gDOQEl5lZE8fpIqnCNwDEvcQeBGBWaDNK33Lsw9gnHd5hB4lghDGR8oDS7yVVYUcseHZVKDyss5OMC2YX8VsVdthhwKKlllyGG7m4fVWFbfijPOL+aaklm/g4YWDRTdxu1q933E11+/w9RNRMIUqSTe0j7LAtbVhkVtXh7k4bJojMLzsstbZlPdyL/ELeHbJKbCPwHZPao5Za2ypVHe51SdWWNFZZFpmDZhqrTOpOyTwQkYS4OAArfsQ2oE4LLEGzNO9H7JyZMNl/E5U2k6xy3X16gA3nAcjUgBvPZSYUjqQ0bpfIkgEyDJK3vN1AhfPug5vX2IYjZAgTqUqbRO+SHmMvO4SxAgPEecXy5r4sTLBmqD186pL+7kZja2xfSWNrbI3tK2lsja2xfaX/AEk8DDGisxHRAAAAAElFTkSuQmCC',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ0AAAAtCAMAAACDMpmRAAAAkFBMVEUAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+WABnwAAAAL3RSTlMAQL+A3xAg8DDQYHCPn7D4W1AH7djDOOjlrHtJybeaVaaWXk5CKyUdFg2KdmtlYverTZYAAALpSURBVFjD7ZnZlqIwEIYrlY0EcG3tdu99nZl6/7cbQqKJjNqNzoUXfOcIChE+6icJHoGuGSC4Xjq7zu4HdHZXRGfX2f2Azm7LaDq/x8mqfHyDI0gJ5xO+q86zy+4pcDt/P9yC+KGtwsIeRVEtkLtdmMXNlqSTI3uO3UJTZKn2BZhHCObZq6EQjWvIZebsGDBK7BDBUWrZ3m7aJ6IxOZzmzV71kBowSLBkUzndA4bOjiBPzqVo6NeoWttJUVkNshkRraeDank/Su0MS8m9HQ8UgntYnbORO7vCwI4SgRKwjZ0TGo+AVysL783yIEIK8zupCXeFNFKZPNihRsQilI4DS8ja2M2owqy0k1zeiSJ/2CTFs5ZRBBWP4XBiza7ZE0yjFkiSerwMsSPx80eUG4roh8GvYmYm68VHUq6cBQxCQkHBNK2s4jXDytxqcAxJc3cpW9rZmSh39/y4/bR6SU55OGZsHk5qAsVqXL04+q6CyMFtD7SzW8fKLebR9Hb6Xe2QtnAvZ4h2NTIl+NtOaYUXJPtEW4rfRP3ejVuYqpAy2B3rbiS4h/IwnMVhZDg0oG2YIfCCZEeTba6Dygmd7RKmRDSPyZ6ePkKDzDICKLDCgiJGEjyXJAuvoV/07JhI8FmVKi/dsHzajlPWbODsEDkXlY4QBgIXJFvx4qs3m/cp5fbfZFNRIXZOWWrH/asgm9phPERLO9iQY/KlKUXEXhFnigOTWE7QtOsZVVC2Z1cyT2u70ar/8LWefG7GlFKmwTXfKi0gUOjUTg8BBBUZ6V60S9JtbfdabsDxYSih/3LCTppYGoOJXUaqMmdSICP7X+w+kqeVyCMcv++Y9qfO6rjzxA7RudcPBCXliR1yT2u7yNMdBcZ/AI7ed0qILMxSFShjU2nqFrzeVtrETqDnAjt4/RR1d6WbEZxASTiEZOB37O+2rH55uGpvF3l7Hgye3xbLBXxH95vsWujsOrsf0NldEZ3dBXbX/T/ZX+tGsbPmqfaQAAAAAElFTkSuQmCC',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ0AAAAtCAMAAACDMpmRAAAAkFBMVEUAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+WABnwAAAAL3RSTlMAQIC/EN8wYCDP73CQn/av1FoYZUbs491QOCscCQTaxpmFUz78d+nKtK2liSRsTkwb4rYAAAM7SURBVFjD7Zdrk5sgFIYPHFBA3dzv96Tbvbbv//93DWgr2kw37oc208kzE4cowcdzOGAItwyBbpe73d3uCu52N8Td7m53Bf/GbtibTJ8Hij7i39gls69fgaeEWqiW8N+2U0PyvKv1qA9tWtKQlx5Fp9Qgz88Hlv4S1w/467csEyfVJ+yOe95lIbWjdL3p43VdCYgSratGY3Ctm7bIVOLtBAlctCNT2M525hme8bl5AmaJmf4cnNFCUESKNJZzPRLsHUAZKLYTiOhod9rCM13SZrlaSPQpx6iysyImK+1kRa6rhgh5tuqXXW4bdkp4bCE83ezGEwSejrmd9ke0x3KAt8qOKUaUdmgjfSCtMjar7Ngxc15n1sgzmv2xW2ZPDhUP4bAcwYxwqHKXCtSwkXW5SLSioKinhWOnGQo9WYS0p8zQnAow+yts0cluZeFxk6+T0m5hBrTHoA5XJiosNwoU3rQVWSMDcwhKHcV2VTWLbnZ7b8SPi6Ey4tAHtF9Z5q+rVjJ/TzO3h1MOZESAIUlyVLN1BjrZnQD0z4HaKP9tnePL02Nofhg7jmadR1mAJEpsQZxHdp+L3ZqBnSKV9bgIySwAvKiGXU3DDlqWICNP4eplZD635NLI7nPzbgHMhrR+geebX40nANJWmTZpbx9VhyRMrpzPpGQgoBp21YqSdbEbhLw8IjB5P5/ZAni8wk4iaXfwdsxSaum3EUuRnQlrjhDSyA524xCoHQJfBNHKAQ/jhl2EuLCLCSSxnSw/OdLITlYwpEyvtxtq+OEQ2Ck/KtDbXK6KDOLCJpaB2nY9a3IkkR1XaDDnHWp2gNmSvruw0h2JRg9+n21vD783jdNUkbvYzs2JNPIErhdnlnpFOR26vUFtDtguNuPdts9LMocvwPQ7fWinbB0ay5FdAnM2F0qzQBrbJc6qjnaBbIaXcSIW76fDA/Dw7G/7wbwTrrx1EtKdRXbM3j28EBTIIjtKtPyMHa32W2CqfVn0iyN5/jzvjNblI8xxhlXdVdnQQ4ZzRRrZhW2YtetmF1DHt+K1ePs2XtFVGHV5GEGqEomRomqkMjP/8X+ya7nb3RB3u7vdFdztboibt7tlfgDHJaSHCA149gAAAABJRU5ErkJggg==',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ0AAAAtCAMAAACDMpmRAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAB5lBMVEX////8/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f7////8/f78/f7////////////////////8/f78/f78/f78/f78/f78/f78/f78/f7////////8/f78/f78/f78/f78/f78/f7////8/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f7////////////8/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f7////8/f78/f78/f78/f78/f78/f7////8/f78/f78/f78/f78/f78/f78/f78/f78/f78/f78/f7////8/f78/f78/f78/f78/f78/f78/f7////8/f4AAABdEz9iAAAAn3RSTlMAD0WDpLvX4ebn5NWqXCKV770GdP3LBRCibjCA32C/cLyRk5bcfQNAIAj4c5uZL89L3k3JzqGvBAo5eXCPn8WldeyerTJAQmqpv8zKTgvTn6jbw9rEYibQmvDiwt98ibn34/LBXRWzrCUUZSnNUCdGzwdmJFEhPAn6sPz2RALqj1scK6tQl9FSHRCB7wHlR5i2tS01jJSjr5BxE2jI9aeBXYMwAAAAAWJLR0ShKdSONgAAAAd0SU1FB+ULEQ4pKoBLWk0AAANtSURBVFjD7diJV9MwGADwzwPkUBEFq20XAYEWRaaAII4pHqh4ICDiAd4oKILijSKKIioD7xOV5k81TY8lXccYx9t4r9973bo0TX/kS5MW0JI5QIPkDU/n6Tydp/N0yRDT6pYsXbY8JXVFWnpG5spVSaZbnbUGM5G9Npl063IwH7nrnVUEIVG6DTgiNjqqiJrkcqIo+6Jcy4fmS7dJ5+TlF2zOKsSZRWlUl15sARQjZNnc4fpQlnkSDZHsSuFLqfpZonXQPD5jXckWotlKd0vxNsg2Oq/MPIqcj2EK59HYzpNkiQStwegk/SxEvhDy001xU0TTbSeWHVBeUZkFO3EVVO8qriEluy2dX2EjYLQtmVErmztGKQJRhQgdaSGIaIlCt7h0BcSyB1L31u2D/fgAHKw/dJiUHLF0/AAy2454sJVMHZIsndFjRqm+zVLXQCxH4djxE41wEjdBs5HZFit3PoVBIFVSmZQ5rsPp9B71zV13iupaT7edgbMEVWjozjHdFbDy6uc6slZT+ZY4HVs6B915qmvXdU0dF+DipZRcUnLZmczINCNncwuhuxLWtdTRkjZScjV23yF+1C1k39HMXuu8fqOrqvumQ8eMO64964bVArxOkSREx53K6WY1o+h9VwENt3puQ15vH/lxp9qhc28uvHxYFSydxM2Nts74U4Lx6RqJ5W5/xb37HSWtDx6SH48ek48nMXWSJjoqEIPfp+sQq9bnaITsXLN3/Qx0A8Ty9BnuA5yT06PrBp+TjyHXzLJQexVTLCZRkQoROmutgGkjii6fziAvAF5iPNxNdl8B+XjN6AKOlYJGeBELWM2q4ogmqIrg0CGzq81aUR52ougG6UoGRW8ARt/C8Lv3MEZKatwyy+yqIfsBoDZk10VBhGxPFJ0iuymi6cYnMG7+8BHjT+WVn3vLvnz9RnDfw8dddYJfsx81wvMMybEaCjh0Ztg6KS4ddEY+3v1gDruNOyVk5FWk6TYnFBBDteTiIUFyGaUwov00btpQMC4d/HLi2tmjLuNOlWXRvKQ+4s2RJGr6dQUkSOZEyN/sQXutjk8Hv7m3CtwFsUJ1HdoWRjHvlyhzh3tM89Yz+af075AO+zc6NVYfR5vzFzHeZ0umMB6YTIhsBjron8gYTxhuMf8vIOHh6Tydp1t0umSO/3lzmDSbFlp5AAAAAElFTkSuQmCC',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ0AAAAtCAQAAAAe5aEoAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAKqNIzIAAAAHdElNRQflCxEOKSP5l+LpAAAEfklEQVRo3u2aT2gcVRzHP2kSGyExi9QWRNtJqSj+XavgseOlFBG6iHpSsohFag9tQFEvdUsVpILrKddthHrQQ4gILQhOvEiotJuKglrLTPVQq+JE2hi0Sb4e9mWym+zO7rws3QTm82Az83tvfvub77zfy29mtksixYoeoKvTQWxItKnTEWxcUumsSaWzJpXOmlQ6a1LprEmlsyaVzppUOmtS6axJpbOmJ7b3WeaZorvG1oW4ynynA+88XVLM7b+AxToz8xCjnQ684zS5/b9G/ZS+Z5VlM/fzPA/W2OJmtIfqNDdR8G5dH97N0i4+YbO8wgDiFl6gD/ieSbpZ5EQ04j52A+f5j3P0AUc5Tj/P8BefM8/tXGOeek8Ex/gKgB3kCRgz1iBR7AHHzNYwDie5bOFjLUiihXZJkvSG2btXH2lKl3VBNyRJp4ReUoXX9Yck6ZwebcGvK8lrKYK45kly1+wlWWv5eV1lXAaA5/iBF3mC7TxsZu114FMz8gRbANjNeR6wvqJOg+TNJEpqF6euPdvAnohWpeuKPu/kEwAOcAeDfAPAAnCbGXkGl6e4CMApK9FKhPh4iGJk9fDI4hHiIUrmIjYmTxnh4eOTjYQULgVCyvj45NaoXYsJG0iS3hN6V5J00NjPSJJGhe42CbtdCG3RrKQrujVxwvryVZSrnMqS8lFKhpLGlVNO3qpjViZsXtK48nJVkORXfVeoUEfkqqBwjUmuZNK9I3Ra0r/qrQq6VrrHTM+Xkr7W5sTSZZUxWxmFUZ9XJeNqqVavdct7hajPlVSOvK91lU34bmIR6Aeus9BwzFIBPQN8Z1E6TzMTeZiuWdlORltj0GTNm6zZWh47EXmfJEhYDK2gJ/ERC8AgA/wNwD+r+mfN34dY5FsWraLKsYdszIkFwJ4mPhzjxYnx4uBWiZyQZLOuF7gIdEcV1RAAN1h+JTkAwFvsYo6A5G95XXzGcZjgSaYtzypDEZ/DBIwwYitNM5LNuk3AKC8Dh+nlZ95kK1BJ0qWLMMFptrEPmOOnxPE4jBMwZArbmYbSECvr2xxhhA+BuMRu5qUFMVphG1ApQMocB+BVPqCfzwA4xONcQYDYyjD7APjRlChJyJHhWNM7gv3AhZj+PNNGuMY4ZAkaXpw2SneWX/nFSHGUg5zlIl9wF/uZYo7f2MWCSc7X+JjfucT77LVI12rcqCJb2q+QI09Q9U8jjgzDNfuPmIowQwmiZceOFouTuDYohBxTnAwJ9bR87MoSwZEUqqiCxhWqHEXnSQpVVkElSaGysXVdSZKngory5Ukq1NR1JRXkSyqt6axbruuatx1Gur2JjsrKU7HGkpMvKVRJjvI1dZ2jkkL5KslZ4aUor0bMjEqSpLLyQp6pCF1JBeVVliLbupBup5Hu6Tb5q21eG+J0o/nXjqbkdV0jZvHpY54/2+ZxndM+6a6ys9Mnc3NJX+tYE/9uYv2QJWN/y2TIkCVo21NkbRTp1h/przrtSaWzJpXOmlQ6a1LprEmlsyaVzppUOmt6qPyeKSUx/wOKVyVoWOmDogAAAABJRU5ErkJggg==',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKkAAAAtCAQAAAB//YNqAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAKqNIzIAAAAHdElNRQflCxEOKTB9KaM3AAAEfUlEQVRo3u3a3WscVRzG8c/WttZGMVqVWGuzrdSX+rZiBRHbruCtaL0TxMQ/oNrc6IXUJndeqFEEvU3QGxFEqmJRYTegImJhtRA10hotSlWkrfYtjcnxIuN028xuMu1stuh852LPnvPbZ8955jdzztmdQghyMmUxCu3uxH+KsKjdPfjvkVuaObmlmZNbmjm5pZmTW5o5uaWZczaWPqWio90dP39ZnCp6hReV3IYOR9vd9fOVdJZu9xg46u85Igv+txvddBf+z/Gnmm1ih+3zo63tHlq7SJeln8elZjm42hrc1O6htYt0WbrbryA0tfRl8Fcq5aAclQb1Zji+Vuk2IV2WHvOBXhSanoo94KKz7FHJYVA0XlfXGZVqigYTPnVf23RnkXYR9Vv0qcmEtm4b9LnbXn9gNehwmQsTlfqF6CjPaus06Ie6+kGV6CjpVDZuxIgiRoxwmkKrdOdNuizlIFhija9mtY3400pHdRu10fUYMu1it1ifqDVuGDuidxUwgM2edMgW1brYmj6lOI+GVbHZiH70nzH0Vum2yNLdYJHuBEv36lJVxgTWYIN9JhtOVOP664bep4ZxmxX1GToj9tBpRjSnVbotsvTr6DVpXfq+Zx2xAu+6H4zqcmyeyrV4cMOzBn4mlei1HBu38LoNSX/hH9CF6YS2UZ95wQ0YwzIFb7jOhIkU+p1xqexJWxpEzWTeoJph9MxjLm+VbgaWnjSmC+vtmtW2ywFXqlkaZeb1doJX5zXgsgc9ZDiuKyo1jJ/JvEN+VNVsEmmVbqaW8p1NuCKx7RX34o5oGXXCJs9bpuqJOTS3YYeadwzptiO67F5qGF+KDOtWRveC62Zs6czqblli28x64HY1sM7F7sKqOS2tYsg4ygbijKo2jP93hi7NcWm2Srcp6S2dWZk+YsyUgmCfL+Kd0pcewEbDjllutQ/B73NqVuNhVgzonyO2EMeOe7wtuhlbOtPJLq/FNYe96SO7HPG6AVxrsQnLHbMUyVMZlOIZdm6K+hMuxOKC6s6XEIJUx7qQzMFwTRDGQgj7wsqwN4SwLVwVpkII3yTq9IeDoRIqoRJKDRT749hKXFcO5cTYcst153uE9Fl6gUlLwLQRV7sxqu/0qZt9bJ3L/eJba93jJScb3HWhFu+gT+2kK4bie954XWw1jikaiEo9JMa2SrdlWdoRjkdn8HgQhKfrzunD4dEQwlToCDtCCDuDsL9hlpZDb9I5rsuhU0clVOZd2yrdFmbpCd+7FVzoUoddUtf2rRIWudKv2IzdVjXQqab4zjS/B7VKd96kt3TKH1GpoA/PxC3bjdoEVvjdzONry2T7L2yvnrhcom4iOjd7MtRNb2n9j8undsI/2WonRk2bttZb1joZ6Z/lknlOauepbup7qfD2GbPiJ+GxsDRuXRVWhovid3eG50JPCu1yKJ7DfWzhdRPupYUQUj9futUTgkl77Dfhvbp/pHI4K0tzmpE/sps9uaWZk1uaObmlmZNbmjm5pZmTW5o5uaWZk1uaOYs1f7AxJzX/ACy5sM9qeERdAAAAAElFTkSuQmCC',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKkAAAAtCAMAAADiKrvTAAAAbFBMVEUAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8+T+BWAAAAI3RSTlMAQIC/3zAg79BgEHCfr49Q2vzjbUkVaPXpy7iEqDosCVgmGZ7g6qkAAALwSURBVFjD7ZnpctsgEICX5dbtq7mTtvv+71hbIMAwTkZyxo1n9P2INASTb9kFZAXoXgCC+2A1hdX0DlhNYTW9yGH3PGyH591fmMmtTd8GcgwM5nFjU/lIE48SZnFb04OhiDnAHG5r+otSdpBRVfD9qCWm1TOl8ExMEkKJFHamGhtRYA0cEc0C03dNKQ/vkwxzCOFvzkIQopSReTjJzCGNICjqARixBaaMzghjcCp/EbFkzzWbU8Ati8O2RKSbRJYYcARoG4CGL8l+nwn9nkwNS6mdKXo6gQ7nJjU1Pet08LekO9Y3pGWIhdRoWtdH036J6T4z7SfTNO6QMMrBsdYFWS8snblXtCSq8cq5Ic616EKG5pnGpV8ufmsZRbjCmEjM/w5SNyWIuzCngDsXCkPkAlFwyxgzxlX9TNNqyEyHKk5jzTzmbII7ynYZExoEVadBSYScG3/XHoPhGLM123RPOfss4eXgPB8tiEFDbPxkA0Hd7ySmYcxcYfrxSjntx1dzymkCfUce66Aef2LsK5OP4HTDZ5uqDeVs/mT7VzEyCXRQXZpibsr8ZqDcFVEIRDvb1FLJryL7l44t30Hmc1oXcwrcFcjy7DdU8vqFKZLMOpAGT+vrtJ0aNPmump9YbirIbM5zb0iU2adUWsQOcvKTk5j2lzD/rd9wCRE5MXTZRzvXlHCfL32kuKLSE6o8SGsKTe003Y1PVT0l37pQOLn6DYU/17QG9UgpWsEuyX55q3SouE7HDbX2OVa+k2bO3LipbZkzXZD9iC2W02emlSEZ/DjEVoPYxmNeamoRj61VGOF6U0CKvLimi3XKtD/hx5KoIaiiCI9O8eFKYHLgcc7FVaaHlyeKPL0cAC7XqRLCzVpfPnV31OVnbJ+GjSeuMX172Gy3YjBPZhDb7eaBwWeoqmyLFdDK9IuH1IRq+najMIbU/e83E1VLRxqIqoaO2J/4DkVZRJk2yBpr9RNN1/dSP5HVFFbTO2A1/X7ofv5v+g9PSJcpgz3O2wAAAABJRU5ErkJggg==',
    headers=headers,
)


headers = {
    'accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:36 GMT',
    'if-none-match': '"94FFD671F8A8153BFF506B467BA7DB70"',
    'priority': 'i',
    'referer': 'https://pns.kurogames.com/',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'image',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get(
    'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/kurogame-57e277bb.png',
    headers=headers,
)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,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',
    headers=headers,
)


headers = {
    'accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'accept-language': 'zh-CN,zh;q=0.9',
    'if-modified-since': 'Tue, 10 Mar 2026 02:43:32 GMT',
    'if-none-match': '"4E216C6A85E428CE62A72B0EF24953A8"',
    'priority': 'u=1, i',
    'referer': 'https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/index-0e180a61.css',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'image',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
}

response = requests.get('https://pns-cdnstatic.kurogames.com/resource/pns_website2.0/assets/bg-e327f0aa.png', headers=headers)


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'Referer': '',
}

response = requests.get(
    'http://data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABzwAAABYCAMAAAC3fHGPAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAA/FBMVEX///8AAAD/AAD/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAACuqLdoAAAAUXRSTlMAAAABBDtJVxMKdRYtZjddBnIcAmsnRFAjbQxZWjombANGTkCAcBAwYCAHcxrf78+/MmGfjx8Fr1RLtA92CHQYTCwUCyhqbyE/VWgrFTVfWAnbUjZyAAAAAWJLR0QB/wIt3gAAAAd0SU1FB+UIDAs6CjnSDG4AAASKSURBVHja7d2JctNGAAZgmQQK4T7NUU7JsQPYMTgcLaVNb3p7+/4PU8mYjKeTgB1brCR/3wySgrH5bTL8s9qVkiRQHxubsRMAQM2cPBU7ASXZ+OJ07AgADXVm62zsCJTj3PmN2BEAmurCxdgJKMWly1diRwBorKvXrseOQBlutGMnAGiwm7esGWqg01u3Y0cAaLI7J2MnYPW+vBs7AUCjGaM00L37D2JHAGi2h49iJ2DFHty/GTsCJUmzLOtsTw6zdtKaaGdZt9j38seyndZCihea7hd41px/S+wPC0r1+MnT2BFYrbt3YiegLFnI9Yv2bIf+pO/SQfFbu3l9DouDdOHuLGpzuptTOtjWnZA8e+6KwEa5veX+CI2VhU46CqP8KK/Kdt5Q3TDYS9ujMNjJyzNN07lq7fB6m/tpo5GBJyTJxvlzsSOwSu0bsRNQmiykSRKGSbIThmGYN1Q/TE7ZdtOiPBcadbamJ2snm0XO224P2soTci86L2NHYHWuXL4UOwKleT/y3EuSvdDeDTv5wPPVQVkNw6JznslBeSbJ/OXZ68/96tA8IYSD49dp7DSszMyJhK9C+Dp2HFbrYM5zMEg6Ya+VhqzVHU4cPec5ffxT5Tlvew73SinPDCrtw3fqbHm++eZN7P8TWJWZKeyZ8rwX+/uOJcz882ZhlPXy7uyFwXA3DLaLkWcaJo169Jzn5PHw0fJc4LztzvsTxUuV58ffJFTZbHkm6evYcViRt99+d3Bs5Nk8kznP3O77Quy1+pNlQ61RGC0x5znToZ+W7c7/6tBwLzsvYkdgNR7ux05Amabl2Q39fJuG3WLYuZe2h6G/fbw5z1nzPanfUZ7wwfd+gFUz/LD1Y+wIlGlanqPQK3bD0G2l/WIIOtxZ5jrP6W4u3TDv1TCxPyv4DDaeP4sdgVW4eCF2Akq1k05uL9RNp18VA80Pdxjqpote53mwyna6m8fo1Zx/UHuyFp4+eRw7Asv76eersSPwGS1WlKsx6C1WzdBwjx7GTsDSNn/5NXYEgLXinm4N8O632AkA1oy7idee63UBPrfNW36OVc29fhc7AcDauX7NYpNae9HZjB0BYP24zKHWrv7+R+wIAGvoz60zsSNwfH/9HTsBwFo6dTJ2Ao7vn7OxEwCspU336AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI5rnP/ar+QGACrr7X4VNwBQXW+LYV7lNgBQXfF78tBN7I8FAI5WVNW4epvYHwsAHG2cVGFxkAVDANRK/MVBFgwBUIIT5SheugITnIcuGCrxLQOwFsprkvg9ecSCIeUJwHJOnPi3BEWTVGBx0PjQBUPlvWUA1kN5w7BxUoXFQYdsjDwBqK74i4MsGAKgXiowwekOQwDUSvyedIchAGqmAouDxu4wBECtjJMKLA5yhyEA6iX+4iALhgColwpMcFowBECtxO9JC4YAAAAAAAAAAAAAAAAAAAAAAKCKQggf/RoA+B/lCQALUp4AAAAAAAAAAAAAAACsmEtUAGBByhMAFqQ8obL+A6vuzJ7gsBDUAAAAAElFTkSuQmCC',
    headers=headers,
)
print(response.text)