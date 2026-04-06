import requests
from bs4 import BeautifulSoup
import os

# 目标URL
url = "https://media-cdn-zspms.kurogame.com/pnswebsite/website2.0/images/1773936000000/8hoakwr6fbpwlfli2l-17739965855021.png"

# 发送HTTP请求获取网页内容
response = requests.get(url)
if response.status_code != 200:
    print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
    exit()

# 使用BeautifulSoup解析网页内容
soup = BeautifulSoup(response.content, 'html.parser')

# 查找所有的图片标签
img_tags = soup.find_all('img')

# 创建保存图片的目录
if not os.path.exists('images'):
    os.makedirs('images')

# 下载所有图片
for img in img_tags:
    img_url = img.get('src')
    if not img_url:
        continue

    # 确保图片URL是完整的
    if not img_url.startswith('http'):
        img_url = 'https:' + img_url

    try:
        img_response = requests.get(img_url)
        if img_response.status_code == 200:
            # 提取图片文件名
            img_name = os.path.basename(img_url)
            # 保存图片到本地
            with open(os.path.join('images', img_name), 'wb') as f:
                f.write(img_response.content)
            print(f"Downloaded {img_name}")
        else:
            print(f"Failed to download {img_url}. Status code: {img_response.status_code}")
    except Exception as e:
        print(f"Error downloading {img_url}: {e}")

print("All images downloaded.")
