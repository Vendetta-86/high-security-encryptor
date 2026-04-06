from pathlib import Path

import cv2
import numpy as np


script_dir = Path(__file__).resolve().parent
image_path = script_dir / "downloads" / "juv.jpg"

print(f"脚本目录: {script_dir}")
print(f"图片路径: {image_path}")

if image_path.exists():
    file_bytes = np.fromfile(str(image_path), dtype=np.uint8)
    im = cv2.imdecode(file_bytes, cv2.IMREAD_GRAYSCALE)
    # IMREAD_COLOR输出彩色图
    # COLOR改成GRAYSCALE则输出黑白的灰度图，通道就只有一个
    # im.shape只输出长宽两个数字
else:
    im = None

if im is None:
    print("图片读取失败，请检查路径或文件是否损坏。")
else:
    print(f"图片读取成功，尺寸: {im.shape}")
    cv2.imshow("JUV", im)
    cv2.waitKey(0)
    cv2.destroyAllWindows()
    print(im,im.shape) #高度 宽度 通道数

cv2.imwrite("juv2.jpg", im)
