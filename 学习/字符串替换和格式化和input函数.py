msg = ' 快来组队！游戏ID：player888，邮箱 player888@example.com.速联 '
#.strip('需要去除的字符')：去掉字符串前后指定字符
clean_msg = msg.strip(' ')
print(msg) #去除前
print(clean_msg) #去除后

#.replace('旧字符'，‘新字符’），将旧字符替换为新字符
safe_msg = clean_msg.replace('player888','*********').replace('player888@example.com','********@example.com')
print(safe_msg)

#关键词替换提示 f'字符串内容{变量}'
out_put = f'[已过滤】{safe_msg}]'
print(out_put)

#input 函数：程序提示用户输入
msg = input('请输入你的评论：')
safe_msg = clean_msg.replace('player888','*********').replace('player888@example.com','********@example.com')
print(safe_msg)

'''
BMI计算
BMI=体重（kg）/身高（m）的平方
体重过轻：BMI<18.5
正常范围：BMI=18.5~23.9
超重：BMI=24.0-27.9
肥胖：BMI>28.0

1.75m 70kg 70/(1.75*1.75)=22.86
'''

height = float(input('请输入你的身高（米）：')) #获取身高
weight = float(input('请输入你的体重（千克）：')) #获取体重

bmi = weight / (height * height)
print(f'你的BMI是：{bmi:.2f}')
if bmi < 18.5:
    print('您的体重过轻'),
elif 18.5 < bmi < 23.9:
    print('您的体重在正常范围')
elif 24.0 < bmi < 27.9:
    print('您的体重超重')
else:
    print('您的体重已在肥胖范围')