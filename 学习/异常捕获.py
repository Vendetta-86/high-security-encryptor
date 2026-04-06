'''
无限循环

如果转换成功 → break

如果失败 → 捕获异常 → 重新输入
'''
while True:
    try: #用来捕获异常
        age = int(input('请输入年龄：')) #程序设定年龄为数字int
        break
    except ValueError: #int() 转换失败时抛出,如输入字符时
        print('请重新输入')
print(f' 您的年龄是{age}')
