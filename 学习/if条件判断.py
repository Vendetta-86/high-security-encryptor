'''
获取工资数目
按照不同工资区间判断
比较判断区间
如果输入的工资<0,提示输入错误
如果输入的工资是0-3500，提示精打细算
如果输入工资是3500-5000：提示一人吃饱不慌
如果输入工资是5000-7000：提示日子有滋有味
如果输入工资是7000-8000：提示日常生活轻松
如果输入工资>8000：提示财务自由
income("请输入你的工资数额：")
'''
def get_income(prompt):
    while True:
        try:
            income = int(input(prompt))
            if income < 0:
                print('工资不能为负数，请重新输入')
                continue
            return income
        except ValueError:
            print('输入有误，请输入整数')
No = get_income("请输入你的工资数额：")
print(f'您输入的工资是：{No}')
if No<=3500:
    print('请精打细算')
elif No<=5000:
    print('一人吃饱不慌')
elif No<=7000:
    print('日子有滋有味')
elif No<=8000:
    print('日常生活轻松')
else:
    print('财务自由')
