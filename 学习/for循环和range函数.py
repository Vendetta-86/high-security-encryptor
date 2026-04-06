idcard = ['赵','钱','孙','李'] #for 变量 in 可迭代对象
for name in idcard:#循环体代码
    print(name)


for num in range(1,10):#range(1,10)为整数1开始到9，最后一位10不包含，如果写作range(10)，则为默认从0到9共十位
    print('工位',num)

shopping_lst = ['milk','eggs','meat','fruit','soap']
for item in shopping_lst:
    print(f'get {item}')

site_lsr =['s1','s2','s3','s4']
for item in site_lsr:
    print(f'arrive {item}')

info = {'adam':92,'eva':50,'pitt':80,'mark':77} #字典内容
for report in info: #遍历字典，取键
    score = info[report] #字典的值通过键获取
    money = score * 100
    print(f'{report},your final KPI score is {score},and your money is {money}')


