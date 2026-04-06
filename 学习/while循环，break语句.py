count = 1
while count <= 10: #条件判断
    print(f'第{count}次提醒') #循环体
    count += 1 #执行+1再次判断

day = 1
while day <= 100:
    print(f'今天是第{day}天')
    day += 1 #没有条件控制语句进入死循环

while True: #无明确循环内容，一直到获得True值。True为python中的bool值，表示永远成立
    answer = input('休假申请：同意/不同意：') #input接收内容
    if answer == "同意": #条件判断语句，不通过则循环提问
        print('谢谢！')
        break #条件判断通过，结束循环

status = ['已提交','已提交','未提交','已提交']
for statu in status: #for循环遍历状态信息
    if statu == '未提交': #条件判断
        print('项目报告未提交，跳过')
        continue #跳过后续代码
    print('写评语') #处理已提交状态
print('所有工作检查完毕')