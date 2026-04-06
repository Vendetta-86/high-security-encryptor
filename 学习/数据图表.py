import  matplotlib.pyplot as plt #导入命令

#设置中文
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False
#准备数据 月份，销售额
months = [1,2,3,4,5,6,7,8,9,10,11,12]
sales = [22,56,89,7,11.5,185,65.58,78,34,66,78.4,95]

#绘图
plt.plot(months,sales,color='darkblue',linewidth=2,label='月度销售额') #绘折线图

plt.title('2025年月度销售额',fontsize=24,fontweight='bold',pad=20)
plt.xlabel('月',fontsize=12)
plt.ylabel('销售额（万元）',fontsize=12)

plt.legend(loc='upper right',fontsize=12) #显示图例
plt.tight_layout() #自动调整

plt.show() #显示