#函数简介
def func1(): #定义
    print('good')
    print('great')
    print('perfect')
func1()  #调用


def make_food(food): #food为形参，接收传递过来的参数
    print(f'正在制作一份{food}三明治') #提示语，food自动替换传进来的值
    sandwich = f'{food} 三明治' #sandwich参数： 将三明治保存下来，之后return
    print('制作完成！')
    return sandwich #传递三明治，即sandwich内容
my_sandwich = make_food('鸡蛋') #加入实参，调用函数
print(f'我拿到了：{my_sandwich}')
my_sandwich = make_food('牛油果') #更换实参，调用函数
print(f'我拿到了：{my_sandwich}')

#匿名函数，临时使用的函数，可以作为传参，只能用一行直接获得结果的表达式，不能使用if之类的循环语句
#普通函数示例
def add(x):
    return x + 1
print(add(5))
#匿名函数对比，假设以上功能只用一次，则额外声明多耗资源。匿名函数用lambda标识
add = lambda x:x+1
print(add(5))

#闭包函数（嵌套函数）=内部函数+记住外部的数据+能被单独调用
