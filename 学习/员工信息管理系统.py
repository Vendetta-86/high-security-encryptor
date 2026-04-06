'''
用列表存储员工信息字典
每个员工信息包含：工号、姓名、年龄、性别、电话、部门
列表存储
一个字典存储一个员工信息,例：
[{
   '工号‘：’1001‘
   ’姓名‘：’李四‘
   ’年龄‘：28
   ’性别‘：’男‘
   ’电话‘：’12345‘
   ’部门‘：’市场部‘
}，{...}]

用户使用系统，选择功能
1：添加员工
2：查询员工
3：修改员工信息
4：删除员工
'''
from random import choice

info = [] #列表，员工信息，全局变量

#一个函数一个功能
def show_menu():  #系统功能菜单
    print('\n'+'='*10+'员工信息管理系统'+'='*10) #开头换行符
    print('1:添加员工')
    print('2:查询员工')
    print('3:修改信息')
    print('4:删除员工')
    print('5:退出系统')
    print('='*25)

def add_staff():
    print('正在执行：添加员工')
    emp_id = input('请输入工号').strip()  #strip()去除输入信息收尾空格，防止因空格导致信息验证失败
    name = input('请输入姓名').strip()
    age = input('请输入年龄').strip()
    gender = input('请输入性别').strip()
    phone = input('请输入电话号码').strip()
    dept = input('请输入部门').strip()
    #工号唯一性检验
    for emp in info:
        if emp['工号'] == emp_id: #遍历全局字典info，取键值工号进行对比
            print(f'工号{emp_id}已存在，请勿重复添加！')
            return
    #工号唯一，构造员工记录
    new_staff = {
        '工号': emp_id,
        '姓名': name,
        '年龄':age,
        '性别': gender,
        '电话':phone,
        '部门':dept,
    }
    info.append(new_staff) #用append，将字典加到列表末尾
    print(f'员工{name}、工号{emp_id}添加成功！')

def search_staff():
    print('正在执行：查找员工')
    emp_id = input('请输入要查询的工号：').strip()
    for emp in info: #遍历全局列表info，对比工号
        if emp['工号'] == emp_id:
            print('\n---员工信息---')
            print(f'工号：{emp['工号']}')
            print(f'姓名：{emp['姓名']}')
            print(f'年龄：{emp['年龄']}')
            print(f'性别：{emp['性别']}')
            print(f'电话：{emp['电话']}')
            print(f'部门：{emp['部门']}')
            print('='*20)
            return #匹配成功，结束函数
    print(f'未找到工号为{emp_id}的员工')

def modify_staff():
    print('正在执行：修改员工信息')
    emp_id = input('请输入要修改的工号：').strip()
    for emp in info: #遍历info,列出查询的字典值
        if emp['工号'] == emp_id:
            print('\n---当前员工信息---')
            print(f'工号：{emp['工号']}')
            print(f'姓名：{emp['姓名']}')
            print(f'年龄：{emp['年龄']}')
            print(f'性别：{emp['性别']}')
            print(f'电话：{emp['电话']}')
            print(f'部门：{emp['部门']}')
            print('=' * 20)
            #逐项询问是否需要修改，回车表示跳过
            new_name = input(f'新姓名（回车跳过，当前{emp['姓名']}):')
            if new_name:
                emp['姓名'] = new_name
            new_age = input(f'新年龄（回车跳过，当前{emp['年龄']}):')
            if new_age:
                emp['年龄'] = new_age
            new_gender = input(f'新性别（回车跳过，当前{emp['性别']}):')
            if new_gender:
                emp['性别'] = new_gender
            new_phone = input(f'新电话（回车跳过，当前{emp['电话']}):')
            if new_phone:
                emp['电话'] = new_phone
            new_dept = input(f'新部门（回车跳过，当前{emp['部门']}):')
            if new_dept:
                emp['部门'] = new_dept
            print(f'工号{emp_id}的信息已更新！')
            return
    print(f'未找到工号为{emp_id}的员工，无法修改')

def delete_staff():
    print('正在执行：删除员工')
    emp_id = input('请输入要删除的工号').strip()
    #循环遍历员工信息，enumerate:同时返回索引和元素
    #i:代表索引，emp：代表元素值
    for i, emp in enumerate(info):
        if emp['工号'] == emp_id:  #匹配要删除的员工信息
            print('\n---即将删除的员工信息---')
            print(f'工号：{emp['工号']}')
            print(f'姓名：{emp['姓名']}')
            print(f'部门：{emp['部门']}')
            print('=' * 20)
            confirm = input('确定要删除吗？（y/n）')
            if confirm == 'y':
                del info[i]
                print(f'工号{emp['工号']}的员工已删除！')
            else:
                print('删除操作已取消！')
            #结束函数
            return
    print(f'未找到工号为{emp_id}的员工，无法删除')

#主程序
def main():  #主程序入口
    while True:
        show_menu() #调用函数，显示功能菜单
        choice = input("请选择操作（1-5）：").strip() #选择功能
        if choice == '1': #调用添加员工函数
            add_staff()
        elif choice == '2':
            search_staff()
        elif choice == '3':
            modify_staff()
        elif choice == '4':
            delete_staff()
        elif choice == '5':
            print('感谢使用本系统，再见！')
            break
        else:
            print('输入无效，请输入1-5之间的数字')
main() #调用主程序函数
