info = {'张伟':'技术部','李娜':'市场部','李强':'财务部','赵敏':'人事部'} #字典内容 键：值
print(info['李娜']) # 直接取值，查找‘李娜’键的值

#直接取值，不存在的键会报错，用get方法，返回none
print(info.get('陈晨'))

#以号码为键的字典
staff = {'E001':'张伟','E002':'李娜','E003':'李强'}
print(staff['E001'])
print(staff['E002'])

staff['E004'] = '赵敏'#新增键
print(staff['E004'])
print(staff)

staff['E003'] = '王强' #当键存在时，赋值语句为修改键值，键不存在时，赋值语句为新增键值
print(staff['E003'])
print(staff)

del staff['E002'] #删除键值
print(staff)

staff.clear() #清空字典内容为空字典
print(staff)