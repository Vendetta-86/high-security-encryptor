info = ['董事长','总经理','财务','人事']
print(info[2])

# 使用append在列表末尾增加新元素
info.append('行政')
print(info)

# 更改索引为3的元素
info[3] = 'HR'
print(info)

# 用remove根据内容删除相应元素
info.remove('行政')
print(info)

# 用clear清空列表
info.clear()
print(info)