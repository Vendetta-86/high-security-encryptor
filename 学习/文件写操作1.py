f = open('test.txt', 'w', encoding='utf-8') #打开date.txt文件，若不存在则自动创建，w为覆盖写入而非追加，中文加编码避免报错
f.write('写入测试\n')
f.write('write功能在写入中不会自己换行\n')
f.write('所以要换行必须在句子末尾加上换行符\n')
f.write('写完要关闭，不然不会存盘\n')
f.close()
f = open('test.txt', 'r', encoding='utf-8')
test1 = f.read()
print(test1)
