f = open('note.txt', 'r', encoding='utf-8')
#打开文件，open(‘文件名’，‘操作，,r代表只读’，‘文件编码为中文，避免出现乱码’）

#第一次读取文件,文件指针在开头
text1 = f.read()
print('第一次读：',text1)

#此时文件指针在末尾，再读一次
text2 = f.read()
print('第二次读：',text2)

#将指针移回开头,再读
f.seek(0)
text3 = f.read()
print('第三次读：',text3)



#关闭文件
f.close()