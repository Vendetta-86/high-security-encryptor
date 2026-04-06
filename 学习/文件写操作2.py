#with open模式指上下文管理器，保证安全打开关闭文件，无需手动调用close方法，释放资源
with open('app.txt', 'a', encoding='utf-8') as f: #a模式将内容追加到末尾
    f.write('追加写入测试\n')
    f.write('a模式写入到末尾,每运行一次就多写一次\n')
    f.write('操作记录\n')
f = open('app.txt', 'r', encoding='utf-8')
text = f.read()
print(text)