class Student: #定义类框架
    dept = '计算机系' #类属性
    def __init__(self, name, grade,score):  #定义初始化,self：当前学生自己
        self.name = name #name为外部传入参数
        self.grade = grade
        self.score = score
        pass

    #介绍
    def introduce(self):
        print(f'{Student.dept}{self.grade}年级学生{self.name}，成绩是{self.score}分')

    #判断是否优秀
    def is_excellent(self):
        return self.score >= 90


#创建学生对象
stu1 = Student(name='adam',grade=3,score=95)
stu1.introduce()
print(stu1.is_excellent())
stu2 = Student(name='eva',grade=2,score=85)
stu2.introduce()
print(stu2.is_excellent())