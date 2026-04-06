class Grandpa: #第一个类
    def has_house(self):
        print('爷爷有房子')

class Father(Grandpa): #括号后写第一个类名，继承第一个类的内容
    def has_car(self):
        print("爸爸有奔驰车")
    def has_money(self):
        print("爸爸有100万存款")


class Son(Father): #继承上个类
    def has_car(self): #本类的has_car
        super().has_car() #super：父类调用，此处调用父类的has_car
        print("儿子骑车上学")
        '''
如果这么写
    def has_car(self):
        print("儿子骑车上学") 
那么本类的has_car会覆盖父类的信息
'''
#复用继承类的已有功能
xiaoming = Son()
xiaoming.has_money()
xiaoming.has_car()