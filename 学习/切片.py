id_no = '33090219850823003x'
#第17位是奇数为男，偶数为女
gender_code = id_no[16]
print(gender_code) #方法一：从前往后
gender_code = id_no[-2]
print(gender_code) #方法二：从后往前

#gender_code = id_no[20] #索引越界

#提取生日，7到14位，索引6到13
birthday = id_no[6:14] #结束位为实际取数大一位
print('出生日期：',birthday)

#隔一个数取值
print('从头开始隔一个数取值',birthday[::2])
#取值倒排
print('从尾倒排',birthday[::-1]) #从尾数依次倒排
print('隔数倒排',birthday[::-2]) #从尾数隔一个倒排