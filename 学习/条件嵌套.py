#第一个条件
is_member = input('是否是会员？是/否：')
#第一次判断
if is_member == '是': #是会员要执行的操作
    member_type = input('您的会员等级是？黄金/黑卡/其他：') #获取会员等级
    #对黄金的判断
    if member_type == '黄金':
        print("商品打九折")
    elif member_type == '黑卡':
        print('商品打八折')
    else:
        print('商品打九五折')

else:
    print('非会员，按原价结算')