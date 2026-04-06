#苹果信息#
apple_name = '苹果'
apple_price = 8.5 #苹果单价8.5元#
apple_weight = 1.5 #苹果重量#

#牛奶信息#
milk_name = '牛奶'
milk_price = 15 #牛奶单价15元#
milk_count = 4 #牛奶数量#

#收银信息#
print ('············XXX超市收银单·············')
#苹果价格#
print(apple_name,':',apple_weight ,'斤 X',apple_price,'元/斤',apple_weight*apple_price,'元')
#牛奶价格#
print(milk_name,'：',milk_count,'盒 X',milk_price,'元/盒',milk_count*milk_price,'元')

print('········································')
#总价#
total_price = apple_price*apple_weight + milk_price*milk_count
print('总计:',apple_price*apple_weight,'+',milk_price*milk_count,':',total_price,'元')