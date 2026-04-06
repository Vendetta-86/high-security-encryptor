#F12-网络-大小
url = 'https://m704.music.126.net/20251229211403/fb7015e67ade72139239d4890f12b029/jdyyaac/obj/w5rDlsOJwrLDjj7CmsOj/60633809660/ee0d/699c/9b3f/4071eb7c32584e5109f8a8ca0b9cda80.m4a?vuutv=MZb2jPgm+tkM1mX+LY0fU0v+FJUyuva2w4F7UcvqEHmGIe4x2yBuufGC1FH07ocCdVYyGDvXxO2ldU3iKRcMznpF/q+zcOjmJSfNOgRlz04=&authSecret=0000019b6a27aaec1cce0a3b226302f1&cdntag=bWFyaz1vc193ZWIscXVhbGl0eV9leGhpZ2g'
import requests
data = requests.get(url).content
#新建（’命名‘，’wb‘）
open('到六月了吗.mp3','wb').write(data) #w：写入数据权限，b：转数据权限
