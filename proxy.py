#!/usr/bin/env python
# coding=utf-8
import base64
import hashlib
import codecs
from binascii import unhexlify
import binascii
from ctypes import *
import pprint
import time
import socket

'''
.text:0040EEB1 push    0                               ; flags
.text:0040EEB3 push    32h                             ; len
.text:0040EEB5 push    offset byte_4196E6
.text:0040EEBA push    s                               ; s
.text:0040EEC0 call    send                            ; Random choise

offset byte_4196E6 - 32h(50) - 11
002E 0000 0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 ....
0000 0000 0402 0008 0008 0000 0000 0000 0000 0020

002E 0000 0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000
0000 0000 0B02 001A 0030 0000 0000 0000 0000 0020 0000 0000 0000

002E 0000 0000 0000 0000 0000 0000 0000 39DF 0003 0007
0000 0000 0F02 003E 0137 0000 0000 0000 0000 0020 0000

Random 									- 0001 0000 0000
ALGERIA/ALGER/ALGIERS 					- 0402 0008 0008
ARGENTINA/DISTRITO FEDERAL/BUENOS AIRES	- 0B02 001A 0030 
0F02 003E 0137


.text:00405F87 push    0                               ; flags
.text:00405F89 push    esi                             ; len
.text:00405F8A push    ebx                             ; buf
.text:00405F8B push    [ebp+s]                         ; s
.text:00405F8E call    recv                            ; Recv d

ebx - 12eh - 11 (24 ,байта на запись)
ebx - 12e6h - 360
0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 0000 0000 0000 0000 0000
000B 0E68 51AB 1CD0 A356 A505 523B 0DAF DA04 020E 0000 6300 000E 8496 3541 1258
D506 1B18 7EBD 10E0 EA05 3537 0000 3400 000E F7D8 0FFA EFB0 1FF5 55C6 D4D6 0EE0
8B05 D235 0000 6300 000E 47F8 DBD4 8FF1 B7A8 0FC7 1E68 19E0 F805 243E 0003 6200
000E F426 A3EA E84D 47D5 1854 C0CB 2A95 9D03 140C 0000 6400 000E 062A 5EF7 0C54
BDEE A1CB 5666 340E 0600 E801 0002 5F00 000E FE8A EFC2 FA28 BF0B 921F 7E72 3E4C
A005 1947 0000 6100 000E 2902 8588 A40A 1620 9B18 0106 19E0 2005 0241 0000 6100
000E FE3F 52BD F8FD 4AF7 A152 86D1 3195 1503 1E0D 0000 6400 000E D122 8216 4487
085B E6D5 F44B 3EE3 A005 8E47 0002 6300 000E 69FA A51E A7E7 9479 3A5F 6242 3E6D
A005 C047 0000 6200 000E 0000 0000

0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 0000 0000 0000 0000 0000
000B
0E68 51AB 1CD0 A356 A505 523B 0DAF DA04 020E 0000 6300 000E
8496 3541 1258 D506 1B18 7EBD 10E0 EA05 3537 0000 3400 000E 
F7D8 0FFA EFB0 1FF5 55C6 D4D6 0EE0 8B05 D235 0000 6300 000E 
47F8 DBD4 8FF1 B7A8 0FC7 1E68 19E0 F805 243E 0003 6200 000E
F426 A3EA E84D 47D5 1854 C0CB 2A95 9D03 140C 0000 6400 000E
062A 5EF7 0C54 BDEE A1CB 5666 340E 0600 E801 0002 5F00 000E
FE8A EFC2 FA28 BF0B 921F 7E72 3E4C A005 1947 0000 6100 000E
2902 8588 A40A 1620 9B18 0106 19E0 2005 0241 0000 6100 000E
FE3F 52BD F8FD 4AF7 A152 86D1 3195 1503 1E0D 0000 6400 000E
D122 8216 4487 085B E6D5 F44B 3EE3 A005 8E47 0002 6300 000E
69FA A51E A7E7 9479 3A5F 6242 3E6D A005 C047 0000 6200 000E
0000 0000



0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 0000 0000 0000 0000 0000
000B 
F626 E4D0 D89B 9343 2B5D 92C6 4368 D102 0D09 0000 6300 000E 
0129 1623 04A4 588C 5050 168F 8822 2200 3A02 0002 6400 000E
1B84 0361 6E0D 0D84 495E 15CF 3EAF A005 B247 0001 6300 000E
E0C4 3541 C188 6A83 AC05 53F6 B3A9 A003 4947 0000 6400 000E
DFE4 FE56 BFC9 FCAD B632 F12A 0BE0 1A05 A32F 0000 6300 000E
84E6 38E1 1398 E386 2141 2651 F6E0 AE04 8D19 0005 6300 000E
52F2 AD03 A5E5 5A06 A14F 4834 639F 9C03 680D 0004 6300 000E
ABE7 F7A3 AF9F DE8E A301 037F 3ECE A005 6147 0000 6200 000E
B244 A695 C912 9A56 8C45 E5DA 01E0 6905 2B25 000B 6300 000E
FE3C 58EB FC78 B1D7 5F45 C23A 13E0 6405 EF3C 0000 6000 000E
9284 CB91 2509 9723 5EC2 74BF 954D 0F01 9C08 0000 6400 000E
0000 0000



.text:00405D51 push    0                               ; flags
.text:00405D53 push    44h                             ; len
.text:00405D55 push    offset byte_41E472              ; buf
.text:00405D5A push    [ebp+s]                         ; s
.text:00405D5D call    send                            ; Login/password

C2 C6 99 C2 5B B2 D1 95  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 03 00 68 00
2C C6 CC C2 DA CA 3A 6F  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
68 F8 21 E2 


 20 00 00 00 65 4F 90 9E  01 00 00 00 42 3C 32 9D  DF 39 03 00 04 02 02 02  1C 03 00 00 F0 03 00 00
66.60.50.157

95.189.37.83
13568
hk1.dblvpn.net
my1.dblvpn.net
us1.dblvpn.net
eu3.dblvpn.net
eu1.dblvpn.net
103.253.40.67

002E 0000 0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 0000 0000 0000
0000 0000 0402 0008 0008 0000 0000 0000 0000 0020 0000 0000 0000 0000 0000 0000
0000 0000 0000 0006 0000 0000 0000 0000 0000 0000 0000 0020 0000 4AEF E009 0000
0000 0B58 F095 39DF 0003 000F 0000 0000 0000 0000 0000 0000 0000 0011 0000 0000

002E 0000 0000 0000 0000 0000 0000 0000 39DF 0003 0007 0000 0000 0000 0000 0000
0000 0000 0B02 001A 0030 0000 0000 0000 0000 0020 0000 0000 0000 0000 0000 0000
0000 0000 0000 0006 0000 0000 0000 0000 0000 0000 0000 0020 0000 4AEF E009 0000
0000 0B58 F095 39DF 0003 000F 0000 0000 0000 0000 0000 0000 0000 0011 0000 0000
'''

t = '71 04 13 84 1b 61 03 5e 49 cf 15 af 3e 05 a0 47 1e 8c b6 8e aa 6d 5d 47 bc bb 3e 05 a0 47 12'
'''
F6 26 E4 D0 D8 9B 93 43 2B 5D 92 C6 43 68 D1 02 0D 09 00 00 63 00 00 0E \
01 29 16 23 04 A4 58 8C 50 50 16 8F 88 22 22 00 3A 02 00 02 64 00 00 0E \
1B 84 03 61 6E 0D 0D 84 49 5E 15 CF 3E AF A0 05 B2 47 00 01 63 00 00 0E \
E0 C4 35 41 C1 88 6A 83 AC 05 53 F6 B3 A9 A0 03 49 47 00 00 64 00 00 0E \
DF E4 FE 56 BF C9 FC AD B6 32 F1 2A 0B E0 1A 05 A3 2F 00 00 63 00 00 0E \
84 E6 38 E1 13 98 E3 86 21 41 26 51 F6 E0 AE 04 8D 19 00 05 63 00 00 0E \
52 F2 AD 03 A5 E5 5A 06 A1 4F 48 34 63 9F 9C 03 68 0D 00 04 63 00 00 0E \
AB E7 F7 A3 AF 9F DE 8E A3 01 03 7F 3E CE A0 05 61 47 00 00 62 00 00 0E \
B2 44 A6 95 C9 12 9A 56 8C 45 E5 DA 01 E0 69 05 2B 25 00 0B 63 00 00 0E \
FE 3C 58 EB FC 78 B1 D7 5F 45 C2 3A 13 E0 64 05 EF 3C 00 00 60 00 00 0E \
92 84 CB 91 25 09 97 23 5E C2 74 BF 95 4D 0F 01 9C 08 00 00 64 00 00 0E

246  38 228 208 216 155 147  67  43  93 146 198  67 104 209   2  13   9   0   0  99   0   0  14 
  1  41  22  35   4 164  88 140  80  80  22 143 136  34  34   0  58   2   0   2 100   0   0  14 
 27 132   3  97 110  13  13 132  73  94  21 207  62 175 160   5 178  71   0   1  99   0   0  14 
224 196  53  65 193 136 106 131 172   5  83 246 179 169 160   3  73  71   0   0 100   0   0  14 
223 228 254  86 191 201 252 173 182  50 241  42  11 224  26   5 163  47   0   0  99   0   0  14 
132 230  56 225  19 152 227 134  33  65  38  81 246 224 174   4 141  25   0   5  99   0   0  14 
 82 242 173   3 165 229  90   6 161  79  72  52  99 159 156   3 104  13   0   4  99   0   0  14 
171 231 247 163 175 159 222 142 163   1   3 127  62 206 160   5  97  71   0   0  98   0   0  14 
178  68 166 149 201  18 154  86 140  69 229 218   1 224 105   5  43  37   0  11  99   0   0  14 
254  60  88 235 252 120 177 215  95  69 194  58  19 224 100   5 239  60   0   0  96   0   0  14
146 132 203 145  37   9 151  35  94 194 116 191 149  77  15   1 156   8   0   0 100   0   0  14 

	69.95.58.194
	69.140.218.229
	1.163.127.3
	79.161.52.72
	65.33.81.38
	50.182.42.241
	5.172.246.83
	94.73.207.21
	80.80.143.22
	93.43.198.146
	194.94.191.116


0000   c2 c6 99 c2 5b b2 d1 95 00 00 00 00 00 00 00 00
0010   00 00 00 00 00 00 00 00 00 00 00 00 03 00 68 00
0020   2c c6 cc c2 da ca 3a 6f 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0040   68 f8 21 e2

0000   c2 c6 99 c2 5b b2 d1 95 00 00 00 00 00 00 00 00
0010   00 00 00 00 00 00 00 00 00 00 00 00 03 00 68 00
0020   2c c6 cc c2 da ca 3a 6f 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0040   68 f8 21 e2

00 00 00 00 00 00 00 00  00 00 00 00 00 00 DF 39
03 00 07 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 01 00 00 00 00 00  00 00 00 00 00 00 00 00
20 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 06 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 20 00 00 00  00 00 00 00 00 00 00 00




st = ''
for i, j in enumerate(t.split(' ')):
	if (i % 24 == 0):
		print (st)
		st = ''
	st += str(int(j,16)) + ' '
print (st)

auth_tx = b'c2c699c25bb2d1950000000000000000000000000000000000000000030068002cc6ccc2daca3a6f00000000000000000000000000000000000000000000000068f821e2'
			c223d46ca998c8000000000000000000000000000000000000000000030068002cc6ccc2daca3a6f00000000000000000000000000000000000000000000000012b61299
#68
auth_rx = b'14000000df39030037b5953b110200003139204a756c792032303134202d2031333a33373a313800000000000000000000000000000000000c7c3438'
			140000009fb6000037b5953b910100003234204a756c792032303134202d2031313a30363a34370000303500000000000000000000000000fc6d093b
#60
#tx1 = b'11000000000000000000000000000000df39030013'
#21
#tx1 = 11000000000000000000000000000000df39030033
#21
#rx1 = b'15000000000000000000000000000000000000003342c7e55d'
select_random_tx = b'2e000000000000000000000000000000df390300070000000000000000000000000000000100000000000000000000000000'
select_random_rx = b'2e010000000000000000000000000000df390300070000000000000000000000000000000b0034959516d054565a4549fb0c144a004401d90c0000620e00b06c105b60d920b64f5751a54673018d06f9000000630e002f099e91be2478462e95b7e6dd3e05a0470f000000640e009f99b3d97f66ce665d37218c684302d10964000000640e002fcaafd65f945fad56cc1e85466d0171061b020000620e0027bb2a489decaa2071a1588ae63005a047a4010000610e00ceccf0d33b33c34f4f67e82e509e01250826000000630e008dbb1d1a1a773b3463301debe0f1042a15d4010000600e005e8aac90bd1459211fae37aaa9a7030c0e3c030000610e00f2dc8812e4b911254443f719e00e05d334b9000000620e00f516094ad55b24285d670d1dc14104260f42110000640e0000000000'
select_country_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000001000000'
select_country_rx = b'1f020000000000000000000000000000df39030008000000000000000000000000000000017e0046007f047300490016003f02cc0011016500cd00d800b3014000ca00af006a05c60065059500f902ae008e01e000970b4c007f00ce00100236000a028a0076002200e802630058007f00340015000f0133001f01a9000b0327004b045000b202dd004505de000e000f0090003500910068004c04d100c800aa0068010e00c9016100b100df001603e6002a015f00d700790098016a00da004d004c035e006a006d00bb009800670037008200a700220067001c01c000f800450054007000200010003200530005009f005900bb0085000b00d20062004200c1006600e200090004000f00cb00ec00ec000e007a001f001c0031002e001b008d000a008800490084000200740005002c000400c40021000c003000b9003e0097000100e300160060003600030009001f009300640005007200370082001600c7000300d7000a00d60002003c001700bf001700a6000d008f000e005d000200e50031009a000100a1000b00810002002d0005001300020025000100d00002007c0012009b0004006c000400900001004e000800a5000300cf00070071000300ad00010014000100110002006900010012000100a300010019000100ab000300ba0001000a000100e7000100320001009e00010038000100a0000100cd0002008b000100ac000200eb0001007b000100d900010054000300070001008c00010000000000'
#select_region_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000002af0000'
#select_city_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000003aff503'
#					'24000000000000000000000000000000df3903000800000000000000000000000000000002040600'#ALGERIA
#					'24000000000000000000000000000000df39030008000000000000000000000000000000020e0600'#AUSTRIA
select_region_rx = b'2b000000000000000000000000000000df390300080000000000000000000000000000000201000600090000000000'
#c80aa946d1920022579b4461080045000073de4440003706111a5fd3e9770a0000dc22add8861dacac0d9b8d4e435018201455fe000047000000000000000000000000000000df390300080000000000000000000000000000000208002e00940030003c0033008a00340050002d00020031001600320001002f00010000000000
select_russia_region_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000002af0600'
select_russia_region_rx = b'ef000000000000000000000000000000df3903000800000000000000000000000000000002320007041500f40301003e051c01fa038b01fd031a00f10314000b042f00f0031a00e5033600f503370002041b0006041000ff031d00e9030500e703120004046500010012000d041200eb031100ed030b0009042a000a040700e2030200f3030e00e3030b00fb031f0005040400e403050008040800ec030a000c040a00f2030900f7030900fe030600fc030600ea0304000e040800ee030800f9030100ef030600e6030400f8030400000404000000000000000000000000000000000000000000000000000000000000000000'
#'0022579b4461c80aa946d192080045000050130440008006937d0a0000dc5fd3e977d88622ad9b8d4ebb1dacadcd50183ef15fa9000024000000000000000000000000000000df3903000800000000000000000000000000000003affa03'
#'c80aa946d1920022579b44610800450000570b7040003706e40a5fd3e9770a0000dc22add8861dacadcd9b8d4ee35018201428e200002b000000000000000000000000000000df39030008000000000000000000000000000000030100a047870100000000'
select_ru_msc_tx = b'2e000000000000000000000000000000df3903000700000000000000000000000000000002affa03a0470000000000000000'
select_fr_frs_tx = b'2e000000000000000000000000000000df3903000700000000000000000000000000000002467301a4060000000000000000'
select_ru_sch_tx = b'2e000000000000000000000000000000df3903000700000000000000000000000000000002aff503b30e0000000000000000'
select_tmp_tx	 = b'2e000000000000000000000000000000df39030007000000000000000000000000000000'

select country 
ask 24000000000000000000000000000000df3903000800000000000000000000000000000001000000
ans 2b020000000000000000000000000000df3903000800000000000000000000000000000001810068003004dd0037051600670236000a024600b9046500d500d800a1014000c500cb00f500af006f05c600110595000503e000a00c4c007f00ce003d028a0074002200fb0263004b00cc00fe007f002d001500230133002b010b00140127006a045000b202d100d30073004400de000e001f0060010f009800a900e702aa0062010e00a3016100a100df002c03e60043017900a501ae0094016a000401350093004d0057035e00690062003e0098004f00a700260067002c016d00af00c000f500450054005f00ec007000280010003500530006001c0032009f005c00bb008b00c1006200e2001000e500470004000900ec000d00370079002e001600c7000200840002007a001f00b900430074000600c40021002c0009000c00340097000200e300140060002d0003000a007200340088004100d70005008d000900a5000400bf001a00640005005d000400a60014008f000e00710007002d000900820018009a0002004e0009003a0001004f0001003c0011008600010025000100d00003007c001200920001001300010090000100a1000600ad0001006c0005001400020011000100cf00060006000200d60003006900010019000100ab000400ba0001000a000100e700010032000100810002002600010038000100cd0002008b00010008000100eb0001009b0003007b000100ff0001005400030023000100070001007d00010000000000
ans[37] = number of countries
8100 - 129 countries
6800 - 104 ITALY
3004 - 1072 proxies


selet region in country
ask 24000000000000000000000000000000df3903000800000000000000000000000000000002af0000
ans ff000000000000000000000000000000df3903000800000000000000000000000000000002360007041100e6030400f40301003e051501fa037c01fd031a00f10312000b043000f0031900f5033a0006040d00ff031900e9030500e7031600e5033300010013000d041400eb031300ed030b0009043300040465000a040700e2030300f3030e00e3030900fe030700ea03050002041900fb03230005040600e403040008040800ec0309000c040900f2030c00f7030a00fc030900ee0308000e040600f9030200ef030500f803030000040400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ans[37] = number of regions

select city in region in country ))
ask 24000000000000000000000000000000df3903000800000000000000000000000000000003aff503
ans 33000000000000000000000000000000df39030008000000000000000000000000000000030300b10e2100a0471500b30e040000000000
ans[37] = number of cities/places
0300 - 3 city
b10e - KRASNODAR
2100 - 33 proxies
a047 - '-'
1500 - 17 proxies
b30e - SOCHI
0400 - 4 proxies



select proxies in city in region in country )))
ask 2e000000000000000000000000000000df3903000700000000000000000000000000000002aff503b30e0000000000000000
ans 86000000000000000000000000000000df3903000700000000000000000000000000000004007d881048f2214220bca28172aff503b30e06170000640e00a3b679f98cdae6e5bca28172aff503b30e06170000630e00c4601132108345c82593d067aff503b30eda000000630e00651e238993798c24bca28172aff503b30efe160000630e0000000000


'e3000000000000000000000000000000df39030008000000000000000000000000000000022f00fb0328003e05ff00040463000d041400fa03600106041100eb031300ec0305000b042500f503350009042e00ff032300ef030600f0031500ee030f00fd031b00e2030200e7031d00e5031e00ed030a00f1031b00e9030200e3030a00070413000504030008040300fe03030001001000e60306000a0407000c040c00f2030500f3030800020411000e040600e4030300f8030200f4030200fc030200f9030300f7030700ea030300000401000000000000000000000000000000000000000000'
#Address =  128.71.174.30 (9052, 40390)
tmp1 = (0, 35, 98, 115, 206, 143, 136, 205, 57, 128, 73, 5, 244, 175, 250, 3, 160, 71, 191, 0, 0, 0, 100, 14)
#Address =  128.73.5.244(8948)
#0 35 98 115 206 143 136 205 57 128 73 5 244 175 250 3 160 71 191 0 0 0 100 14
#Address =  128.70.65.39(7520, 52535)
#0 102 52 10 180 151 209 40 208 128 70 65 39 175 250 3 160 71 100 1 0 0 100 14 
#Address =  176.194.185.104(35852)
#0 118 153 55 9 213 101 222 36 176 194 185 104 175 250 3 160 71 107 2 0 0 99 14 
'''

#auth_tx = b'c2c699c25bb2d1950000000000000000000000000000000000000000030068002cc6ccc2daca3a6f00000000000000000000000000000000000000000000000068f821e2'
auth_tx = b'c223d46ca998c8000000000000000000000000000000000000000000030068002cc6ccc2daca3a6f00000000000000000000000000000000000000000000000012b61299'
select_random_tx = b'2e000000000000000000000000000000df390300070000000000000000000000000000000100000000000000000000000000'
select_region_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000002af0000'
select_city_tx = b'24000000000000000000000000000000df3903000800000000000000000000000000000003aff503'


DEBUG = True

key = b'QlZ1kWj2XhE3gCf4RdV5sTs6BaY7ANS8UDM9FIG0OHP'
def ROR(x, n, bits = 32):
	n = n % bits
	mask = (2**n) - 1
	mask_bits = x & mask
	return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits):
    return ROR(x, bits - n, bits)

def proxy_decrypt(byte_str):
#	print (byte_str)
	res = ''
	for i in range(len(byte_str)):
		v10 = ord(chr(key[(i % len(key))]))
		v9 = ROR(ord(chr(byte_str[i])), v10, 8)
		res += chr(v9)
	return res

def proxy_encrypt(byte_str):
#	print (byte_str)
	res = ''
	for i in range(len(byte_str)):
		v10 = ord(chr(key[(i % len(key))]))
		v9 = ROL(ord(chr(byte_str[i])), v10, 8)
		res += chr(v9)
	return res

def proxy_loginpass(login, password):
#	return login + '\x00' * (29 - len(login)) + '\x40\x0d\00' + password + '\x00' * (32 - len(password))
	return login + '\x00' * (32 - len(login)) + password + '\x00' * (32 - len(password))


def get_ip(address):
	a = int(address[9])
	b = int(address[10])
	c = int(address[11])
	d = int(address[12])
	return (str(a) +'.'+ str(b) +'.'+ str(c) +'.'+ str(d))

def print_all(address):
	s = ''
	for i in range(len(address)):
		s += str(int(address[i])) + ' '
	print (s)

def parse_addresses(string, debug = False or DEBUG):
	hex_string = codecs.decode(string, "hex_codec")
	leng = 24
	size = hex_string[36]
	if debug:
		print ("-----len = ", len(string))
		print ("-----Number of recived addresses = ", size)
	tmp = []
	addresses = []
	for i in range(size):
		tmp.append(hex_string[37 + i*leng : 37 + (i+1)*leng])
	for address in tmp:
		if debug:
			print(get_ip(address))
		addresses.append(get_ip(address))
	return addresses

def parse_countries(string, debug = False or DEBUG):
	hex_string = codecs.decode(string, "hex_codec")
	leng = 4
	size = (hex_string[38] << 8) + hex_string[37]
	if debug:
		print ("-----Number of recived countries = ", size)
		country = proxy_countries()
	res = {}
	for i in range(size):
		country_index = int(hex_string[40 + i*leng] << 8) + int(hex_string[39 + i*leng])
		proxy_count = int(hex_string[42 + i*leng] << 8) + int(hex_string[41 + i*leng])
		res[country_index] = proxy_count
		if debug:
			try:
				cnt = country[country_index - 1]
			except:
				cnt = b'-'
			print(cnt, proxy_count)
	return res

def parse_regions(string, debug = False or DEBUG):
	hex_string = codecs.decode(string, "hex_codec")
	leng = 4
	size = (hex_string[38] << 8) + hex_string[37]
	if debug:
		print ("-----Number of recived regions = ", size)
		region = proxy_regions()
	res = {}
	for i in range(size):
		region_index = int(hex_string[40 + i*leng] << 8) + int(hex_string[39 + i*leng])
		proxy_count = int(hex_string[42 + i*leng] << 8) + int(hex_string[41 + i*leng])
		res[region_index] = proxy_count
		if debug:
			try:
				cnt = region[region_index - 1]
			except:
				cnt = b'-'
			print(cnt, proxy_count)
	return res

def parse_cities(string, debug = False or DEBUG):
	hex_string = codecs.decode(string, "hex_codec")
	leng = 4
	size = (hex_string[38] << 8) + hex_string[37]
	if debug:
		print ("-----Number of recived cities = ", size)
		city = proxy_cities()
	res = {}
	for i in range(size):
		city_index = int(hex_string[40 + i*leng] << 8) + int(hex_string[39 + i*leng])
		proxy_count = int(hex_string[42 + i*leng] << 8) + int(hex_string[41 + i*leng])
		res[city_index] = proxy_count
		if debug:
			try:
				cnt = city[city_index - 1]
			except:
				cnt = b'-'
			print(cnt, proxy_count)
	return res

def proxy_countries():
	t = open('country.txt', "rb").read().split(b'\r\n')
	return t

def proxy_regions():
	t = open('region.txt', "rb").read().split(b'\r\n')
	return t

def proxy_cities():
	t = open('city.txt', "rb").read().split(b'\r\n')
	return t

def get_country(index):
	COUNTRY = proxy_countries()
	try:
		t = COUNTRY[index - 1]
	except:
		t = b'-'
	return t.decode('utf-8')

def get_region(index):
	REGION = proxy_regions()
	try:
		t = REGION[index - 1]
	except:
		t = b'-'
	return t.decode('utf-8')

def get_city(index):
	CITY = proxy_cities()
	try:
		t = CITY[index - 1]
	except:
		t = b'-'
	return t.decode('utf-8')

def get_auth_identity(string):
	if len(string) != 60:
		print("-----Error in recived data after login")
		return -1
	else:
		return (string[4:7])

def proxy_select_country(debug = False or DEBUG):
	sock = socket.socket()
	sock.connect(('95.211.233.119', 8877))
	sock.settimeout(30)
	#auth
	data_send = codecs.decode(auth_tx, "hex_codec")
	sock.send(data_send)
	data_recv = ''
	while (len(data_recv) < 60 ):
		data_recv = sock.recv(60)
	#id
	ident = get_auth_identity(data_recv)
	#request
	select = b'24000000000000000000000000000000'+ binascii.hexlify(bytearray(ident)) + b'000800000000000000000000000000000001000000'
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	#answer
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	time.sleep(3)
	data_recv = sock.recv(10048)
	sock.close()
	return parse_countries(binascii.hexlify(bytearray(data_recv)), debug)

def proxy_select_region(country_code, debug = False or DEBUG):
	sock = socket.socket()
	sock.connect(('95.211.233.119', 8877))
	sock.settimeout(30)
	#auth
	data_send = codecs.decode(auth_tx, "hex_codec")
	sock.send(data_send)
	data_recv = ''
	while (len(data_recv) < 60 ):
		data_recv = sock.recv(60)
	#id
	ident = get_auth_identity(data_recv)
	#request
	select = b'24000000000000000000000000000000'+ binascii.hexlify(bytearray(ident)) + b'000800000000000000000000000000000002' + country_code + b'0000'
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	#answer
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	time.sleep(3)
	data_recv = sock.recv(10048)
	sock.close()
	return parse_regions(binascii.hexlify(bytearray(data_recv)), debug)

def proxy_select_city(country_code, region_code, debug = False or DEBUG):
	sock = socket.socket()
	sock.connect(('95.211.233.119', 8877))
	sock.settimeout(30)
	#auth
	data_send = codecs.decode(auth_tx, "hex_codec")
	sock.send(data_send)
	data_recv = ''
	while (len(data_recv) < 60 ):
		data_recv = sock.recv(60)
	#id
	ident = get_auth_identity(data_recv)
	#request
	select = b'24000000000000000000000000000000'+ binascii.hexlify(bytearray(ident)) + b'000800000000000000000000000000000003' + country_code + region_code
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	#answer
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	time.sleep(3)
	data_recv = sock.recv(10048)
	sock.close()
	return parse_cities(binascii.hexlify(bytearray(data_recv)), debug)

def proxy_select(country_code, region_code, city_code, debug = False or DEBUG):
	sock = socket.socket()
	sock.connect(('95.211.233.119', 8877))
	sock.settimeout(30)
	#auth
	data_send = codecs.decode(auth_tx, "hex_codec")
	sock.send(data_send)
	data_recv = ''
	while (len(data_recv) < 60 ):
		data_recv = sock.recv(60)
	#id
	ident = get_auth_identity(data_recv)
	#request
	select = b'2e000000000000000000000000000000'+ binascii.hexlify(bytearray(ident)) + b'000700000000000000000000000000000002' + country_code + region_code + city_code + b'0000000000000000'
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	#answer
	time.sleep(3)
	data_recv = sock.recv(10048)
	sock.close()
	return parse_addresses(binascii.hexlify(bytearray(data_recv)), debug)

def proxy_select_random():
	sock = socket.socket()
	sock.connect(('95.211.233.119', 8877))
	sock.settimeout(30)
	#auth
	data_send = codecs.decode(auth_tx, "hex_codec")
	sock.send(data_send)
	data_recv = ''
	while (len(data_recv) < 60 ):
		data_recv = sock.recv(60)
	#id
	ident = get_auth_identity(data_recv)
	#request
	select = b'2e000000000000000000000000000000'+ binascii.hexlify(bytearray(ident)) + b'00070000000000000000000000000000000100000000000000000000000000'
	data_send = codecs.decode(select, "hex_codec")
	sock.send(data_send)
	#answer
	data_recv = sock.recv(2048)
	sock.close()
	return parse_addresses(binascii.hexlify(bytearray(data_recv)))


RUSSIA = b'af'
UNITED_STATES = b'e0'
BASHKORTOSTAN = b'e503'
UFA = b'9e0e'

#print (get_country(123123))

countries = proxy_select_country()
for country_code in countries:
	f = open('proxy.dump', 'a+')
	try:
		tmp0= '{num:02x}'.format(num = country_code)
		regions = proxy_select_region(str.encode(tmp0))
	except:
		print("Error in countries\n")
	for region_code in regions:
		try:
			tmp = '{num:04x}'.format(num = region_code)
			tmp1 = tmp[2:] + tmp[:2]
			print (tmp1)
			cities = proxy_select_city(str.encode(tmp0), str.encode(tmp1))
		except:
			print("Error in regions\n")
		for city_code in cities:
			try:
				tmp = '{num:04x}'.format(num = city_code)
				tmp2 = tmp[2:] + tmp[:2]
				proxies = proxy_select(str.encode(tmp0), str.encode(tmp1), str.encode(tmp2))
				place = '\n' + get_country(country_code) +'/' + get_region(region_code) + '/'+ get_city(city_code) +'\n'+ '----------'+'\n'
				f.write(place)
			except:
				f.write("Error in cities\n")
			for proxy in proxies:
				try:
					f.write(proxy+'\n')
				except:
					f.write("Error in proxies\n")
	f.close()


#proxy_select_region(UNITED_STATES, True)
#proxy_select_city(RUSSIA, BASHKORTOSTAN, True)
#proxy_select(RUSSIA, BASHKORTOSTAN, UFA)
#proxy_select(RUSSIA, b'fa03', b'a047', True)

#proxy_select_random()
'''
lp = proxy_loginpass('alfakete', 'alfaketo')
lp = lp.encode('utf-8')
hashed = proxy_decrypt(binascii.hexlify(bytearray(lp)))
pprint.pprint(hashed)
'''

