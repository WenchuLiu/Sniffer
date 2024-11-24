import psutil
import netifaces as nif


def get_all_interfaces():
    d = psutil.net_if_stats()
    #print(d)
    d2 = psutil.net_if_addrs()
    #print(d2.keys())
    r = []
    m = []
    for i in d2.keys():
        # select NIFs whose "isup" attribute equals TRUE and save as list of tuples [(name,macaddress),...]
        print(i)
        print(d2[i][0].address.lower().replace("-", ":"))

        if "Loopback" not in i and d[i][0]:
            print(i, d2[i][0].address)
            #chosen_mac = d2[i][0].address.lower().replace("-", ":")
            #print("chosen_mac", chosen_mac)
            r.append(i)
            m.append(d2[i][0].address.lower().replace("-", ":"))

    return r,m


def mac_for_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except : #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return "mafeeeeesh"


def my_hexdump( src, length=16, sep='.' ):
    result = []
    for i in range(0, len(src), length):
        subSrc = src[i:i+length]
        hexa = ''
        isMiddle = False
        for h in range(0,len(subSrc)):
            if h == length/2:
                hexa += ' '
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace('0x','')
            if len(h) == 1:
                h = '0'+h
            hexa += h+' '
        hexa = hexa.strip(' ')
        text = ''
        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep
        result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))

    return '\n'.join(result)


def my_hexdump2(x):
   r_l= []
   x=str(x)
   l = len(x)
   i = 0
   while i < l:
       #print ("%04x  " % i)
       r_l.append("%04x  " % i)
       for j in range(16):
           if i+j < l:
               #print ("%02X" % ord(x[i+j]))
               r_l.append("%02X" % ord(x[i+j]))
           else:
               #print ("  ")
               r_l.append("  ")

           if j%16 == 7:
               pass
       #print (" ")
       r_l.append(" ")
       #print (x[i:i+16])
       r_l.append(x[i:i+16])
       i += 16
       r_l.append("\n")
   return " ".join(r_l)



