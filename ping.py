# encoding:utf-8
import concurrent.futures.thread
import ipaddress
import time
import struct
import socket
import select
import argparse
from random import randint
from scapy.all import *
import array
import dns.resolver
import itertools
import sys
import telnetlib
# import thread
from concurrent.futures import ThreadPoolExecutor

def chesksum(data):
    n = len(data)
    m = n % 2
    sum = 0
    for i in range(0, n - m, 2):
        sum += (data[i]) + ((data[i + 1]) << 8)  # 传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    if m:
        sum += (data[-1])
    # 将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)  # 如果还有高于16位，将继续与低16位相加
    answer = ~sum & 0xffff
    #  主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def checksum_six(data):
    """计算校验和"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(array.array("H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def request_ping(data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body,lenth,ipv):
    #  把字节打包成二进制数据
    if(ipv==4):
        format_string=f'>BBHHH{lenth}s'
        icmp_packet = struct.pack(format_string, data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body)
        icmp_chesksum = chesksum(icmp_packet)  # 获取校验和
        icmp_packet = struct.pack(format_string, data_type, data_code, icmp_chesksum, data_ID, data_Sequence, payload_body)
    else:
        format_string=f'>BBHLL{lenth}s'
        icmp_packet = struct.pack(format_string, data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body)
        icmp_chesksum = checksum_six(icmp_packet)
        icmp_packet = struct.pack(format_string, data_type, data_code, icmp_chesksum, data_ID, data_Sequence, payload_body)
    #  把校验和传入，再次打包
    return icmp_packet

def chose_ipv6(host,rawsocket,icmp_packet,dst_addr):
    addr_info_list = socket.getaddrinfo(host, None, socket.AF_INET6)
    host_addr_list = list()
    for addr in addr_info_list:
        host_addr_list.append(addr[4][0])
    random.shuffle(host_addr_list)
    #print(host_addr_list)

    for addr in host_addr_list:
        try:
            # udp_server_sock.bind(0)
            host_addr = addr
            rawsocket.bind(host_addr)
        except Exception as a:
            #print("ERROR1:",a)
            print(" ")
        try:
            sendt = rawsocket.sendto(icmp_packet, (dst_addr, 0))
            if (sendt > 0):
                #print(sendt)
                #print("break")
                return
        except Exception as b:
            print("ERROR2:",b)

def raw_socket(dst_addr, icmp_packet,host,n=4):
    '''
       连接套接字,并将数据发送到套接字
    '''
    # 实例化一个socket对象，ipv4，原套接字，分配协议端口
    if(n==6):
        rawsocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    else:
        rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    #rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    # 记录当前请求时间
    send_request_ping_time = time.time()
    # 发送数据到网络
    if(n==6):
        chose_ipv6(host, rawsocket, icmp_packet, dst_addr)
    else:
        host_addr = socket.gethostbyname(host)
        #rawsocket.bind(("192.168.221.1",0))
        sendt=rawsocket.sendto(icmp_packet, (dst_addr, 80))
    # 返回数据
    return send_request_ping_time, rawsocket, dst_addr


def reply_ping(send_request_ping_time, rawsocket, data_Sequence, ipv, timeout=2):
    while True:
        # 开始时间
        started_select = time.time()
        # 实例化select对象，可读rawsocket，可写为空，可执行为空，超时时间
        what_ready = select.select([rawsocket], [], [], timeout)
        # 等待时间
        wait_for_time = (time.time() - started_select)
        # 没有返回可读的内容，判断超时
        if what_ready[0] == []:  # Timeout
            return -1
        # 记录接收时间
        time_received = time.time()
        # 设置接收的包的字节为1024
        received_packet, addr = rawsocket.recvfrom(1024)
        print()

        if(ipv==6):
            # print("here")
            icmpv6Header = received_packet[0:12]
            # 反转编码
            re_type, code, checksum, packet_id, sequence = struct.unpack(">BBHLL", icmpv6Header)
            # print(re_type)
            if re_type == 129 and sequence == data_Sequence:
                return time_received - send_request_ping_time
        else:
            # print("here!!")
            icmpHeader = received_packet[20:28]
            # 反转编码
            re_type, code, checksum, packet_id, sequence = struct.unpack(">BBHHH", icmpHeader)
            if re_type == 0 and sequence == data_Sequence:
                return time_received - send_request_ping_time
        # 数据包的超时时间判断
        timeout = timeout - wait_for_time
        if timeout <= 0:
            return -1


def dealtime(dst_addr, sumtime, shorttime, longtime, accept, i, time):
    sumtime += time
    print(sumtime)
    if i == 4:
        print("{0}的Ping统计信息：".format(dst_addr))
        print(
            "数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                i + 1, accept, i + 1 - accept, (i + 1 - accept) / (i + 1) * 100, shorttime, longtime, sumtime))


def TraceRouteTTL(r,dstn,timetolive=128):
    i=1
    for item in range(1, timetolive+1):
        dst_addr = socket.gethostbyname(dstn)
        RandomID = randint(1, 65534)
        packet = IP(dst=dst_addr, ttl=item, id=RandomID) / ICMP(id=RandomID, seq=RandomID)
        respon = sr1(packet, timeout=3, verbose=0)
        if respon != None:
            ip_src = str(respon[IP].src)
            if ip_src != dst_addr:
                if(r==1):
                    print(i,". {}".format(str(respon[IP].src)))
                    i=i+1
            else:
                if(r==1):
                    print(i,". {} 已到达".format(str(respon[IP].src)))
                    return 1
        else:
            if(r==1):
                print(i,". TimeOut")
                i=i+1
        #time.sleep(1)
    if(ip_src!=dst_addr):
        return 0

def ttl_restrict(dstn,timetolive):
    dst_addr = socket.gethostbyname(dstn)
    RandomID = randint(1, 65534)
    packet = IP(dst=dst_addr, ttl=timetolive, id=RandomID) / ICMP(id=RandomID, seq=RandomID)
    respon = sr1(packet, timeout=3, verbose=0)
    if respon != None:
        ip_src = str(respon[IP].src)
        if ip_src == dst_addr:
            return 1;
    else:
        return 0

def resolve_ipv6_dns(host):
    try:
        result = dns.resolver.resolve(host, 'AAAA')
        for ipv6 in result:
            return str(ipv6)
    except Exception as e:
        print(f"Error resolving {host}: {e}")
        return None


def ping_net(net_addr,host_addr,numb):
    nets = net_addr.split('.')
    net_a = ''
    for net in nets:
        net = int(net)
        net_b = '{:08b}'.format(net)
        net_a += net_b  #net_a为二进制网络号
    pos = net_a.rfind('1')
    num = 32-int(pos)-1    #有多少位为0
    #s = list(itertools.product(range(2), repeat=num))
    s = list(itertools.product(range(2), repeat=32-int(numb)))
    # print(s)  #主机号
    net_c = net_a[:-(32-int(numb))]
    # print(net_a)
    # print(net_c)
    params_2=[net_c + ''.join(map(str, i)) for i in s]
    # print(params_2)
    params=[str(int(i[0:8], 2)) + '.' + str(int(i[8:16], 2)) + '.' + str(int(i[16:24], 2)) + '.' + str(int(i[24:32], 2)) for i in params_2]
    # print(params)
    # print(param)
    # for i in params:
    #     l=
    t=[[1,0,0.7,host_addr,0,128,1,56,'',4]]*len(params)
    t1 = [1]*len(params)
    t2 = [1] * len(params)
    t3 = [0.7] * len(params)
    t4 = [host_addr] * len(params)
    t5 = [0] * len(params)
    t6 = [128] * len(params)
    t7 = [1] * len(params)
    t8 = [56] * len(params)
    t9 = [''] * len(params)
    t10 = [4] * len(params)

    # print(t)
    params3=[params,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10]
    #print(params3)

    # p=[[i]+t[:] for i in params]
    #print(p)

    count = pow(2,32-int(numb))
    cnt = 0
    # for small in s:
    #     # ss1 = ''.join(map(str, small))
    #     # nnet = net_c + ss1     #获取子网ip
    #     # sub_ip = str(int(nnet[0:8], 2)) + '.' + str(int(nnet[8:16], 2)) + '.' + str(int(nnet[16:24], 2)) + '.' + str(int(nnet[24:32], 2))
    # executor = concurrent.futures.thread.ThreadPoolExecutor(max_workers=100)
    # result =

    with ThreadPoolExecutor(max_workers=100) as t:
        results = t.map(ping, *params3)
    #     #ping_num=ping(sub_ip,1,0,0.7,host_addr,0,128,1,56,'',4)
    #     print(f"task1: {task1.done()}")
    # ping_num = task1.re
        # sult()
        for i in results:
            # print(i)
            if(i == 23):
                cnt += 1
    #     else:
    #         cnt=cnt
    print("在当前网络号{0}中，共有{1}个子网,其中有{2}个可以ping通".format(net_addr,count,cnt))


def telnet(host, port):
    """
    测试端口号通不通
    :return:
    """
    try:
        #  timeout单位s
        telnetlib.Telnet(host=host, port=port, timeout=2)
        print(f"{port}  端口开放")
    except:
        print(f"{port}  端口未开放")
        # 或什么都不打印
        # pass


def for_port(dst_ip, port):
    """
    添加端口到列表中
    使用示例: python3 telnet_for.py 39.105.137.91 81 82 83 84
    :return:
    """
    dst_addr = socket.gethostbyname(dst_ip)

    port_list = port
    if not len(port_list):
        port_list = [20, 21, 22, 53, 80, 8080, 443, 8443, 8888, 3306, 3389]
    for port in port_list:
        telnet(dst_addr, port)

def tr_ping(data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body, lenth,
                               ipv,tr,dst_addr,host):
    icmp_packet = request_ping(data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body, lenth,
                               ipv)
    if (tr == 1):
        print("正在构建数据包")
    # 连接套接字,并将数据发送到套接字
    send_request_ping_time, rawsocket, addr = raw_socket(dst_addr, icmp_packet, host, ipv)
    if (tr == 1):
        print("正在创建套接字")
        print("正在将协议发到网上")
        print("正在接收数据包")
    # 数据包传输时间
    # print("ipv={0}".format(ipv))
    times = reply_ping(send_request_ping_time, rawsocket, data_Sequence, ipv)
    return times,addr

def muli_ping(number,dstn,n=4,q=0,ti=0.7,host="",route=0,timetolive=128,ifnet=0,lenth=56,sample='',ipv=4,tr=0):
    ping(dstn,n=4,q=0,ti=0.7,host="",route=0,timetolive=128,ifnet=0,lenth=56,sample='',ipv=4,tr=0)

def ping(dstn,n=4,q=0,ti=0.7,host="",route=0,timetolive=128,ifnet=0,lenth=56,sample='',ipv=4,tr=0):
    send, accept, lost = 0, 0, 0
    sumtime, shorttime, longtime, avgtime = 0, 1000, 0, 0
    # TODO icmp数据包的构建
    if(ipv==4):
        data_type = 8  # ICMP Echo Request
        data_code = 0  # must be zero
        data_checksum = 0  # "...with value 0 substituted for this field..."
        data_ID = 0  # Identifier
        data_Sequence = 1  # Sequence number
        if(tr==1):
            print("正在构建icmp包头")
    else:   #构建ipv6报文
        data_type = 128  # ICMP Echo Request
        data_code = 0  # must be zero
        data_checksum = 0  # "...with value 0 substituted for this field..."
        data_ID = 1  # Identifier
        data_Sequence = 1  # Sequence number
        if (tr == 1):
            print("正在构建icmpv6包头")
    if sample!='':
        nums=lenth//len(sample)
        databody = sample * nums
        #payload_body = b'{databody}'
        payload_body = bytes(databody,encoding="utf8")
    else:
        payload_body = b'abcdefghijklmnopqrstuvwabcdefghi'  # data
    # 将主机名转ipv4地址格式，返回以ipv4地址格式的字符串，如果主机名称是ipv4地址，则它将保持不变\
    if ipv==4:
        if(ifnet==1):
            dst_addr=dstn
        else:
            dst_addr = socket.gethostbyname(dstn)
            if (tr == 1):
                print("正在解析地址")
    else:
        dst_addr=resolve_ipv6_dns(dstn)
        if (tr == 1):
            print("正在解析地址")
    if ifnet==0:
        print("正在 Ping {0} [{1}] 具有 {2} 字节的数据:".format(dstn, dst_addr, lenth))
    if route==1:
        TraceRouteTTL(route,dstn,timetolive)
    numm = 0
    reach = ttl_restrict(dstn,timetolive);
    #print(n)
    for i in range(0, n):
        if(timetolive!=128):
            if(reach==0):
                 print("can't reach, TTL is too small")
                 return 0
        send = i + 1
        # 请求ping数据包的二进制转换
        times,addr = tr_ping(data_type, data_code, data_checksum, data_ID, data_Sequence+i, payload_body, lenth,
                ipv, tr, dst_addr, host)
        if times > 0:
            if ifnet == 1:
                print(dst_addr," online")
                numm=23
            if q == 0:
                print("来自 {0} 的回复: 字节={1} 时间={2}ms".format(addr,lenth,int(times * 1000)))
            accept += 1
            return_time = int(times * 1000)
            sumtime += return_time
            if return_time > longtime:
                longtime = return_time
            if return_time < shorttime:
                shorttime = return_time
            time.sleep(ti)
        else:
            lost += 1
            if(ifnet == 0):
                print("请求超时。")
            elif ifnet==1:
                print(dst_addr, "offline")
        if send == n and ifnet != 1:
            print("{0}的Ping统计信息:".format(dst_addr))
            print(
                "\t数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                    i + 1, accept, i + 1 - accept, (i + 1 - accept) / (i + 1) * 100, shorttime, longtime,
                    sumtime / send))
    return numm

if __name__ == "__main__":
    #i = input("请输入要ping的主机或域名\n")
    parser = argparse.ArgumentParser(description='test')
    parser.add_argument('-ip', type=str, help='输入想ping的ip地址，如果有多个，用‘/’分割')
    parser.add_argument('-net', type=str, default='', help='输入网络号‘/’掩码位数，对其所有ip进行检查')
    parser.add_argument('-c', type=int, default=4, help='输入想ping的次数')
    parser.add_argument('-q', type=int, default=0, help='输入1只显示最后结果')
    parser.add_argument('-i', type=int, default=0, help='输入想间隔的秒数') 
    parser.add_argument('-I', type=str, default='', help='输入发送端ip')
    parser.add_argument('-r', type=int, default=0, help='输入1追踪路径')
    parser.add_argument('-t', type=int, default=128, help='设置ttl存活数量')
    parser.add_argument('-s', type=int, default=56, help='设置想发送的数据包大小')
    parser.add_argument('-p', type=str, default='', help='设置想发送的范本样式')
    parser.add_argument('-ipv', type=int, default=4, help='输入4使用Ipv4，输入6使用Ipv6')
    parser.add_argument('-tr', type=int, default=0, help='输入1显示具体操作步骤')
    parser.add_argument("-test_port", type=str, default='', help="输入想检查端口号的ip地址,若有想检查的端口号，用“”括起来，例如“www.baidu.com 10 23 8000”")

    args = parser.parse_args()

    if(args.net!=''):
        ips = args.net.split('/')
        net = ips[0]
        numb = ips[1]
        ping_net(net,args.I,numb)
    elif(args.test_port!=''):
        netport = args.test_port.split(' ')
        ip_ad = netport[0]
        del netport[0]
        for_port(ip_ad, netport)
    else:
        String = args.ip
        ips=String.split('/')
        for ip in ips:
            ping(ip,args.c,args.q,args.i,args.I,args.r,args.t,0,args.s,args.p,args.ipv,args.tr)
            print("\n")