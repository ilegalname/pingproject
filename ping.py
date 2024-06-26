# encoding:utf-8
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
# def checksum_six(msg):
#     s = 0
#     for i in range(0, len(msg), 2):
#         w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
#         s = ((s+w) & 0xffff) + ((s+w) >> 16)
#     return ~s & 0xffff

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

def chose_ipv6(host):
    addr_info_list = socket.getaddrinfo(host, None, socket.AF_INET6)


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
        #host_addr = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
        #addr_info_list = socket.getaddrinfo(host, None, socket.AF_INET6)
        #print(addr_info_list)
        #print(host_addr)
        #host_addr = "2408:8409:2482:5255:9831:b5e4:d7c1:8d20"
        #host_addr = "2408:8409:2482:5255:9910:1ac:14a3:61cf"
        #rawsocket.bind((host_addr, 0))
        # print
        i = 0
        addr_info_list = socket.getaddrinfo(host, None, socket.AF_INET6)
        #le= len(addr_info_list)
        for addr in addr_info_list:
            #host_addr = socket.getaddrinfo(host, None, socket.AF_INET6)[i][4][0]
            host_addr = addr[4][0]
            #print(i)
            print(host_addr)
            try:
                #udp_server_sock.bind(0)
                rawsocket.bind((host_addr, len(host_addr)))
                sendt=rawsocket.sendto(icmp_packet, (dst_addr, 0,0,0))
            except Exception as e:
                i = i + 1
                print(e)
                continue
            if(sendt>0):
                break
    else:
        host_addr = socket.gethostbyname(host)
        rawsocket.bind((host_addr,0))
        rawsocket.sendto(icmp_packet, (dst_addr, 80))
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
        rep=received_packet[0:1]
        re=struct.unpack("B",rep)
        # print(re)
        #print(type(re))
        #print(hex(re))
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

def resolve_ipv6_dns(host):
    try:
        result = dns.resolver.resolve(host, 'AAAA')
        for ipv6 in result:
            return str(ipv6)
    except Exception as e:
        print(f"Error resolving {host}: {e}")
        return None

def ping(dstn,n=4,q=0,ti=0.7,host="",route=0,timetolive=128,lenth=56,sample='',ipv=4):
    send, accept, lost = 0, 0, 0
    sumtime, shorttime, longtime, avgtime = 0, 1000, 0, 0
    # TODO icmp数据包的构建
    if(ipv==4):
        data_type = 8  # ICMP Echo Request
        data_code = 0  # must be zero
        data_checksum = 0  # "...with value 0 substituted for this field..."
        data_ID = 0  # Identifier
        data_Sequence = 1  # Sequence number
    else:   #构建ipv6报文
        data_type = 128  # ICMP Echo Request
        data_code = 0  # must be zero
        data_checksum = 0  # "...with value 0 substituted for this field..."
        data_ID = 1  # Identifier
        data_Sequence = 1  # Sequence number
    if(sample!=''):
        nums=lenth//len(sample)
        databody = sample * nums
        payload_body = b'{databody}'
    #print(payload_body)
    else:
        payload_body = b'abcdefghijklmnopqrstuvwabcdefghi'  # data
    # 将主机名转ipv4地址格式，返回以ipv4地址格式的字符串，如果主机名称是ipv4地址，则它将保持不变\
    if(ipv==4):
        dst_addr = socket.gethostbyname(dstn)
    else:
        #dst_ad = socket.gethostbyname(dstn)
        #dst_addr = ipaddress.IPv6Address('::ffff:' + dst_ad)
        #addr_info = socket.getaddrinfo(dstn, None, socket.AF_INET6)[0]
        #dst_addr = addr_info[4][0]
        dst_addr=resolve_ipv6_dns(dstn)
    print("正在 Ping {0} [{1}] 具有 {2} 字节的数据:".format(dstn, dst_addr, lenth))
    # reach=TraceRouteTTL(route,dstn,timetolive)
    for i in range(0, n):
        # if(reach==0):
        #     print("can't reach, TTL is too small")
        #     return 0
        send = i + 1
        # 请求ping数据包的二进制转换
        icmp_packet = request_ping(data_type, data_code, data_checksum, data_ID, data_Sequence + i, payload_body, lenth, ipv)
        # 连接套接字,并将数据发送到套接字
        send_request_ping_time, rawsocket, addr = raw_socket(dst_addr, icmp_packet,host,ipv)
        # 数据包传输时间
        #print("ipv={0}".format(ipv))
        times = reply_ping(send_request_ping_time, rawsocket, data_Sequence + i,ipv)
        if times > 0:
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
            print("请求超时。")

        if send == n:
            print("{0}的Ping统计信息:".format(dst_addr))
            print(
                "\t数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                    i + 1, accept, i + 1 - accept, (i + 1 - accept) / (i + 1) * 100, shorttime, longtime,
                    sumtime / send))

if __name__ == "__main__":
    #i = input("请输入要ping的主机或域名\n")
    parser = argparse.ArgumentParser(description='test')
    parser.add_argument('-ip', type=str, help='输入想ping的ip地址，如果有多个，用‘/’分割')
    parser.add_argument('-c', type=int, default=4, help='输入想ping的次数')
    parser.add_argument('-q', type=int, default=0, help='输入1只显示最后结果')
    parser.add_argument('-i', type=int, default=0, help='输入想间隔的秒数') 
    parser.add_argument('-I', type=str, default='', help='输入发送端ip')
    parser.add_argument('-r', type=int, default=0, help='输入1追踪路径')
    parser.add_argument('-t', type=int, default=128, help='设置ttl存活数量')
    parser.add_argument('-s', type=int, default=56, help='设置想发送的数据包大小')
    parser.add_argument('-p', type=str, default='', help='设置想发送的范本样式')
    parser.add_argument('-ipv', type=int, default=4, help='输入4使用Ipv4，输入6使用Ipv6')


    args = parser.parse_args()
    String = args.ip
    ips=String.split('/')
    for ip in ips:
        ping(ip,args.c,args.q,args.i,args.I,args.r,args.t,args.s,args.p,args.ipv)
        print("\n")