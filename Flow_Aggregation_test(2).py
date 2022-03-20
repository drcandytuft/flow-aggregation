import dpkt
import time
import sys
import configparser
import binascii
import socket
from Flow import Flow
from dpkt.compat import compat_ord


def get_IP_packet(pkt):
    """
    从数据包中读取IP数据包
    :param pkt:所有数据包
    :return:ip数据包
    """
    # pkt：全部数据
    eth = dpkt.ethernet.Ethernet(pkt)
    # 确保以太网帧包含一个IP包
    if eth.type == dpkt.ethernet.ETH_TYPE_IP6:  # 对ipv6进行判断
        if not isinstance(eth.data, dpkt.ip6.IP6):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
    else:
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
    #  ip数据包
    ip_packet = eth.data
    """
    此处可输出ip地址等 需要特定函数转化格式：输出形如：192.168.137.227
    """
    return ip_packet


def pcap_read(pcap_file):
    """
    对文件中所有数据包进行读取，分类
    :param pcap_file:数据包文件
    :return:时间邮戳和所有数据包
    """
    pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))
    pkt_list = pcap.readpkts()
    pkt_result = []
    tms_result = []
    for (ts, pkt) in pkt_list:
        try:

            ip_packet = get_IP_packet(pkt)
            trans_packet = ip_packet.data  # 传输层的数据
            data = trans_packet.data  # 应用层数据
            pkt_result.append(pkt)
            tms_result.append(ts)
        except Exception as e:
            print(e)
            continue
    return tms_result, pkt_result


def flow_combine(ip_pkt_list, ip_tms_list, flow_definition):
    """
    组流
    :param ip_pkt_list:ip数据包
    :param ip_tms_list:时间邮戳包
    :param flow_definition:单双流标识
    :return:组流后的流
    """
    flow_list = []
    src_port = None
    dst_port = None
    trans_layer_proto = None
    for (pkt_stream, tms) in zip(ip_pkt_list, ip_tms_list):
        eth = dpkt.ethernet.Ethernet(pkt_stream)
        pkt = eth.data
        src_ip = pkt.src
        dst_ip = pkt.dst
        if pkt.p == dpkt.ip.IP_PROTO_TCP:  # TCP数据包
            tcp_packet = pkt.tcp
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport
            trans_layer_proto = dpkt.ip.IP_PROTO_TCP
        elif pkt.p == dpkt.ip.IP_PROTO_UDP:  # UDP数据包
            udp_packet = pkt.udp
            src_port = udp_packet.sport
            dst_port = udp_packet.dport
            trans_layer_proto = dpkt.ip.IP_PROTO_UDP
        if len(flow_list) == 0:  # 初次
            flow = Flow(src_ip, dst_ip, src_port, dst_port, trans_layer_proto, eth, tms)
            flow_list.append(flow)
        else:
            flow_is_exist = False
            if flow_definition == 1:  # 单向流
                for flow_unit in flow_list:
                    """
                    判断是否同流
                    """
                    if flow_unit.src_ip == src_ip and flow_unit.dst_ip == dst_ip and flow_unit.src_port == src_port and flow_unit.dst_port == dst_port:
                        flow_is_exist = True
                        flow_unit.append_packet(eth, tms)
                        break
            elif flow_definition == 2:  # 双向流
                for flow_unit in flow_list:
                    if ((
                                flow_unit.src_ip == src_ip and flow_unit.dst_ip == dst_ip and flow_unit.src_port == src_port and flow_unit.dst_port == dst_port) or (
                                flow_unit.src_ip == dst_ip and flow_unit.dst_ip == src_ip and flow_unit.src_port == dst_port and flow_unit.dst_port == src_port)) and flow_unit.trans_layer_proto == trans_layer_proto:
                        flow_is_exist = True
                        flow_unit.append_packet(eth, tms)
                        break
            if not flow_is_exist:
                """
                插入新流
                """
                flow = Flow(src_ip, dst_ip, src_port, dst_port, trans_layer_proto, eth, tms)
                flow.append_packet(eth, tms)
                flow_list.append(flow)

    return flow_list


def print_flow(flow_list, f):
    """
    输出流总数与流信息到文件中
    :param flow_list:组流后的流
    """
    print('Number of flows: ' + str(len(flow_list)), file=f)
    for flowUnit in flow_list:
        print(flowUnit, file=f)


def check():
    """
    -h : 获取帮助
    -b : 对单向流组流
    -u : 对双向流组流
    :return:
    """
    if len(sys.argv) == 2:
        if sys.argv[1] == '-h':
            doc()
            mod = 0
        elif sys.argv[1] == '-u':
            mod = 1
        elif sys.argv[1] == '-b':
            mod = 2
        else:
            doc()
        return mod
    else:
        print("Use \'-h\' for more help")
        mod = 0
        return mod


def doc():
    str_doc = """
    The program is coded in python 3.8.3 with dpkt.
    To execute the program,use the following command:
    python Flow_Aggregation_test.py [-h] OPTION
    OPTION:
        -u unidirectional flow aggregation
        -b bidirectional flow aggregation
    """
    print(str_doc)


if __name__ == "__main__":
    mod = check()
    if mod != 1 and mod != 2:
        sys.exit(0)

    time_start = time.time()
    config = configparser.ConfigParser()  # 创建一个对象，使用对象的方法对指定的配置文件做增删改查操作。
    config.read('./edconfig.ini', encoding='utf-8')
    pcap_name_list = config.options('source')
    # 双向流在uni_log文件夹中查找，单向流在bi_log文件夹中查找
    if mod == 1:
        folder = 'uni_log'
    else:
        folder = 'bi_log'
    try:
        for pcap_key in pcap_name_list:
            pcap_name = config.get('source', str(pcap_key))
            log = open('.//' + folder + '//' + pcap_name + '.log', 'w')
            tms_list, pkt_list = pcap_read('.//pcap//' + pcap_name)
            flow = flow_combine(pkt_list, tms_list, mod)
            print_flow(flow, log)
            log.close()

    except Exception as e:
        print('[INFO]配置文件错误:{}'.format(e))
        sys.exit(0)
