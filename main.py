import re
import csv
import sqlite3

p = re.compile(
    r'^(?P<timestamp>[\d:.]+) IP \(.*, id (?P<id>\d+), offset (?P<offset>\d+), flags \[(?P<ip_flags>.*)\], proto (?P<proto>\w+) .*?, length (?P<ip_length>\d+).*\)$'
    r'(\s*^\s*(?P<src_ip>\d+.\d+.\d+.\d+).(?P<src_port>\d+) > (?P<dst_ip>\d+.\d+.\d+.\d+).(?P<dst_port>\d+):( Flags \[(?P<tcp_flags>[^,]+)\])?(, cksum [^,]+)?(, seq (?P<seqno>\d+:\d+))?(, ack (?P<ackno>\d+))?.*$)?',
    re.M)

# tcpdump -nnv ip >> tcpdump.out
with open('tcpdump.out') as f:
    s = f.read()
    s = list(p.finditer(s))

with open('tcpdump.out.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, p.groupindex.keys())
    writer.writeheader()
    for m in s:
        writer.writerow(m.groupdict())

with sqlite3.connect(':memory:') as con:
    con.execute(f'''CREATE TABLE tcpdumpout
                    ({','.join([x+' TEXT NULL' for x in p.groupindex.keys()])})
                ''')
    for m in s:
        con.execute(f'''INSERT INTO tcpdumpout VALUES
                        ({','.join(['"'+x+'"' if x else 'NULL' for x in m.groupdict().values()])})
                    ''')

    # IP分组携带不同协议的分组数
    res1_packet = con.execute(r'''SELECT proto, COUNT(proto)
                                  FROM tcpdumpout
                                  GROUP BY proto
                              ''').fetchall()
    # IP分组携带不同协议的总数据量
    res1_len = con.execute(r'''SELECT proto, SUM(ip_length)
                              FROM tcpdumpout
                              GROUP BY proto
                           ''').fetchall()

    # 多少IP分组是片段
    res2_frag = con.execute(r'''SELECT COUNT(*)
                                FROM tcpdumpout
                                WHERE ip_flags=="+"
                            ''').fetchall()
    # 多少IP数据报被分片
    res2_packet = con.execute(r'''SELECT COUNT(DISTINCT id)
                                  FROM tcpdumpout
                                  WHERE ip_flags=="+"
                              ''').fetchall()
    # 载荷为TCP有多少比例的IP数据报被分片
    res2_packet_tcp = con.execute(r'''SELECT COUNT(DISTINCT id)
                                      FROM tcpdumpout
                                      WHERE ip_flags=="+" AND proto=="TCP"
                                  ''').fetchall()
    # 载荷为UDP有多少比例的IP数据报被分片
    res2_packet_udp = con.execute(r'''SELECT COUNT(DISTINCT id)
                                      FROM tcpdumpout
                                      WHERE ip_flags=="+" AND proto=="UDP"
                                  ''').fetchall()

    # IP数据报长度的累积分布
    res3_ip = con.execute(r'''SELECT SUM(ip_length)
                              FROM tcpdumpout
                              GROUP BY id
                              ORDER BY SUM(ip_length)
                          ''').fetchall()
    # TCP数据报长度的累积分布
    res3_tcp = con.execute(r'''SELECT SUM(ip_length)
                               FROM tcpdumpout
                               WHERE proto=="TCP"
                               GROUP BY id
                               ORDER BY SUM(ip_length)
                           ''').fetchall()
    # UDP数据报长度的累积分布
    res3_udp = con.execute(r'''SELECT SUM(ip_length)
                               FROM tcpdumpout
                               WHERE proto=="UDP"
                               GROUP BY id
                               ORDER BY SUM(ip_length)
                           ''').fetchall()
