#!/usr/bin/python
import json
import sys
import math
import re
import thread
from time import sleep,time,mktime,asctime

g = dict()
blacklist = []
PARSER = re.compile('(\s{2}|\d*\s*\d{1,2}:\d{2}:\d{2})\s*(\d+)\s*([^\t]*)\s*(.*)')

#Not perfect, many problems
Table_Filter = re.compile('(?i)(?<=into|from|join)\s+(\w+)(,\s*(\w+))?(?:(\s*\w+,\s*(\w+))+)?')

threshold = 1

expire_sec = 600
refresh_time = 60
#last timespan of parse
last_parse_time = 0
#last timespan of analyze
last_refresh_time = 0
Lock = thread.allocate_lock()

def gettime(t):
    d,s = t.split()
    s = map(int,s.split(':'))

    return mktime((int(d[0:2]),int(d[2:4]),int(d[4:6]),s[0],s[1],s[2],0,0,0))

def log_parser(lines,records):
    global last_parse_time,expire_sec
    for line in lines:
        line = PARSER.search(line)
        if not line:
            continue
        line = list(line.groups())
        if line[0].isspace():
            line[0] = last_parse_time
        else:
            line[0] = gettime(line[0])
        last_parse_time = line[0]

        if time()-line[0] <= expire_sec:
            records.append(line)
def Warn(info,level):
    f = open('warning','a')
    #f.write('{info:\'%s\' , level:%s}\n'%(info.strip(),level))
    f.write(json.dumps({'info':info.strip(),'level':level,'time':asctime()}))
    f.write('\n')
    f.close()

#Mainly avoid injection. With blacklist
def weird_test(lines):
    global blacklist
    #Black list of injection like operation
    for bl,al,wn in blacklist:
        for line in lines:
            line = line[3]
            if bl.search(line):
                Warn(wn,al)
                break
        
        '''DOESN'T WORK WELL
        #Many Upper & Many Lower
        countUpper = len(re.findall('[A-Z]',line))
        countLower = len(re.findall('[a-z]',line))
        if abs(countUpper-countLower) < len(line)/3.0:
            Warn('Potential attempt to bypass filter with weird letter case',3)
            '''

def f(t):
    theta = 0.1/refresh_time
    return math.exp(-theta * t)

def f_d(t):
    theta = 0.1/refresh_time
    return -theta * math.exp(-theta * t)

'''
Def:
x belongto R^N
f(t) = -theta e^(-theta * t)
g(t,n) = sigma(i=1,n,x_i*f(t-t_i))

g(t,n) = -f_d(dt)*g(t-dt,n)
g(t,n+1) = g(t,n) + x_(n+1) * f(t-t_n+1)

t_i and x_i are raw data
'''
def brute_test(lines):
    #the vector of brute degree(nearest similarity)
    global g,last_refresh_time
    t_n = time()
    if last_refresh_time == 0:
        co = 1
    else:
        co = -f_d(t_n - last_refresh_time)

    g = dict([(i,v*co) for i,v in g.items()])

    for line in lines:
        t_i = line[0]
        #Initialize the coefficiency of element vector Xi
        f_ti = f(t_n - t_i)

        #approximate evaluation of decay
        line = set(line[3].lower().split())
        for a in line:
            if a in g:
                g[a] += 1.0 * f_ti
            else:
                g[a] = 1.0 * f_ti

        #remove the rare ones
        for i,v in g.items():
            if v < 0.05:
                g.pop(i)

        #if absolute brute degree exceeds threshold
        if len(g) > 0 and sum(g.values())/len(g) > threshold:
            Warn('Potential brute force attack',3)
            #Only tell once
            g.clear()
            break
    last_refresh_time = t_n

def analyze(lines):
    honeypot_test(lines)
    brute_test(lines)
    weird_test(lines)
    '''
    other_test
    '''

def watch_daemon(f):
    global general,refresh_time,Lock

    sleep(refresh_time)
    #watch_daemon acts like provider
    #log_parser acts like consumer
    Lock.acquire()
    lines = f.readlines()
    records = []
    if len(lines) > 0:
        log_parser(lines,records)
        #only analyze when it's updated
        analyze(records)
    Lock.release()

def honeypot_test(lines):
    global honeypot,Table_Filter
    for line in lines:

        #find all table names
        _tablenames = Table_Filter.findall(line[3])
        tablenames = []

        #remove duplicate and space
        for tn in _tablenames:
            st = set(tn)
            if '' in st:
                st.remove('')
            tablenames += list(st)

        #if there's no tablenames within
        if len(tablenames) == 0:
            continue

        tablenames = list(tablenames)
        trigger = False
        for hp in honeypot:
            if hp in tablenames:
                trigger = True
                break
        if trigger:
            Warn('Honeypot Triggered', 7)

def read_config():
    global general,threshold,refresh_time,honeypot

    f = open('blacklist')
    for line in f.readlines():
        tmp = line.split('\t\t')
        tmp[0] = re.compile(tmp[0])
        blacklist.append(tuple(tmp))

    f = open('config')
    for line in f.readlines():
        pair = line.split()
        if pair[0] == 'honeypot':
            honeypot = pair[1].split(';')
        elif pair[0] == 'general':
            general = pair[1]
        elif pair[0] == 'brute_threshold':
            threshold = float(pair[1])
        elif pair[0] == 'refresh_time':
            refresh_time = int(pair[1])
        elif pair[0] == 'expire_sec':
            expire_sec = int(pair[1])

    try:
        f = open(general)
    except:
        print 'Open log file error\nCheck if you have enabled and have the previlege to access',general
        sys.exit(0)
    return f

def main():
    f = read_config()
    while True:
        watch_daemon(f)
    f.close()
if __name__ == '__main__':
    main()
