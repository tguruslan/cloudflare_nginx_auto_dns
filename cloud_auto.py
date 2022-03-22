#!/usr/bin/python3

from nginxparser_eb import load
import inotify.adapters
import CloudFlare
import time

cf_email=''
cf_token=''
folder='/etc/nginx/sites-available'
logfile='/var/log/cloud_auto.log'

ignore_ips=[]


cf = CloudFlare.CloudFlare(email=cf_email, token=cf_token)

zones = cf.zones.get()
all_zones={}
for zone in zones:
    all_zones[zone['name']] = zone['id']

def get_zone_id(name):
    tmp=""
    for key in all_zones:
        if key in name:
           tmp=all_zones[key]
    return tmp

def save_record(ip,domain):
    try:
        r = cf.zones.dns_records.post(
            get_zone_id(domain),
            data={
                'name': domain,
                'type': 'A',
                'content': ip,
                'proxied': True
            }
        )
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        r = e
    return r

def delete_record(ip,domain):
    for a in cf.zones.dns_records.get(
            get_zone_id(domain),
            params={
                'name': domain,
                'type': 'A',
                'content': ip,
                'proxied': True,
            }
    ):
        try:
            r = cf.zones.dns_records.delete(a['zone_id'], a['id'])
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            r = e
    return r

def get_data(filename):
    domains=[]
    ips=[]
    for a in load(open(filename,'r')):
        for b in a[1]:
            if b[0] == 'listen':
                ip=b[1].split(':')[0]
                if not ip in ignore_ips:
                    ips.append(ip)

            if b[0] == 'server_name':
                for domain in b[1].split(' '):
                    domains.append(domain)
    resp={}
    for domain in list(filter(None, domains)):
       resp[domain]=list(filter(None, ips))

    return resp

def get_exist(name):
    resp_ip=[]
    for a in cf.zones.dns_records.get(
            get_zone_id(name),
            params={'name': name, 'type': 'A'}
    ):
        resp_ip.append(a['content'])
    return resp_ip


def _main():
    i = inotify.adapters.Inotify()
    i.add_watch(folder)
    lastfile=""
    count=0

    for event in i.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        if filename and filename[0].isalpha() and filename.endswith('.conf') and not filename.startswith('ssl.'):
            if type_names[0] in ['IN_CREATE', 'IN_CLOSE_WRITE']:
                if lastfile != filename:
                    with open(logfile, "a+") as log:
                        time.sleep(10)
                        config = get_data('{}/{}'.format(folder,filename))
                        lastfile=filename

                        for c in config:
                            l_a=config[c]
                            l_b=get_exist(c)
                            for ip in list(set(l_a)-set(l_b)):
                                log.write('try create {} {}\n'.format(c, ip))
                                log.write('{}\n'.format(save_record(ip, c)))

                            for ip in list(set(l_b)-set(l_a)):
                                log.write('try delete {} {}\n'.format(c, ip))
                                log.write('{}\n'.format(delete_record(ip, c)))

                else:
                    if count > 75: # Костиль щоб скрипт не спрацьовував через те що він сам же і відкрив файл
                        count=0
                        lastfile=""
                    else:
                        count=count+1

            if type_names[0] in ['IN_DELETE']:
                with open(logfile, "a+") as log:
                    domain = filename.replace('.conf','')
                    for a in cf.zones.dns_records.get(
                        get_zone_id(domain),
                        params={'name': domain, 'type': 'A'}
                    ):
                        r = cf.zones.dns_records.delete(a['zone_id'], a['id'])
                        log.write('try delete {} {}\n'.format(a['name'], a['content']))

if __name__ == '__main__':
    _main()
