#!/usr/bin/env python3

# Requirements
import argparse
import codecs
import json
import os

import shodan
from shodan.cli.helpers import get_api_key

color = {
    'BOLD': '\033[01m',
    'GREEN': '\033[92m',
    'ORANGE': '\033[33m',
    'RED': '\033[1;31m',
    'END': '\033[0m',
}

bn = r'''
{GREEN}                            /)          (\
                            <(            )>
                             )\___    ___/(
                              )\--(_,,_)/(
                                .: :: :.
                               <`^-..-^'>
                               <^<>'`<>^>>
                                `-(-|)-'  >
                            _____(/=|\)_____>
                           (  .---\()/---.  )  >
                            )(    V^^V-   )(       >
                           (  )   \vv/\- (  )        >
                           ' (     `'  )- ) `         >
                              `      ,'- ' \  `.-.
                                   ,'_ __   \ /   \   >
                                  /____ _    .     )
                                  \======= == )  ,'  >
                                   \========,'  /  >
                     _   ,,-.--.____\_____,' , ' >
                    ( `-'/, <`-------.    ,'   >
                     `  ( )\ )        >--')   /
                         `  ' .------<=====)  (\
                           ,-'        |===)   ( \  _.--.
                          /           .==)    |  \(  --.`
                         /           /==)   , \`.______ \_.-)
                        (           /===)      \       \`._/
                         `.  `  ____\===)'      \       `._
                           ` .      ))=/         .
                                >-'//==.
                            __,'  /'==-|         .
                      , ---/_,--.(==-,'.         |
                  , ---,   `    (,)  ,'|
                  - ,---------------'
                (' /                    \       /
                 `.\                     `-----<
                    )                        \  `.__
                                              ).--._)
                                             (_)   '
                                               `{END}

                                                {RED}Version: 0.1{END}
{BOLD}{ORANGE}Achilles0x0{END}
{BOLD}{RED}L33t0s_H4ck0r${END}
'''.format(**color)

os.system('cls' if os.name == 'nt' else 'clear')
codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)

api = shodan.Shodan(get_api_key())

class Shenlong(object):

    def __init__(self):
        self.description = bn
        parser = argparse.ArgumentParser(description='Shodan OSINT - Shenlong', prog=self.description)
        parser.add_argument('-g', '--ipaddr', metavar='8.8.8.8', type=str, help='IP Address', default=None)
        parser.add_argument('-o', '--output', metavar='output', help='Specify output file name [Default JSON]')
        self.args = parser.parse_args()

    def start(self):
        print(self.description)

        target = self.args.ipaddr
        filename = self.args.output

        if target is not None:
            ip = api.host(target)
            print(f'''
IP Address: {ip['ip_str']}
Hostname: {ip.get('hostnames')}
OS: {ip.get('os')}
Domains: {ip.get('domains')}
Organization: {ip.get('org')}
ASN: {ip.get('asn')}
DeviceType: {ip.get('info')}
Location: {ip.get('location')}
ISP: {ip.get('isp')}
Info: {ip.get('os')}
Ports: {ip.get('ports','transport')}
CVEs: {ip.get('vulns')}
----------PORT DETAILS----------''')
            for info in ip['data']:
                print(f'''
Port: {info['port']}/{info['transport']}
Info: {info['data']}
''')

        if filename is not None:
            with open(filename, 'a') as write_file:
                json.dump(ip, write_file)
                write_file.write(',')
                write_file.close()

try:
    Shenlong().start()
except KeyboardInterrupt:
    print(r'''
{GREEN}     /     \
    ((     ))
===  \\_v_//  ===
  ====)_^_(====
  ===/ O O \===
  = | /_ _\ | =
 =   \/_ _\/   =
      \_ _/
      (o_o)
       VwV{END}

{RED}Keyboard Interrupt{END}
'''.format(**color))
exit()

# Necessario instalar a chave de API do Shodan localmente
# $: easy_install shodan ou pip install shodan
# $: shodan init <API>
