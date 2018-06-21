#!/usr/bin/python3

from argparse import ArgumentParser
from socket import *
from sys import *
from netaddr import *

#Intervalo de IPs
#Rede completa com exceção do broadcast e mascara
#Lista de IPs ex.: 192.168.0.102 103 105 110
#Scan nas principais portas
#Scan em uma porta específica ou intervalo de portas
#Resolução de nomes
#Resolução de serviço
#Versão do serviço quando possível

parse = ArgumentParser(
    description='Port Scanner',
    epilog='Danilo Loschiavo'
)

parse.add_argument(
    '-t',
    '--target',
    dest = 'target',
    help = 'Especifique o IP. Ex: 192.168.1.1',
    action = 'store',
    required = False
)

parse.add_argument(
    '-tr',
    '--target-range',
    dest = 'target_range',
    help = 'Especifique um intervalo de IPs. Ex: 192.168.1.1 192.168.1.100',
    action = 'store',
    required = False,
    nargs = 2
)

parse.add_argument(
    '-ts',
    '--target-sub-net',
    dest = 'network',
    help = 'Especifique um sub-net. EX: 192.168.1.0/24',
    action = 'store',
    required = False
)

parse.add_argument(
    '-l',
    '--list-file',
    dest = 'list_file',
    help = 'Especifique o local do arquivo com ips.',
    action = 'store',
    required = False
)

parse.add_argument(
    '-p',
    '--port',
    dest = 'port',
    help = 'Especifique a porta. ',
    action = 'store',
    required = False,
    type = int
)

parse.add_argument(
    '-pr',
    '--port-range',
    dest = 'port_range',
    help = 'Especifique um intervalo de portas. Ex: 21 22',
    action = 'store',
    required = False,
    type = int,
    nargs = 2
)

def ChecarPorta(ip, port):
    with socket(AF_INET, SOCK_STREAM) as s:
        s.settimeout(.1)
        check = s.connect_ex((ip, port))
        if not check:
            service = getservbyport(port, 'tcp').upper()
            try:
                versao = s.recv(1024).decode().splitlines()[0]
            except:
                versao = "DESCONHECIDA"
            if len(service) >= 10: 
                print('{}\tOPEN\t{}\t{}'.format(port, service, versao))
            else:
                print('{}\tOPEN\t{}\t\t{}'.format(port, service, versao))

arg = parse.parse_args()
ips = list()
ports = list()

if arg.target:
    ips.append(arg.target)
elif arg.target_range:
    for ip in IPRange(arg.target_range[0], arg.target_range[1]):
        ips.append(str(ip))
elif arg.network:
    for ip in IPNetwork(arg.network):
        ips.append(str(ip))
elif arg.list_file:
    for ip in open(arg.list_file, "r").readlines():
        ips.append(str(ip))
else:
    print('Necessário especificar um alvo!')
    exit(1)

if arg.port:
    ports.append(arg.port)
elif arg.port_range:
    for port in range(arg.port_range[0], arg.port_range[1]):
        ports.append(port)
else:
    for port in [21, 22, 80, 3389]:
        ports.append(port)

for ip in ips:
    try:
        print('Verificando: [{}] - [{}]'.format(str(ip), gethostbyaddr(str(ip))[0]))
        print('Porta\tStatus\tServiço\t\tVersão')
        for port in ports:
            ChecarPorta(ip, port)
    except:
        print('SEM CONEXÃO: {}'.format(str(ip)))
