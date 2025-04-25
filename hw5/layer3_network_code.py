"""Simulating a network with 3 subnets"""
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, Controller
import ipaddress


class Layer3Topo( Topo ):
    def build( self ):
        """
        build the topography of the network
        """
        #routers for each LAN
        sA = self.addSwitch('sA', dpid="0000000000000001")   # for LAN A
        sB = self.addSwitch('sB', dpid="0000000000000002")   # for LAN B
        sC = self.addSwitch('sC', dpid="0000000000000003")   # for LAN C
        rA = self.addHost('rA', ip='20.10.172.1/26')
        rB = self.addHost('rB', ip='20.10.172.65/25')
        rC = self.addHost('rC', ip='20.10.172.193/27')

        #hosts in LAN A 
        hA1 = self.addHost('hA1', ip='20.10.172.2/26')
        hA2 = self.addHost('hA2', ip='20.10.172.3/26')

        # hosts in LAN B 
        hB1 = self.addHost('hB1', ip='20.10.172.66/25')
        hB2 = self.addHost('hB2', ip='20.10.172.67/25')

        #hosts in LAN C
        hC1 = self.addHost('hC1', ip='20.10.172.194/27')
        hC2 = self.addHost('hC2', ip='20.10.172.195/27')

        #link hosts to LAN switch 
        for h, sw in [(hA1,sA), (hA2,sA), (hB1,sB), (hB2,sB), (hC1,sC), (hC2,sC)]:
            self.addLink(h, sw)

        self.addLink(rA, sA)
        self.addLink(rB, sB)
        self.addLink(rC, sC)

        self.addLink(rA, rB)
        self.addLink(rB, rC)
        self.addLink(rC, rA)


def runTest():
    """
    run connectivity tests on the hots
    """
    topo = Layer3Topo()
    net = Mininet(topo=topo, controller=Controller, switch=OVSKernelSwitch)
    net.start()

    print('\nRunning pingAll\n')
    net.pingAll()

    print('\nDetailed LAN testing:\n')
    for lan, hosts in [('LAN A', ['hA1','hA2']), ('LAN B', ['hB1','hB2']), ('LAN C', ['hC1','hC2'])]:
        print(f'{lan}\n')
        for src in hosts:
            for dst in hosts:
                if src != dst:
                    result = net.get(src).cmd(f'ping -c1 -W1 {net.get(dst).IP()}')
                    if ', 0% packet loss' in result:
                        loss = 'OK'
                    else:
                        loss = 'FAIL'
                    print(f'{src} to {dst}: {loss}\n')
    
    net.stop()


# never ened up using
# def get_network(ip, mask):
#     #ip_parts = list(map(int, ip.split('.')))
#     #mask_parts = list(map(int, mask.split('.')))
#     #network = [ip_parts[i] & mask_parts[i] for i in range(4)]
#     #return '.'.join(map(str, network))

#     return str(ipaddress.ip_network(f'{ip}/{mask}', strict=False).network_address)


def cidr_to_mask(cidr):
    """
    converts cidr form into mask form
    cidr: the cidr number of bits to mask
    returns: the subnet mask in 255.255.255.X form
    """
    return str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False).netmask)


def task3():
    """
    setup the topography as instructed in task 3
    """
    topo = Layer3Topo()
    net = Mininet(topo=topo, controller=Controller, switch=OVSKernelSwitch)  
    net.start()
    
    hosts = ['hA1', 'hA2', 'hB1', 'hB2', 'hC1', 'hC2']
    lans = ['rA','rB', 'rC']
    cidr_map = {'rA': 26, 'rB': 25, 'rC': 27}

    for lan in lans:
        rtr = net.get(lan)
        # enable ip forwarding
        result = rtr.cmd('sysctl -w net.ipv4.ip_forward=1')
        print(f'Enabled IP forwarding for LAN {lan[-1]}')

    for lan in lans:
        # add routes to routers
        for dst in lans:
            if dst != lan:
                d = net.get(dst)
                dst_cidr = cidr_map[dst]
                dst_mask = cidr_to_mask(dst_cidr)
                dst_ip = d.IP()
                ip_parts = d.IP().split('.')
                ip_parts[-1] = str(int(ip_parts[-1])-1)
                dst_network = '.'.join(ip_parts)
 
                #dst_network = get_network(dst_ip, dst_mask)
                dst_gateway = dst_ip
                print(f'Adding route from LAN {lan[-1]} to LAN {dst[-1]}')
                #print(dst_network, dst_mask, dst_gateway)
                result = rtr.cmd(f'route add -net {dst_network} netmask {dst_mask} gw {dst_gateway}')
                #print(result)

    # add routes to hosts
    for host in hosts:
        for lan in lans:
            if host[1] == lan[1]:
                continue
            else:
                h = net.get(host)
                host_ip = h.IP()
                host_gateway = net.get(f'r{host[1]}').IP()
                l = net.get(lan)
                if 'rA' == lan:
                    cidr = 26
                elif 'rB' == lan:
                    cidr = 25
                else:
                    cidr = 27
                lan_netmask = cidr_to_mask(cidr)
                #lan_network = get_network(l.IP(), lan_netmask)
                ip_parts = l.IP().split('.')
                ip_parts[-1] = str(int(ip_parts[-1])-1)
                lan_network = '.'.join(ip_parts)
                print(f'Adding route from {h} to {l}')
                #print(lan_network, lan_netmask, host_gateway)
                result = h.cmd(f'route add -net {lan_network} netmask {lan_netmask} gw {host_gateway}')
                #print(result)
                

    # test
    print('Running tests using ping and traceroute')
    
    for src in hosts:
        for dst in hosts:
            if src[1] == dst[1]:
                # hosts on same subnet
                continue
            if src != dst:
                s = net.get(src)
                d = net.get(dst)
                src_ip = s.IP()
                dst_ip = d.IP()
                print(f'Testing ping from {s} to {d}')
                result = s.cmd(f'ping -c 3 {dst_ip}')
                print(result)
                print(f'Testing traceroute from {s} to {d}')
                result = s.cmd(f'traceroute {dst_ip}')
                print(result)

    for host in hosts:
        h = net.get(host)
        print(f'Table for {host}:{h.IP()}')
        print(h.cmd('route -n'))

    net.stop()



if __name__ == '__main__':
    #runTest()
    task3()

