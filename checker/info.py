N_HOSTS = 4

# For the full topology
N_ROUTERS = 3
N_HOSTSEACH = 2

R_OUTFILE = "switch_out.txt"
R_ERRFILE = "switch_err.txt"
LOGDIR = "hosts_output"
ARP_TABLE = "arp_table.txt"

# If this is low there are bunch of annoying race conditions; this makes
# testing last veeeery long, but at least it's somewhat robust even on
# low-resource machines.
TIMEOUT = 12

BASE_FORMATS = {
        "host_name": "h-{}",
        "router_if_name": "r-{}",
        "host_if_name": "h-{}",
        "router_ip": "192.168.1.{}",
        "switch_name": "switch-{}",
        "host_ip": "192.168.1.{}",
        "router_mac": "de:fe:c8:ed:{1:02X}:{0:02X}",
        "host_mac": "de:ad:be:ef:00:{:02X}",
        "output_file": "{}-host-out.txt",
        "error_file": "{}-host-err.txt",
        "r2r_ip1": "192.{}.{}.1",
        "r2r_ip2": "192.{}.{}.2",
        "r2r_if_name": "rr-{}-{}",
        "r2r_mac": "ca:fe:ba:be:{:02X}:{:02X}",
        "out_file": "switch_{}_out",
        "err_file": "switch_{}_err",
        "rtable": "rtable{}.txt"
}


def get(value, first=None, second=None):
    return BASE_FORMATS[value].format(first, second)
