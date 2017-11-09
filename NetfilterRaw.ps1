nft add set filter blackhole { type ipv4_addr\;}
nft add element filter blackhole { 
    10.2.2.0/24, 
    10.4.0.0/16, 
    10.32.0.0/24, 
    10.54.0.0/19, 
    10.55.1.0/24, 
    10.64.0.0/16, 
    10.92.2.0/24, 
    10.172.0.0/16,
    10.200.0.0/24,
    10.200.2.0/24
}

Qwuik uses udp and even the latest greatest conntrack kernel module can't track its state so you get udp packets for quick flying out different
interfaces, so if you can see chrome is using qwuick then that might perform badely even with the latest in wan load 
balancing



Get-SFTPChildItem -SFTPSession $SFTPSession -Path /

