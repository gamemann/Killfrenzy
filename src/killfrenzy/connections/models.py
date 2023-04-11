from django.db import models
from django.db.models.fields.related import ForeignKey
from django.db.models import signals

import asyncio

global web_socket
import web_socket

# Edge module.
class Edge(models.Model):
    name = models.CharField(verbose_name="name", help_text="Display name of edge.", max_length=32, blank=True)
    ip = models.CharField(verbose_name="IP", help_text="The edge server IP.", max_length=32)

    status = models.BooleanField(verbose_name="Status", editable=False, default=False)
    xdp_status = models.BooleanField(verbose_name="XDP Status", editable=False, default=False)

    def __str__(self):
        return self.name + " (" + self.ip + ")"

class Edge_Stats(models.Model):
    edge_id = models.ForeignKey(Edge, on_delete=models.CASCADE)
    sdate = models.DateTimeField(auto_now=True)

    bla_pckts = models.BigIntegerField(null=True, editable=False)
    bla_pckts_ps = models.BigIntegerField(null=True, editable=False)

    bla_bytes = models.BigIntegerField(null=True, editable=False)
    bla_bytes_ps = models.BigIntegerField(null=True, editable=False)

    whi_pckts = models.BigIntegerField(null=True, editable=False)
    whi_pckts_ps = models.BigIntegerField(null=True, editable=False)

    whi_bytes = models.BigIntegerField(null=True, editable=False)
    whi_bytes_ps = models.BigIntegerField(null=True, editable=False)

    blo_pckts = models.BigIntegerField(null=True, editable=False)
    blo_pckts_ps = models.BigIntegerField(null=True, editable=False)

    blo_bytes = models.BigIntegerField(null=True, editable=False)
    blo_bytes_ps = models.BigIntegerField(null=True, editable=False)

    fwd_pckts = models.BigIntegerField(null=True, editable=False)
    fwd_pckts_ps = models.BigIntegerField(null=True, editable=False)

    fwd_bytes = models.BigIntegerField(null=True, editable=False)
    fwd_bytes_ps = models.BigIntegerField(null=True, editable=False)

    fwdo_pckts = models.BigIntegerField(null=True, editable=False)
    fwdo_pckts_ps = models.BigIntegerField(null=True, editable=False)

    fwdo_bytes = models.BigIntegerField(null=True, editable=False)
    fwdo_bytes_ps = models.BigIntegerField(null=True, editable=False)

    pass_pckts = models.BigIntegerField(null=True, editable=False)
    pass_pckts_ps = models.BigIntegerField(null=True, editable=False)

    pass_bytes = models.BigIntegerField(null=True, editable=False)
    pass_bytes_ps = models.BigIntegerField(null=True, editable=False)

    bad_pckts = models.BigIntegerField(null=True, editable=False)
    bad_pckts_ps = models.BigIntegerField(null=True, editable=False)

    bad_bytes = models.BigIntegerField(null=True, editable=False)
    bad_bytes_ps = models.BigIntegerField(null=True, editable=False)

    a2rp_pckts = models.BigIntegerField(null=True, editable=False)
    a2rp_pckts_ps = models.BigIntegerField(null=True, editable=False)

    a2rp_bytes = models.BigIntegerField(null=True, editable=False)
    a2rp_bytes_ps = models.BigIntegerField(null=True, editable=False)

    a2rs_pckts = models.BigIntegerField(null=True, editable=False)
    a2rs_pckts_ps = models.BigIntegerField(null=True, editable=False)

    a2rs_bytes = models.BigIntegerField(null=True, editable=False)
    a2rs_bytes_ps = models.BigIntegerField(null=True, editable=False)

    dro_pckts = models.BigIntegerField(null=True, editable=False)
    dro_pckts_ps = models.BigIntegerField(null=True, editable=False)

    dro_bytes = models.BigIntegerField(null=True, editable=False)
    dro_bytes_ps = models.BigIntegerField(null=True, editable=False)

    drc_pckts = models.BigIntegerField(null=True, editable=False)
    drc_pckts_ps = models.BigIntegerField(null=True, editable=False)

    drc_bytes = models.BigIntegerField(null=True, editable=False)
    drc_bytes_ps = models.BigIntegerField(null=True, editable=False)

    cpu_load = models.BigIntegerField(null=True, editable=False)

class Edge_Settings(models.Model):
    class ForceMode(models.IntegerChoices):
        NONE = 0, "None (DRV)"
        SKB = 1, "SKB"
        HW = 2, "Offload"
    
    edge_id = models.ForeignKey(Edge, on_delete=models.CASCADE)
    interface = models.CharField(verbose_name="Interface", help_text="The interface for the XDP program to bind to", default="ens18", max_length=64)
    edge_ip = models.CharField(verbose_name="Edge IP", help_text="Override the interface IP (leave blank to have it retrieved automatically, recommended)", max_length=32, blank=True)
    force_mode = models.IntegerField(verbose_name="XDP Force Mode", help_text="The XDP force mode.", default=ForceMode.NONE, choices=ForceMode.choices)
    socket_count = models.IntegerField(verbose_name="Socket Count", help_text="AF_XDP socket count (0 = use CPU count).", default=0)
    queue_is_static = models.BooleanField(name="queue_is_static", verbose_name="Use Queue ID", help_text="Whether to use the below queue ID for all socket.", default=False)
    queue_id = models.IntegerField(verbose_name="Queue ID", help_text="The queue ID to use if Use Queue ID is enabled.", default=0)
    zero_copy = models.BooleanField(verbose_name="Zero Copy", help_text="Whether to enable AF_XDP zero-copy support.", default=False)
    need_wakeup = models.BooleanField(verbose_name="Need Wakeup", help_text="AF_XDP enable need wakeup (may cause better performance.", default=True)
    batch_size = models.IntegerField(verbose_name="Batch Size", help_text="AF_XDP batch size for RX.", default=64)
    verbose = models.BooleanField(verbose_name="Verbose", help_text="Whether to enable verbose mode on the edge server.", default=False)
    calc_stats = models.BooleanField(verbose_name="Calculate Stats", help_text="Whether to calculate stats to /etc/kilimanjaro.", default=True)
    allow_all_edge = models.BooleanField(verbose_name="Allow All Edge Traffic", help_text="Whether to enable all traffic sent directly to the edge depending on the edge IP.", default=True)

    bgp = models.BooleanField(verbose_name="Enable BGP (AKA Announce)", help_text="Whether to enable BGP.", default=True)

    class Meta:
        verbose_name = "edge setting"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        ret = {}

        ret["interface"] = self.interface
        ret["edge_ip"] = self.edge_ip
        ret["force_mode"] = self.force_mode
        ret["socket_count"] = self.socket_count
        ret["queue_is_static"] = self.queue_is_static
        ret["queue_id"] = self.queue_id
        ret["zero_copy"] = self.zero_copy
        ret["need_wakeup"] = self.need_wakeup
        ret["batch_size"] = self.batch_size
        ret["verbose"] = self.verbose
        ret["calc_stats"] = self.calc_stats
        ret["allow_all_edge"] = self.allow_all_edge

        edge = web_socket.socket_c.get_conn(self.edge_id.ip)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("edge_update", edge=edge, settings=ret))

    def __str__(self):
        return self.edge_id.name + " Settings"

# Connection module.
class Connection(models.Model):
    class Filters(models.IntegerChoices):
        NONE = 0, "None"
        SRCDS = (1 << 0), "SRCDS"
        RUST = (1 << 1), "Rust"
        GMOD = (1 << 2), "GMOD"

    class Protocols(models.TextChoices):
        UDP = "udp", "UDP"
        TCP = "tcp", "TCP"
        ICMP = "icmp", "ICMP"

    enabled = models.BooleanField(verbose_name="Enabled", help_text="Enable connection.", default=True)
    
    protocol = models.CharField(verbose_name="Protocol", help_text="The protocol for this connection.", max_length=12, default=Protocols.UDP, choices=Protocols.choices)
    bind_ip = models.CharField(verbose_name="Bind IP", help_text="Usually game server IP/Anycast IP", max_length=32)
    bind_port = models.IntegerField(verbose_name="Bind Port", help_text="Usually the game server port (e.g. 27015).")

    dest_ip = models.CharField(verbose_name="Dest IP", help_text="The game server machine IP.", max_length=32)
    dest_port = models.IntegerField(verbose_name="Dest Port", help_text="Port to translate to (0 = bind port, default).", default=0)

    filters = models.IntegerField(verbose_name="Filters", help_text="Filters to apply for this connection.", default=Filters.NONE, choices=Filters.choices)

    udp_rl_bl = models.IntegerField(verbose_name="UDP RL BL", help_text="UDP rate limit block time.", default=0)
    udp_rl_pps = models.IntegerField(verbose_name="UDP RL PPS", help_text="UDP rate limit PPS limit.", default=0)
    udp_rl_bps = models.IntegerField(verbose_name="UDP RL BPS", help_text="UDP rate limit BPS limit.", default=0)

    tcp_rl_bl = models.IntegerField(verbose_name="TCP RL BL", help_text="TCP rate limit block time.", default=0)
    tcp_rl_pps = models.IntegerField(verbose_name="TCP RL PPS", help_text="TCP rate limit PPS limit.", default=0)
    tcp_rl_bps = models.IntegerField(verbose_name="TCP RL BPS", help_text="TCP rate limit BPS limit.", default=0)

    icmp_rl_bl = models.IntegerField(verbose_name="ICMP RL BL", help_text="ICMP rate limit block time.", default=0)
    icmp_rl_pps = models.IntegerField(verbose_name="ICMP RL PPS", help_text="ICMP rate limit PPS limit.", default=0)
    icmp_rl_bps = models.IntegerField(verbose_name="ICMP RL BPS", help_text="ICMP rate limit BPS limit.", default=0)

    syn_rl_bl = models.IntegerField(verbose_name="SYN RL BL", help_text="TCP SYN rate limit block time.", default=0)
    syn_rl_pps = models.IntegerField(verbose_name="SYN RL PPS", help_text="TCP SYN rate limit PPS limit.", default=0)
    syn_rl_bps = models.IntegerField(verbose_name="SYN RL BPS", help_text="TCP SYN rate limit BPS limit.", default=0)

    a2s_info_enabled = models.BooleanField(verbose_name="A2S_INFO Caching", help_text="Whether to enable A2S_INFO caching.", default=False)
    a2s_info_cache_time = models.IntegerField(verbose_name="A2S_INFO Cache Time", help_text="A2S_INFO cache time if enabled.", default=45)
    a2s_info_global_cache = models.BooleanField(verbose_name="A2S_INFO Global Cache", help_text="Whether to enable A2S_INFO global caching.", default=False)
    a2s_info_cache_timeout = models.IntegerField(verbose_name="A2S_INFO Cache Timeout", help_text="A2S_INFO cache timeout for expired caches.", default=180)

    pps = models.BigIntegerField(null=True, editable=False)
    bps = models.BigIntegerField(null=True, editable=False)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        ret = []
        conn = {}
        conn["enabled"] = self.enabled
        conn["protocol"] = self.protocol
        conn["bind_ip"] = self.bind_ip
        conn["bind_port"] = self.bind_port
        conn["dest_ip"] = self.dest_ip
        conn["dest_port"] = self.dest_port
        conn["filters"] = self.filters

        conn["udp_rl"] = {}
        conn["udp_rl"]["block_time"] = self.udp_rl_bl
        conn["udp_rl"]["pps"] = self.udp_rl_pps
        conn["udp_rl"]["bps"] = self.udp_rl_bps

        conn["tcp_rl"] = {}
        conn["tcp_rl"]["block_time"] = self.tcp_rl_bl
        conn["tcp_rl"]["pps"] = self.tcp_rl_pps
        conn["tcp_rl"]["bps"] = self.tcp_rl_bps

        conn["icmp_rl"] = {}
        conn["icmp_rl"]["block_time"] = self.icmp_rl_bl
        conn["icmp_rl"]["pps"] = self.icmp_rl_pps
        conn["icmp_rl"]["bps"] = self.icmp_rl_bps
        
        conn["syn_settings"] = {}
        conn["syn_settings"]["rl"] = {}
        conn["syn_settings"]["rl"]["block_time"] = self.syn_rl_bl
        conn["syn_settings"]["rl"]["pps"] = self.syn_rl_pps
        conn["syn_settings"]["rl"]["bps"] = self.syn_rl_bps

        conn["cache_settings"] = {}
        conn["cache_settings"]["a2s_info_enabled"] = self.a2s_info_enabled
        conn["cache_settings"]["a2s_info_cache_time"] = self.a2s_info_cache_time
        conn["cache_settings"]["a2s_info_global_cache"] = self.a2s_info_global_cache
        conn["cache_settings"]["a2s_info_cache_timeout"] = self.a2s_info_cache_timeout
        ret.append(conn)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("connection_update", connections=ret))

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.bind_ip + ":" + str(self.bind_port)

class Connection_A2S_Response(models.Model):
    connection_id = ForeignKey(Connection, on_delete=models.CASCADE)
    response = models.CharField(verbose_name="A2S_INFO Response", help_text="A2S_INFO response text.", max_length=2048)
    expires = models.BigIntegerField(verbose_name="Cache Expire Time", help_text="Response's expire time in nanoseconds.", null=True)

    def __str__(self):
        return self.ip + ":" + str(self.port)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        a2s = {}

        a2s["ip"] = self.connection_id.bind_ip
        a2s["port"] = self.connection_id.bind_port
        a2s["expires"] = self.expires
        a2s["response"] = self.self.response

        asyncio.run(web_socket.socket_c.prepare_and_send_data("a2s_update", a2s_resp=a2s))

    class Meta:
        verbose_name = "A2S_INFO response"
        verbose_name_plural = "A2S_INFO responses"

class Connection_Stats(models.Model):
    connection_id = ForeignKey(Connection, on_delete=models.CASCADE)
    pps = models.BigIntegerField(null=True, editable=False)
    bps = models.BigIntegerField(null=True, editable=False)

class Whitelist(models.Model):
    auto_added = models.BooleanField(verbose_name="Auto Added", help_text="Whether this was added by system", editable=False, default=False)
    prefix = models.CharField(verbose_name="Prefix", help_text="The prefix in IP/CIDR format", max_length=32)

    class Meta:
        verbose_name_plural = "whitelist IPs"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        ret = []

        ret.append(self.prefix)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("whitelist_update", whitelist=ret))

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.prefix

class Blacklist(models.Model):
    auto_added = models.BooleanField(verbose_name="Auto Added", help_text="Whether this was added by system", editable=False, default=False)
    prefix = models.CharField(verbose_name="Prefix", help_text="The prefix in IP/CIDR format", max_length=32)

    class Meta:
        verbose_name_plural = "blacklist IPs"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        ret = []

        ret.append(self.prefix)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("blacklist_update", blacklist=ret))

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.prefix

class Port_Punch(models.Model):
    auto_added = models.BooleanField(verbose_name="Auto Added", help_text="Whether this was added by system", editable=False, default=False)
    ip = models.CharField(verbose_name="IP Address", help_text="IP address", max_length=32)
    port = models.IntegerField(verbose_name="Port", help_text="Port", default=0)
    cnt = models.IntegerField(editable = False, default=0, null = True)

    service_ip = models.CharField(verbose_name="Service IP Address", help_text="Service IP address", max_length=32)
    service_port = models.IntegerField(verbose_name="Service Port", help_text="Service Port", default=0)

    dest_ip = models.CharField(verbose_name="Destination IP Address", help_text="The game server machine's IP address", max_length=32)
    
    last_seen = models.DateTimeField(editable = False, auto_now = True, null = True)
    created = models.DateTimeField(editable = False, auto_now_add = True, null = True)

    def __str__(self):
        return self.ip + ":" + str(self.port)

    def save(self, *args, **kwargs):
        new = False

        if not self.id or (self.cnt is not None and self.cnt < 5):
            new = True

        self.cnt = self.cnt + 1

        super().save(*args, **kwargs)

        if new:
            ret = []
            pp = {}

            pp["ip"] = self.ip
            pp["port"] = self.port
            pp["service_ip"] = self.service_ip
            pp["service_port"] = self.service_port

            pp["dest_ip"] = self.dest_ip

            ret.append(pp)

            #print("[KF] Port punching " + str(self.ip) + ":" + str(self.port) + " => " + str(self.service_ip) + ":" + str(self.service_port) + " (" + str(self.dest_ip) + ")...")

            asyncio.run(web_socket.socket_c.prepare_and_send_data("port_punch_update", port_punch=ret))

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    class Meta:
        verbose_name = "port punch"
        verbose_name_plural = "port punches"

class Validated_Client(models.Model):
    src_ip = models.CharField(verbose_name="Source IP", help_text="The source IP of client.", max_length=32)
    src_port = models.IntegerField(verbose_name="Source Port", help_text="The source port of client.", default=0)

    dst_ip = models.CharField(verbose_name="Destination IP", help_text="The destination IP of server.", max_length=32)
    dst_port = models.IntegerField(verbose_name="Destination Port", help_text="The destination port of server.", default=0)

    last_seen = models.DateTimeField(editable = False, auto_now = True, null = True)
    created = models.DateTimeField(editable = False, auto_now_add = True, null = True)

    def __str__(self):
        return self.src_ip + ":" + str(self.src_port)

    def save(self, *args, **kwargs):
        new = False

        if not self.id:
            new = True

        super().save(*args, **kwargs)

        if new:
            ret = []
            vc = {}

            vc["src_ip"] = self.src_ip
            vc["src_port"] = self.src_port
            vc["dst_ip"] = self.dst_ip
            vc["dst_port"] = self.dst_port

            ret.append(vc)

            asyncio.run(web_socket.socket_c.prepare_and_send_data("validated_client_update", validated_client=ret))

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    class Meta:
        verbose_name = "validated client"
        verbose_name_plural = "validated clients"

def delete_item(sender, instance, **kwargs):
    if sender == Connection:
        ret = []
        conn = {}

        conn["protocol"] = instance.protocol
        conn["bind_ip"] = instance.bind_ip
        conn["bind_port"] = instance.bind_port
        conn["dest_ip"] = instance.dest_ip

        ret.append(conn)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("connection_delete", connections=ret))

    elif sender == Whitelist:
        ret = []
        whitelist = {}

        whitelist["prefix"] = instance.prefix

        ret.append(whitelist)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("whitelist_delete", whitelist=ret))
    elif sender == Blacklist:
        ret = []
        blacklist = {}

        blacklist["prefix"] = instance.prefix

        ret.append(blacklist)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("blacklist_delete", blacklist=ret))
    elif sender == Port_Punch:
        ret = []
        pp = {}

        pp["ip"] = instance.ip
        pp["port"] = instance.port
        pp["service_ip"] = instance.service_ip
        pp["service_port"] = instance.service_port

        ret.append(pp)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("port_punch_delete", port_punch=ret))
    elif sender == Validated_Client:
        ret = []
        vc = {}

        vc["src_ip"] = instance.src_ip
        vc["src_port"] = instance.src_port
        vc["dst_ip"] = instance.dst_ip
        vc["dst_port"] = instance.dst_port

        ret.append(vc)

        asyncio.run(web_socket.socket_c.prepare_and_send_data("validated_client_delete", validated_client=ret))


signals.post_delete.connect(receiver=delete_item, sender=Connection)
signals.post_delete.connect(receiver=delete_item, sender=Whitelist)
signals.post_delete.connect(receiver=delete_item, sender=Blacklist)
signals.post_delete.connect(receiver=delete_item, sender=Port_Punch)