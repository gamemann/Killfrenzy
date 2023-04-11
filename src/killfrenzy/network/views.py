from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from connections.models import *

def index(request):
    edges = Edge.objects.all()
    pps = {}
    mbps = {}
    cpu_load = {}
    xdp_status = {}

    for edge in edges:
        if edge is None:
            continue
        
        try:
            stats = Edge_Stats.objects.filter(edge_id=edge).latest('id')
        except Exception:
            stats = None
        
        tot_pps = 0
        tot_mbps = 0
        cpu_load_edge = 0
        
        if stats is not None:
            cpu_load_edge = stats.cpu_load

            for k, v in stats.__dict__.items():
                if "pckts_ps" in k:
                    tot_pps = tot_pps + int(v)
                elif "bytes_ps" in k:
                    tot_mbps = tot_mbps + int((int(v) / 1e6))

        pps[edge.id] = tot_pps
        mbps[edge.id] = tot_mbps
        cpu_load[edge.id] = cpu_load_edge
        xdp_status[edge.id] = edge.xdp_status

    ctx = {"edges": edges, "pps": pps, "mbps": mbps, "cpu_load": cpu_load, "xdp_status": xdp_status}

    return render(request, 'network/index.html', ctx)

def view_edge(request, edge_id):
    edge = get_object_or_404(Edge, id=edge_id)


    return render(request, 'network/view_edge.html', {"edge": edge})