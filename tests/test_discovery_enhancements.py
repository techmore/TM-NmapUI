import socket
import struct
import sys
from types import SimpleNamespace
import pytest
from nmapui import host_identity
from nmapui.networking import discovery_only_gateway_addresses
from nmapui.settings import get_network_report_profile
from nmapui.topology_recommendations import append_recommendations


def packet():
    owner = '20.1.168.192.in-addr.arpa'
    encode = lambda text: b''.join(bytes([len(x)]) + x.encode() for x in text.split('.')) + b'\0'
    data = encode('WORKSTATION.local')
    return struct.pack('!6H', 0, 0x8400, 0, 1, 0, 0) + encode(owner) + struct.pack('!HHIH', 12, 1, 10, len(data)) + data


def fake_socket(monkeypatch, data=None, peer=('192.168.1.20', 5353), error=None):
    class Client:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):assert value <= 1
        def sendto(self,data,target):assert target == ('192.168.1.20',5353)
        def recvfrom(self,size):
            if error:raise error
            return data,peer
    monkeypatch.setattr(host_identity.socket,'socket',lambda *args:Client())


def test_mdns_records_device_reported_source(monkeypatch):
    fake_socket(monkeypatch,packet())
    assert host_identity.query_mdns_hostname('192.168.1.20') == {'hostname':'WORKSTATION.local','hostname_source':'device_mdns'}


@pytest.mark.parametrize('data',[b'',b'\0'*12,packet()[:-3],packet()[:12]+b'\xc0\x0c'])
def test_mdns_rejects_malformed_packets(monkeypatch,data):
    fake_socket(monkeypatch,data)
    assert host_identity.query_mdns_hostname('192.168.1.20') is None


@pytest.mark.parametrize('peer',[('192.168.1.21',5353),('192.168.1.20',9999)])
def test_mdns_rejects_unrelated_reply(monkeypatch,peer):
    fake_socket(monkeypatch,packet(),peer)
    assert host_identity.query_mdns_hostname('192.168.1.20') is None


def test_mdns_timeout_is_inconclusive(monkeypatch):
    fake_socket(monkeypatch,error=socket.timeout())
    assert host_identity.query_mdns_hostname('192.168.1.20') is None


@pytest.mark.parametrize('address',['8.8.8.8','127.0.0.1','224.0.0.251','::1','invalid','0.0.0.0'])
def test_mdns_skips_non_lan_addresses(monkeypatch,address):
    monkeypatch.setattr(host_identity.socket,'socket',lambda *a:pytest.fail('Must not send'))
    assert host_identity.query_mdns_hostname(address) is None


def test_vpn_default_keeps_attached_gateway_protected(monkeypatch):
    monkeypatch.setitem(sys.modules,'netifaces',SimpleNamespace(AF_INET=2,gateways=lambda:{'default':{18:('link#1','utun7')},2:[('192.168.1.1','en0',False)]}))
    assert discovery_only_gateway_addresses({}) == ['192.168.1.1']


def test_network_plan_is_customer_and_subnet_scoped():
    doc={'target_profiles':[{'id':'a','target':'192.168.1.0/24','customer_id':'a'}]}
    assert get_network_report_profile(doc,'192.168.1.20','a')['id']=='a'
    assert get_network_report_profile(doc,'192.168.1.20','b') is None
    assert get_network_report_profile(doc,'192.168.2.20','a') is None
    assert get_network_report_profile(doc,'192.168.1.20','') is None


def test_appendix_escapes_plan_and_is_idempotent():
    xml=b'<nmaprun><host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/></host></nmaprun>'
    plan={'title':'<script>bad</script>','devices':[{'id':'pc','parent':'lan','name':'PC','proposed_ip':'192.168.1.70'}]}
    once=append_recommendations('<html><body>Approved report</body></html>',[xml],plan)
    twice=append_recommendations(once,[xml],plan)
    assert '<script>bad</script>' not in twice
    assert twice.count('id="customer-network-plan"')==1
    assert twice.count('id="topology-recommendations"')==1
    assert 'Approved report' in twice


def test_appendix_discloses_timed_out_service_scan():
    xml=b'<nmaprun><host timedout="true"><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/></host></nmaprun>'
    result=append_recommendations('<body>Approved report</body>',[xml])
    assert 'Incomplete scan coverage' in result
    assert 'Empty port results do not establish' in result


def test_scan_start_snapshots_server_customer_and_projects_history(monkeypatch):
    import base64
    from flask import Flask
    from flask_socketio import SocketIO
    from nmapui.handlers.scan_jobs import register_scan_job_handlers
    from nmapui.jobs import ClientJobRegistry
    from nmapui.runtime_scan_history import scan_run_rows
    monkeypatch.setenv('NMAPUI_USERNAME','scanner')
    monkeypatch.setenv('NMAPUI_PASSWORD','test-password')
    monkeypatch.setenv('NMAPUI_TRUST_LOCAL_UI','false')
    app=Flask(__name__);socketio=SocketIO(app,test_mode=True)
    registry=ClientJobRegistry();customer={'id':'customer-a','name':'Customer A'}
    monkeypatch.setattr(socketio,'start_background_task',lambda *a,**k:None)
    register_scan_job_handlers(socketio,{
        'validate_target':lambda target:(True,None),
        'rate_limiter':SimpleNamespace(can_scan=lambda *a:(True,None),record_scan=lambda *a:None),
        'job_registry':registry,'emit_job_status':lambda *a:None,
        'set_last_scan_target_state':lambda **k:None,'start_scan_task':lambda *a:None,
        'generate_report_task':lambda *a:None,'get_client_state':lambda **k:{'current_customer':customer},
    })
    token=base64.b64encode(b'scanner:test-password').decode()
    client=socketio.test_client(app,headers={'Authorization':'Basic '+token})
    client.emit('start_scan',{'target':'192.168.1.20','customer_id':'forged'})
    jobs=registry.snapshot()['active_jobs'];assert len(jobs)==1
    details=jobs[0]['details'];assert details['customer_id']=='customer-a'
    customer['id']='customer-b'
    assert details['customer_id']=='customer-a'
    rows=scan_run_rows(SimpleNamespace(list_jobs=lambda **k:[{'job_id':'source','payload':{'details':details}}]))
    assert rows[0]['customer_id']=='customer-a' and rows[0]['customer_name']=='Customer A'
    client.disconnect()
