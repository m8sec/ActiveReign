'''
Help From
https://github.com/the-useless-one/pywerview/blob/master/pywerview/requester.py
https://github.com/the-useless-one/pywerview/blob/master/pywerview/functions/net.py
'''

import socket
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm

from ar3.core.connector import Connector

class RpcCon(Connector):
    def __init__(self, args, loggers, host):
        Connector.__init__(self, args, loggers, host)
        self.pipe           = None
        self.rpc_connection = None
        self.dcom           = None
        self.wmi_connection = None
        self.port           = 445


    def create_rpc_con(self, pipe):
        # Here we build the DCE/RPC connection
        self.pipe = pipe

        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        if self.pipe == r'\drsuapi':
            string_binding = epm.hept_map(self.host, drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self.username, password=self.password,domain=self.domain, lmhash=self.lmhash,nthash=self.nthash)
        else:
            rpctransport = transport.SMBTransport(self.host, self.port, self.pipe,username=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash,nthash=self.nthash)

        # SET TIMEOUT
        rpctransport.set_connect_timeout(self.timeout)
        dce = rpctransport.get_dce_rpc()

        if self.pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except socket.error:
            self.rpc_connection = None
        else:
            dce.bind(binding_strings[self.pipe[1:]])
            self.rpc_connection = dce

    def list_services(self):
        services = {}
        # https://github.com/SecureAuthCorp/impacket/blob/master/examples/services.py
        self.create_rpc_con(r'\svcctl')
        ans = scmr.hROpenSCManagerW(self.rpc_connection)
        scManagerHandle = ans['lpScHandle']
        resp = scmr.hREnumServicesStatusW(self.rpc_connection, scManagerHandle)
        for i in range(len(resp)):
            name = resp[i]['lpServiceName'][:-1]
            services[name]              = {}
            services[name]['Name']      = name
            services[name]['Display']   = resp[i]['lpDisplayName'][:-1]

            state = resp[i]['ServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_CONTINUE_PENDING:
                services[name]['Status'] = "CONTINUE PENDING"
            elif state == scmr.SERVICE_PAUSE_PENDING:
                services[name]['Status'] = "PAUSE PENDING"
            elif state == scmr.SERVICE_PAUSED:
                services[name]['Status'] = "PAUSED"
            elif state == scmr.SERVICE_RUNNING:
                services[name]['Status'] = "RUNNING"
            elif state == scmr.SERVICE_START_PENDING:
                services[name]['Status'] = "START PENDING"
            elif state == scmr.SERVICE_STOP_PENDING:
                services[name]['Status'] = "STOP PENDING"
            elif state == scmr.SERVICE_STOPPED:
                services[name]['Status'] = "STOPPED"
            else:
                services[name]['Status'] = "UNKNOWN"

        self.rpc_connection.disconnect()
        return services

    def get_netsessions(self):
        self.sessions = {}
        self.create_rpc_con(r'\srvsvc')
        try:
            resp = srvs.hNetrSessionEnum(self.rpc_connection, '\x00', NULL, 10)
        except DCERPCException:
            return list()

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            self.sessions[session['sesi10_username'].strip('\x00')] = {'user' : session['sesi10_username'].strip('\x00'),
                                                      'host' : session['sesi10_cname'].strip('\x00'),
                                                      'time' : session['sesi10_time'],
                                                      'idle' : session['sesi10_idle_time']
                                                      }
        self.rpc_connection.disconnect()


    def get_netloggedon(self):
        self.loggedon = {}
        self.create_rpc_con(r'\wkssvc')
        try:
            resp = wkst.hNetrWkstaUserEnum(self.rpc_connection, 1)
        except DCERPCException as e:
            return list()

        results = list()
        for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            self.loggedon[wksta_user['wkui1_username'].strip('\x00')] = {
                                    'domain'    : wksta_user['wkui1_logon_domain'].strip('\x00'),
                                    'logon_srv' : wksta_user['wkui1_logon_server'].strip('\x00'),
                                    'user'      : wksta_user['wkui1_username'].strip('\x00'),
                                }

        self.rpc_connection.disconnect()
