import requests.packages.urllib3
import yaml
import logging
from cobra.internal.codec.xmlcodec import toXMLStr
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.ctrlr
import cobra.model.fabric
import cobra.model.pol
import cobra.model.fv
import cobra.model.l3ext

class AciMo:
    def __init__(self, url, username, password, config, secure=False, timeout=60):
        self._url = url
        self._username = username
        self._password = password
        self._secure = secure
        self._timeout = timeout
        self._config = config

        requests.packages.urllib3.disable_warnings()
        ls = cobra.mit.session.LoginSession(self._url, self._username, self._password, secure=self._secure,
                                            timeout=self._timeout)
        self._md = cobra.mit.access.MoDirectory(ls)
        self._md.login()


    def create_pod(self):

        existing_pod_id = [int(pod.podId) for pod in self._md.lookupByClass('fabricSetupP')]

        for pod in self._config.pod_list():
            if pod['id'] in existing_pod_id:
                logger1.warning('Pod {0} already exist. Skipping...'.format(pod['id']))

            else:
                logger1.warning('Creating pod {0} with TEP Pool {1}'.format(pod['id'], pod['tep']))

                polUni = cobra.model.pol.Uni('')
                ctrlrInst = cobra.model.ctrlr.Inst(polUni)
                fabricSetupPol = cobra.model.fabric.SetupPol(ctrlrInst)
                fabricSetupP = cobra.model.fabric.SetupP(fabricSetupPol, podId=pod['id'], tepPool=pod['tep'])

                logger1.debug(toXMLStr(fabricSetupPol))
                c = cobra.mit.request.ConfigRequest()
                c.addMo(fabricSetupPol)
                self._md.commit(c)


    def create_spine(self):

        existing_spine_id = [int(id.nodeId) for id in self._md.lookupByClass('fabricNodeIdentP')]

        for pod in self._config.pod_list():
            id = pod['id']

            for spine in pod['spines']:
                if spine['id'] in existing_spine_id:
                    logger1.warning('Spine {0} already exist. Skipping...'.format(spine['id']))

                elif 'sn' not in spine.keys():
                    logger1.warning('No SN provided for spine {0}. Skipping...'.format(spine['id']))

                else:
                    logger1.warning('Creating new spine with id {0}'.format(spine['id']))

                    polUni = cobra.model.pol.Uni('')
                    ctrlrInst = cobra.model.ctrlr.Inst(polUni)
                    fabricNodeIdentPol = cobra.model.fabric.NodeIdentPol(ctrlrInst)
                    fabricNodeIdentP = cobra.model.fabric.NodeIdentP(fabricNodeIdentPol, podId=id, nodeId=spine['id'],
                                                                     name=spine['name'], role='spine', serial=spine['sn'])

                    logger1.debug(toXMLStr(fabricNodeIdentPol))
                    c = cobra.mit.request.ConfigRequest()
                    c.addMo(fabricNodeIdentPol)
                    self._md.commit(c)


    def create_external_connection_profile(self):

        logger1.warning('Creating external connectivity profile')

        polUni = cobra.model.pol.Uni('')
        fvTenant = cobra.model.fv.Tenant(polUni, 'infra')
        fvFabricExtConnP = cobra.model.fv.FabricExtConnP(fvTenant, rt=self._config.multipod['community'], name='Fabric_Ext_Conn_Prof', siteId='0', id='1')
        l3extFabricExtRoutingP = cobra.model.l3ext.FabricExtRoutingP(fvFabricExtConnP, name='Fabric_Ext_Routing_Prof')

        for el in self._config.multipod['subnets']:
            l3extSubnet = cobra.model.l3ext.Subnet(l3extFabricExtRoutingP, ip=el)

        for el in self._config.multipod['dataplane_tep']:
            fvPodConnP = cobra.model.fv.PodConnP(fvFabricExtConnP, id=el['pod-id'])
            fvIp = cobra.model.fv.Ip(fvPodConnP, addr=el['ip'])

        fvPeeringP = cobra.model.fv.PeeringP(fvFabricExtConnP, type='automatic_with_full_mesh')

        logger1.debug(toXMLStr(fvTenant))
        c = cobra.mit.request.ConfigRequest()
        c.addMo(fvTenant)
        self._md.commit(c)


    def create_l3_out(self):

        logger1.warning('Creating an L3Out on the spines for the connectivity towards the IPN')

        topMo = cobra.model.pol.Uni('')
        fvTenant = cobra.model.fv.Tenant(topMo, name='infra')
        l3extOut = cobra.model.l3ext.Out(fvTenant, name='multipod')
        ospfExtP = cobra.model.ospf.ExtP(l3extOut, areaCtrl='redistribute,summary', areaId=self._config.multipod['ospf']['area_id'],
                                         areaType=self._config.multipod['ospf']['type'], areaCost='1')
        l3extRsEctx = cobra.model.l3ext.RsEctx(l3extOut, tnFvCtxName='overlay-1')
        l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, name='bLeaf')

        l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, name='portIf')
        ospfIfP = cobra.model.ospf.IfP(l3extLIfP, authKeyId='1', authType='none')
        ospfRsIfPol = cobra.model.ospf.RsIfPol(ospfIfP, tnOspfIfPolName='ospfIfPol')

        for pod in self._config.pod_list():
            id = pod['id']

            for spine in pod['spines']:
                l3extRsNodeL3OutAtt = cobra.model.l3ext.RsNodeL3OutAtt(l3extLNodeP, rtrIdLoopBack='yes', rtrId=spine['rid'],
                                                               tDn='topology/pod-' + id + '/node-' + spine['id'])

                for intf in spine['intf']:
                    l3extRsPathL3OutAtt = cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, ifInstT='sub-interface',
                                                                           addr=intf['ip'], encap='vlan-4',
                                                                           tDn='topology/pod-' + id + '/node-' + spine['id'] + '/pathep-[eth' + intf['id'] + ']')


        l3extInstP = cobra.model.l3ext.InstP(l3extOut, matchT='AtleastOne', name='ipnInstP')

        logger1.debug(toXMLStr(topMo))
        c = cobra.mit.request.ConfigRequest()
        c.addMo(topMo)
        self._md.commit(c)


class Configuration:
    def __init__(self, filename):
        self._config = dict()

        with open(filename, 'r') as yaml_file:
            logger1.debug('Loading configuration')
            self._config = yaml.load(yaml_file)
            logger1.debug('Configuraiton loaded')


    def pod_list(self):
        return self._config['pods']

    @property
    def multipod(self):
        return self._config['multipod']


def main():
    Cfg = Configuration('config.yml')
    ACI = AciMo(url='https://10.32.72.31', username='admin', password='ADVISE4ever!', config=Cfg)
    ACI.create_pod()
    ACI.create_spine()
    ACI.create_external_connection_profile()



if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()