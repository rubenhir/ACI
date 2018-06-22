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
import cobra.model.infra
import cobra.model.fvns
import cobra.model.fv
import cobra.model.l3ext
import cobra.model.ospf

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

        for pod in self._config.pod_list:
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

        for pod in self._config.pod_list:
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

        logger1.warning('Provisining L3Out {0}'.format(self._config.policy_name['l3out']))

        topMo = cobra.model.pol.Uni('')
        fvTenant = cobra.model.fv.Tenant(topMo, name='infra')
        l3extOut = cobra.model.l3ext.Out(fvTenant, name=self._config.policy_name['l3out'])
        ospfExtP = cobra.model.ospf.ExtP(l3extOut, areaCtrl='redistribute,summary', areaId=self._config.ospf['area_id'], areaType=self._config.ospf['type'], areaCost='1')
        l3extRsEctx = cobra.model.l3ext.RsEctx(l3extOut, tnFvCtxName='overlay-1')
        l3extRsL3DomAtt = cobra.model.l3ext.RsL3DomAtt(l3extOut, tDn='uni/l3dom-' + self._config.policy_name['domain'])
        l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, name='Spines')

        l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, name='Interfaces')
        ospfIfP = cobra.model.ospf.IfP(l3extLIfP, authKeyId='1', authType='none')
        ospfIfPol = cobra.model.ospf.IfPol(fvTenant, nwT='p2p', ownerKey='', name='ospf_policy', ctrl='advert-subnet,bfd')
        ospfRsIfPol = cobra.model.ospf.RsIfPol(ospfIfP, tnOspfIfPolName='ospf_interface_policy')

        for pod in self._config.pod_list:
            id = pod['id']

            for spine in pod['spines']:
                tDn = 'topology/pod-' + str(id) + '/node-' + str(spine['id'])
                l3extRsNodeL3OutAtt = cobra.model.l3ext.RsNodeL3OutAtt(l3extLNodeP, rtrIdLoopBack='yes', rtrId=spine['rid'], tDn=tDn)

                for intf in spine['intf']:
                    tDn = 'topology/pod-' + str(id) + '/node-' + str(spine['id']) + '/pathep-[eth' + str(intf['id'] + ']')
                    l3extRsPathL3OutAtt = cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, ifInstT='sub-interface', addr=intf['ip'], encap='vlan-4', tDn=tDn)

        l3extInstP = cobra.model.l3ext.InstP(l3extOut, matchT='AtleastOne', name='ipnInstP')

        logger1.debug(toXMLStr(topMo))
        c = cobra.mit.request.ConfigRequest()
        c.addMo(topMo)
        self._md.commit(c)


    def create_access_policies(self):

        polUni = cobra.model.pol.Uni('')
        infraInfra = cobra.model.infra.Infra(polUni)
        infraFuncP = cobra.model.infra.FuncP(infraInfra)

        logger1.warning('Provisioning vlan pool {0}'.format(self._config.policy_name['vlan_pool']))
        fvnsVlanInstP = cobra.model.fvns.VlanInstP(infraInfra, name=self._config.policy_name['vlan_pool'], allocMode='static')
        fvnsEncapBlk = cobra.model.fvns.EncapBlk(fvnsVlanInstP, from_='vlan-4', role='external', allocMode='inherit', to='vlan-4')
        logger1.debug(toXMLStr(fvnsVlanInstP))

        logger1.warning('Provisioning domain {0}'.format(self._config.policy_name['domain']))
        l3extDomP = cobra.model.l3ext.DomP(polUni, name=self._config.policy_name['domain'])
        infraRsVlanNs = cobra.model.infra.RsVlanNs(l3extDomP, tDn=fvnsVlanInstP.dn)
        logger1.debug(toXMLStr(l3extDomP))

        logger1.warning('Provisioning aep {0}'.format(self._config.policy_name['aep']))
        infraAttEntityP = cobra.model.infra.AttEntityP(infraInfra, name=self._config.policy_name['aep'])
        infraRsDomP = cobra.model.infra.RsDomP(infraAttEntityP, tDn=l3extDomP.dn)
        logger1.debug(toXMLStr(infraAttEntityP))

        logger1.warning('Provisining policy-group {0}'.format(self._config.policy_name['pgr']))
        infraSpAccPortGrp = cobra.model.infra.SpAccPortGrp(infraFuncP, name=self._config.policy_name['pgr'])
        infraRsAttEntP = cobra.model.infra.RsAttEntP(infraSpAccPortGrp, tDn=infraAttEntityP.dn)
        logger1.debug(toXMLStr(infraSpAccPortGrp))

        for pod in self._config.pod_list:
            for spine in pod['spines']:
                logger1.warning('Creating interface profile {0}'.format(spine['name']))
                infraSpAccPortP = cobra.model.infra.SpAccPortP(infraInfra, name=spine['name'])

                for intf in spine['intf']:
                    intf_name = 'E' + intf['id'].split('/')[0] + '_' + intf['id'].split('/')[1]
                    infraSHPortS = cobra.model.infra.SHPortS(infraSpAccPortP, name=intf_name, type='range')
                    infraRsSpAccGrp = cobra.model.infra.RsSpAccGrp(infraSHPortS, tDn=infraSpAccPortGrp.dn)
                    infraPortBlk = cobra.model.infra.PortBlk(infraSHPortS, name='Block2', fromCard= intf['id'].split('/')[0], fromPort=intf['id'].split('/')[1],
                                                             toCard=intf['id'].split('/')[0], toPort=intf['id'].split('/')[1])
                    logger1.debug(toXMLStr(infraSHPortS))

                logger1.warning('Provising switch profile for {0}'.format(spine['name']))
                infraSpineP = cobra.model.infra.SpineP(infraInfra, name=spine['name'])
                infraSpineS = cobra.model.infra.SpineS(infraSpineP, name=spine['name'], type='range')
                infraNodeBlk = cobra.model.infra.NodeBlk(infraSpineS, from_=spine['id'], to_=spine['id'], name='block1')
                infraRsSpAccPortP = cobra.model.infra.RsSpAccPortP(infraSpineP, tDn=infraSpAccPortP.dn)
                logger1.debug(toXMLStr(infraSpineP))

        c = cobra.mit.request.ConfigRequest()
        c.addMo(polUni)
        self._md.commit(c)


class Configuration:
    def __init__(self, filename):
        self._config = dict()

        with open(filename, 'r') as yaml_file:
            logger1.debug('Loading configuration')
            self._config = yaml.load(yaml_file)
            logger1.debug('Configuraiton loaded')

    @property
    def pod_list(self):
        return self._config['pods']

    @property
    def multipod(self):
        return self._config['multipod']

    @property
    def policy_name(self):
        return self._config['multipod']['policy_name']

    @property
    def ospf(self):
        return self._config['multipod']['ospf']


def main():
    Cfg = Configuration('config.yml')
    ACI = AciMo(url='https://10.32.72.31', username='admin', password='ADVISE4ever!', config=Cfg)
    ACI.create_pod()
    ACI.create_spine()
    ACI.create_external_connection_profile()
    ACI.create_access_policies()
    ACI.create_l3_out()


if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()