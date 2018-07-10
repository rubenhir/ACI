import logging
import requests
import json
import yaml
import re
import json


class Request:
    def __init__(self, url, auth_cookie):
        self._url = url
        self._auth_cookie = auth_cookie
        self._tree = {'topSystem': {'children': []}}
        self._second_leaf = False

        '''
        tree_element = {parent_key : { 
                        'children' : [tree_element1, tree_element2... tree_element<x>], 
                        'attributes': {key1 ; value1, key2: value2... key<x>: value<x>}}
        with:
            parent_key, key<x>, value<x>: string
            tree_element<x>: tree_element
            children, attribute: token
            '''


    def _build_tree(self, dn_list, attributes):

        '''
        convert dn_list into a tree structure
        dn /name1/name2/... /namex
        dn_list: ['', name1, name2, ... namex]
        attributes: {key1: value1, .... keyx: valuex}
        tree: {name1: {
                'children': [tree]}
                'attributes": attributes}
        '''


        if len(dn_list) == 0:
            return {'attributes' : attributes }

        else:
            tree = self._build_tree(dn_list[1:], attributes)
            tree = {'children' : [{dn_list[0] : tree}]}

            return (tree)


    def _merge_tree(self, tree1, tree2):

        parent_key = tree2.keys()[0]
        tree2_child_key = tree2[parent_key].keys()[0]
        tree1_children_keys = tree1[parent_key].keys()


        if tree2_child_key == 'children' and 'children' in tree1_children_keys:

            '''
            tree1 = {value: {children: [tree1... treex]} 
            or tree1 = {value: {attributes: {}, children: [tree1... treex]}
            tree2 = {value: {children: [tree]}
            '''

            tree1_children = tree1[parent_key]['children']
            tree1_child_tree = None
            tree2_child_tree = tree2[parent_key]['children'][0]

            for tree in tree1_children:
                if tree.keys()[0] == tree2_child_tree.keys()[0]:
                    tree1_child_tree = tree

            if tree1_child_tree:
                # tree1 has a child tree that match tree2_child_tree
                self._merge_tree(tree, tree2_child_tree)

            else:
                tree1[parent_key]['children'].append(tree2_child_tree)


        elif tree2_child_key == 'children':
            '''            
            tree1 = {value: {attributes: {key1: value1,... keyx: valuex}}}
            tree2 = {value: {children: [tree1... treex]}
            '''

            tree2_children = tree2[parent_key]['children']
            tree1[parent_key]['children'] = tree2_children


        elif tree2_child_key == 'attributes':
            '''
            tree1 = {value: {children: [tree1...treex]}
            tree2 = {value: {attributes: {key1: value1, ... keyx: valuex}}}
            '''

            if 'attributes' in tree1[parent_key].keys():
                self._second_leaf = True
                return

            else:
                tree2_leaf = tree2[parent_key]['attributes']
                tree1[parent_key][tree2_child_key] = tree2_leaf


        if self._second_leaf:
            self._second_leaf = False
            tree1[parent_key]['children'].append(tree2[parent_key]['children'][0])


    def build_payload(self, dn, **kwargs):

        dn_list = dn.split('/')

        if dn_list[0] == '':
            new_tree = self._build_tree(dn_list[1:], kwargs)

        else:
            new_tree = self._build_tree(dn_list, kwargs)

        self._merge_tree(self._tree, new_tree['children'][0])


    def apply_change(self):

        logger1.debug(self._tree)

        response = requests.request("POST", self._url + "/api/mo/sys.json", data=json.dumps(self._tree), cookies=self._auth_cookie)
        logger1.warning(response.status_code)

        if response.status_code != 200:
            logger1.debug(response.json())


    def __str__(self):
        return str(self._tree)


class NxAPI:
    def __init__(self, url, username, password):
        self._url = url
        self._username = username
        self._password = password
        self._auth_cookie = ''

    def login(self):
        logger1.warning('Trying to login to {0}'.format(self._url))

        payload = {'aaaUser': {'attributes': {'name': self._username, 'pwd': self._password}}}
        logger1.debug(payload)

        response = requests.request("POST", self._url + "/api/aaaLogin.json", data=json.dumps(payload))
        logger1.warning(response.status_code)

        if response.status_code == requests.codes.ok:
            data = json.loads(response.text)['imdata'][0]
            token = str(data['aaaLogin']['attributes']['token'])
            self._auth_cookie = {"APIC-cookie": token}


    def logout(self):
        logger1.warning('Trying to logout'.format(self._url))

        payload = {'aaaUser': {'attributes': {'name': self._username}}}
        logger1.debug(payload)

        response = requests.request("POST", self._url + "/api/aaaLogout.json", data=json.dumps(payload),cookies=self._auth_cookie)
        logger1.warning(response.status_code)


    def new_request(self):
        request = Request(self._url, self._auth_cookie)

        return request


class TemplateParser:
    def __init__(self, filename):
        self._config = dict()

        with open(filename, 'r') as yaml_file:
            logger1.debug('Loading configuration')
            self._config = yaml.load(yaml_file)
            logger1.debug('Configuration loaded')

    def get_router_list(self):
        return self._config['routers'].keys()

    def get_router_config(self, ip):
        router_config = self._config['routers'][ip].copy()

        for key in self._config['all_routers'].keys():
            if key not in router_config.keys():
                router_config[key] = self._config['all_routers'][key]

            else:
                if isinstance(self._config['all_routers'][key], dict):
                    router_config[key].update(self._config['all_routers'][key])

                elif isinstance(self._config['all_routers'][key], list):
                    router_config[key] += self._config['all_routers'][key]

        return router_config


class ConfigGen:
    def __init__(self, router_template, router):
        self._router_template = router_template
        self._router = router


    def _enable_feature(self):
        logger1.warning('Enabling feature....')

        request = self._router.new_request()

        for feature in self._router_template['features']:
            request.build_payload('/topSystem/fmEntity/fm' + feature.lower().title(), adminSt='enabled')

        request.apply_change()


    def _enable_pim(self):
        logger1.warning('Configuring pim...')

        request = self._router.new_request()
        request.build_payload('/topSystem/pimEntity/pimInst/pimDom', name='default')

        for grp in self._router_template['pim']['group-list']:
            request.build_payload('/topSystem/pimEntity/pimInst/pimDom/pimStaticRPP/pimStaticRP', addr=self._router_template['pim']['rp'])
            request.build_payload('/topSystem/pimEntity/pimInst/pimDom/pimStaticRPP/pimStaticRP/pimRPGrpList', override='no', bidir='yes', grpListName=grp)

        request.apply_change()


    def _enable_ospf(self):

        if 'id' in self._router_template['ospf'].keys():
            ospf_router_id = self._router_template['ospf']['id']
        else:
            ospf_router_id = 1

        logger1.warning('Configuring ospf router id {0}...'.format(ospf_router_id))

        request = self._router.new_request()
        request.build_payload('/topSystem/ospfEntity/ospfInst', name=str(ospf_router_id))
        request.build_payload('/topSystem/ospfEntity/ospfInst/ospfDom', adjChangeLogLevel='brief', name='default', rtrId=ospf_router_id, ctrl='bfd')

        request.apply_change()


    def _configure_interfaces(self, config):
        logger1.warning('Configuring interfaces')

        for intf in sorted(config.keys()):

            if intf == 'all':
                pass

            else:
                logger1.warning('Configuring {0}'.format(intf))

                intf_config = config[intf].copy()

                if 'all' in config.keys():
                    intf_config.update(config['all'])

                feature_list = list()

                if 'po' in intf_config.keys():
                    po_id = intf_config['po']
                    int_id = re.search('[0-9]+/[0-9]+', intf).group()

                    feature_list = list()
                    feature_list.append({'pcAggrIf': {'attributes': {'pcMode': 'on', 'id': 'po{0}'.format(po_id), 'isExplicit': 'yes'},'children': [{'pcRsMbrIfs': {'attributes': {'tDn': 'sys/intf/phys-[eth{0}]'.format(int_id)}}},{'pcShadowAggrIf': {'attributes': {'id': 'po{0}'.format(po_id)}}}]}})
                    payload = {'topSystem': {'children': [{'interfaceEntity': {'children': feature_list }}]}}
                    logger1.debug(payload)

                    response = requests.request("POST", self._url + "/api/mo/sys.json", data=json.dumps(payload),cookies=self._auth_cookie)
                    logger1.debug(response.status_code)

                    if response.status_code != 200:
                        logger1.debug(response.json())


                if 'ip' in intf_config.keys():

                    if re.search('Loopback[0-9]+', intf, re.IGNORECASE):
                        pass

                    elif re.search('Port-channel[0-9]+', intf, re.IGNORECASE):
                        intf_id = 'po' + re.search('[0-9]+', intf).group()

                        interfaceEntityList = [{'pcAggrIf': {
                            'attributes': {'layer': 'Layer3', 'id': intf_id, 'userCfgdFlags': 'admin_layer'}}}]
                        interfaceEntity = {'interfaceEntity': {'children': interfaceEntityList}}

                    elif re.search('Ethernet[0-9]+', intf, re.IGNORECASE):
                        intf_id = 'eth' + re.search('[0-9]+/[0-9]+', intf).group()

                        interfaceEntityList = [{'l1PhysIf': {
                            'attributes': {'layer': 'Layer3', 'id': intf_id, 'userCfgdFlags': 'admin_layer'}}}]
                        interfaceEntity = {'interfaceEntity': {'children': interfaceEntityList}}


                    topSystemList = [interfaceEntity]
                    topSystem = {'topSystem': {'children': topSystemList}}
                    logger1.debug(topSystem)

                    response = requests.request("POST", self._url + "/api/mo/sys.json", data=json.dumps(topSystem),cookies=self._auth_cookie)
                    logger1.debug(response.status_code)

                    if response.status_code != 200:
                        logger1.debug(response.json())


    def apply_configuration(self):

        if 'features' in self._router_template.keys():
            self._enable_feature()

        if 'pim' in self._router_template.keys():
            self._enable_pim()

        if 'ospf' in self._router_template.keys():
            self._enable_ospf()

        '''
        if 'interfaces' in config.keys():
            self._configure_interfaces(config['interfaces'])
        '''


def main():

    '''
    my_change = Request('toto', 'toto')
    my_change.build_payload('topSystem/pimEntity/pimInst/pimDom/pimStaticRPP/pimStaticRP', addr='172.18.1.22/32')
    my_change.build_payload('topSystem/pimEntity/pimInst/pimDom', name='default')
    my_change.build_payload('topSystem/pimEntity/pimInst/pimDom/pimStaticRPP/pimStaticRP/pimRPGrpList', override='no', bidir='yes', grpListName='239.0.0.0/8')
    my_change.build_payload('topSystem/pimEntity/pimInst/pimDom/pimStaticRPP/pimStaticRP/pimRPGrpList', override='no', bidir='yes', grpListName='225.0.0.0/8')
    print(my_change)
    '''

    cfg = TemplateParser('IPN.yml')


    for router in cfg.get_router_list():
        logger1.warning('Applying config to {0}'.format(router))
        router1 = NxAPI('http://' + router, 'admin', 'ADVISE4ever!')
        router1.login()

        config_gen = ConfigGen(cfg.get_router_config(router), router1)
        config_gen.apply_configuration()

        router1.logout()


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()