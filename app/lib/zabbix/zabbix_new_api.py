#!/usr/bin/env python
# coding=utf-8
import ConfigParser
import json
import sys
import traceback
from os import path
import requests
from flask import current_app

# import opt_excel

reload(sys)
sys.setdefaultencoding("utf-8")

BASE_DIR = path.dirname(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
sys.path.append(BASE_DIR)


class zabbix_ops:
    def __init__(self):
        self.url = "http://z.zhaogangren.com/api_jsonrpc.php"
        self.header = {"Content-Type": "application/json"}
        self.authID = self.user_login()

    def user_login(self):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    "user": "admin",
                    "password": "Skt6edg.gangfu.int"
                },
                "id": 0
            })
        request = requests.post(self.url, data=data, headers=self.header)
        response = json.loads(request.content)
        authID = response['result']
        return authID

    def get_trigger(self):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "trigger.get",
                "params": {
                    "monitored": 1,
                    "only_true": 1,
                    "selectLastEvent": "extend",
                    "selectHosts": "extend",
                    "sortfield": "lastchange",
                    "sortorder": "DESC",
                    "limit": 20

                    # "output": "extend",
                    # "selectFunctions": "extend",
                    # "filter": {
                    #     "value": 1
                    # },
                    # "value": 1,
                    # "select_acknowledges": "extend",
                    # "objectids": "13926",
                    # "sortfield": ["clock", "eventid"],
                    # "sortorder": "DESC"
                },

                "auth": self.authID,
                "id": 1
            })
        result = requests.post(self.url, data=data, headers=self.header)
        response = json.loads(result.content)
        res = response['result']

        return res

    def get_hostid_by_hostip(self, hostip=""):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": ["hostid", "name", "status", "host"],
                    # "output":"extend",
                    "filter": {"ip": [hostip]}
                    # "selectInterfaces":["interfaces", "ip"]
                },
                "auth": self.authID,
                "id": 1
            })
        result = requests.post(self.url, data=data, headers=self.header)
        response = json.loads(result.content)
        res = response['result']
        if (res != 0) and (len(res) != 0):
            host_id = response['result'][0]['hostid']
        else:
            print "Can not find the vserver's hostid, Pls check! %s" % hostip
            return 0
        return host_id

    def delete_host_by_ip(self, hostip):
        hostid = self.get_hostid_by_hostip(hostip)
        if hostid == 0:
            print "\x1b[1;31mhost_get error please check it"
            return False
        # print hostid
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "host.delete",
                "params": [hostid],
                "auth": self.authID,
                "id": 1
            })
        # res = self.get_data(data)['result']
        result = requests.post(self.url, data, headers=self.header)
        response = json.loads(result.content)
        try:
            res = response['result']
            if 'hostids' in res.keys():
                print "zabbix中删除成功: %s" % hostip
                return True
            else:
                print "zabbix中删除失败: %s" % hostip
                return False
        except:
            print "删除主机异常，可能是主机不存在!"
            return False

    def get_itemid_by_hostid(self, hostid="", zabbix_key="cpu"):
        itemid_list = {}
        if hostid == -1:
            print "Hostid is bad, the job can not get itemid."
            return itemid_list

        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": "extend",
                    "hostids": hostid,
                    "search": {
                        "key_": zabbix_key
                    },
                    "sortfield": "name"
                },
                "auth": self.authID,
                "id": 1
            })
        result = requests.post(self.url, data, headers=self.header)
        response = json.loads(result.content)
        res = response['result']
        if (res != 0) and (len(res) != 0):
            for re in res:
                if zabbix_key == 'vfs.fs.size':
                    if "percentage" in re['name']:
                        itemid_list[re['itemid']] = re['key_']
                else:
                    itemid_list[re['itemid']] = re['name']

        return itemid_list

    def get_history_by_itemid(self, itemid_dict="", history_id=3):
        history_dict = {}
        if len(itemid_dict) == 0:
            print "itemid lists is None, Don't go on to do."
            return history_dict
        else:
            itemid_list = itemid_dict.keys()
        for itemid in itemid_list:
            history_dict[itemid] = []
        count = len(itemid_list) * 20
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "history.get",
                "params": {
                    "output": "extend",
                    "history": history_id,
                    "itemids": itemid_list,
                    "sortfield": "clock",
                    "sortorder": "DESC",
                    "limit": count
                },
                "auth": self.authID,
                "id": 1
            })

        result = requests.post(self.url, data, headers=self.header)
        response = json.loads(result.content)
        res = response['result']
        if (res != 0) and (len(res) != 0):
            # 将每个itemid的value放在同一个字典里面
            for value in res:
                history_dict[value['itemid']].append(value['value'])
        else:
            print '\t', "Get History Error or cannot find this value,please check !"
            return []
        # print history_dict

        return history_dict

    def hostinterface_create_by_hostid(self, hostid, hostip, port, type):
        """
        Interface type.

            Possible values are:
            1 - agent;
            2 - SNMP;
            3 - IPMI;
            4 - JMX.
        """
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "host.massadd",
                "params": {
                    "hosts": [
                        {
                            "hostid": hostid
                        }
                    ],
                    "interfaces": [
                        {
                            "dns": "",
                            "ip": hostip,
                            "main": 1,
                            "port": port,
                            "type": type,
                            "useip": 1
                        }
                    ]

                },
                "auth": self.authID,
                "id": 1
            }
        )
        try:
            result = requests.post(self.url, data, headers=self.header)
            response = json.loads(result.content)
            hostids = response['result']['hostids']
        except:
            print response['error']
            return []
        # hostids = response['result']['hostids']
        # print response
        return hostids

    def get_templateid_by_templatename(self, templatename):
        data = (
            {
                "jsonrpc": "2.0",
                "method": "template.get",
                "params": {
                    "output": "extend",
                    "filter": {
                        "name": templatename
                    }
                },
                "auth": self.authID,
                "id": 1
            }
        )
        result = requests.post(self.url, json.dumps(data), headers=self.header)
        response = json.loads(result.content)
        templateid = response['result'][0]['templateid']
        return templateid

    def get_groupid_by_groupname(self, groupname):
        data = (
            {
                "jsonrpc": "2.0",
                "method": "hostgroup.get",
                "params": {
                    "output": "extend",
                    "filter": {
                        "name": [
                            groupname
                        ]
                    }
                },
                "auth": self.authID,
                "id": 1
            }
        )
        result = requests.post(self.url, json.dumps(data), headers=self.header)
        response = json.loads(result.content)
        groupid = response['result'][0]['groupid']
        return groupid

    def update_host_by_hostid(self, hostid_list, group_id, template_id):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "host.massadd",
                "params": {
                    "hosts": hostid_list,
                    "groups": [{"groupid": group_id}, {"groupid": 36}],
                    "templates": [{"templateid": template_id}]
                },
                "auth": self.authID,
                "id": 1
            }
        )
        try:
            result = requests.post(self.url, data, headers=self.header)
            response = json.loads(result.content)
            hostids = response['result']['hostids']
        except:
            print "异常退出!"

        return hostids


class zabbix_login:
    def __init__(self, env):
        # configure parameter
        conf = ConfigParser.ConfigParser()
        conf_path = path.join(BASE_DIR, "configsss.ini")
        conf.read(conf_path)
        self.headers = {"Content-Type": "application/json"}
        self.server = conf.get(env, 'server')
        self.username = conf.get(env, 'username')
        self.password = conf.get(env, 'password')
        self.url = "http://%s/api_jsonrpc.php" % self.server
        self.authID = self.user_login()

    def user_login(self):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    "user": self.username,
                    "password": self.password
                },
                "id": 0
            })
        request = requests.post(self.url, data=data, headers=self.headers)
        response = json.loads(request.content)
        authID = response['result']
        return authID


class host:
    def __init__(self, env):
        zl = zabbix_login(env)
        self.url = zl.url
        self.authID = zl.user_login()
        self.headers = zl.headers

    def create(self, host, group_id, ip, template_id):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "host.create",
                "params": {
                    "host": host,
                    "interfaces": [
                        {
                            "type": 1,
                            "main": 1,
                            "useip": 1,
                            "ip": ip,
                            "dns": "",
                            "port": "10050"
                        }
                    ],
                    "groups": [
                        {
                            "groupid": group_id
                        }
                    ],
                    "templates": [
                        {
                            "templateid": template_id
                        }
                    ],
                },
                "auth": self.authID,
                "id": 1
            })
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                host_res = response['result']
            print "主机创建成功:\t%s" % host_res
        except Exception, e:
            message = u'创建主机（Create host failure）失败!'
            print message, e
            traceback.print_exc()
            return False
        return host_res

    def delete(self, *args):
        json_data = {
            "jsonrpc": "2.0",
            "method": "host.delete",
            # "params": [],
            "auth": self.authID,
            "id": 1
        }
        json_data['params'] = list(args)

        data = json.dumps(json_data)
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                host_res = response['result']
            print "主机删除成功:\t%s" % host_res
        except Exception, e:
            message = u'删除主机（Delete host failure）失败!'
            print message, e
            traceback.print_exc()
            return False
        return host_res

    def get(self, **kwargs):
        host_res = []
        json_data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": "extend",
                # "filter": {
                #     # "host": [host]
                # }
            },
            "auth": self.authID,
            "id": 1
        }
        for k, v in kwargs.items():
            json_data['params'][k] = v

        data = json.dumps(json_data)
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                host_res = response['result']
                # print "主机获取信息成功:\t%s" % host_res
        except Exception, e:
            message = u'获取主机（Get host failure）失败!'
            print message, e
            traceback.print_exc()
            return False
        return host_res

    def update(self, **kwargs):
        json_data = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {},
            "auth": self.authID,
            "id": 1
        }

        for k, v in kwargs.items():
            json_data['params'][k] = v

        data = json.dumps(json_data)

        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                host_res = response['result']
            print "主机信息更新成功:\t%s" % host_res
        except Exception, e:
            message = u'更新主机（Update host failure）失败!'
            print message, e
            traceback.print_exc()
            return False
        return host_res


class hostgroup:
    def __init__(self, env):
        zl = zabbix_login(env)
        self.url = zl.url
        self.authID = zl.user_login()
        self.headers = zl.headers

    def create(self, name=""):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "hostgroup.create",
                "params": {
                    "name": name
                },
                "auth": self.authID,
                "id": 1
            })
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                group_id = response['result']['groupids']
            print "主机组创建成功，ID是%s" % group_id
        except Exception, e:
            message = u'创建主机组（hostgroup）失败!'
            print message, e
            traceback.print_exc()
            return False
        return group_id

    def delete(self, ids=""):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "hostgroup.delete",
                "params": [
                    ids
                ],
                "auth": self.authID,
                "id": 1
            })
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                group_id = response['result']['groupids']
            print "主机组删除成功，ID是%s" % group_id
        except Exception, e:
            message = u'删除主机组（Delete hostgroup failure）失败!'
            print message
            return False
        return group_id

    def get(self, **kwargs):
        group_info = []
        json_data = {
            "jsonrpc": "2.0",
            "method": "hostgroup.get",
            "params": {
                "output": "extend",
                # "filter": {
                #     "name":[name]
                # }
            },
            "auth": self.authID,
            "id": 1
        }
        # 解析参数kwargs
        for k, v in kwargs.items():
            json_data['params'][k] = v

        data = json.dumps(json_data)
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                group_info = response['result']
                # print "主机组获取信息成功:\t%s" % group_info
        except Exception, e:
            message = u'获取主机组信息（Get hostgroup failure）失败!'
            print message
            return False
        return group_info

    def update(self, groupid, groupname):
        data = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "hostgroup.update",
                "params": {
                    "groupid": groupid,
                    "name": groupname
                },
                "auth": self.authID,
                "id": 1
            })
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                host_info = response['result']
            print "主机组更新成功:\t%s" % host_info
        except Exception, e:
            message = u'更新主机组（Update hostgroup failure）失败!'
            print message
            return False
        return host_info


class template:
    def __init__(self, env):
        zl = zabbix_login(env)
        self.url = zl.url
        self.authID = zl.user_login()
        self.headers = zl.headers

    def get(self, **kwargs):
        group_info = []
        json_data = {
            "jsonrpc": "2.0",
            "method": "template.get",
            "params": {
                "output": "extend",
                # "filter": {
                #     "name":[name]
                # }
            },
            "auth": self.authID,
            "id": 1
        }
        # 解析参数kwargs
        for k, v in kwargs.items():
            json_data['params'][k] = v

        data = json.dumps(json_data)
        try:
            result = requests.post(self.url, data=data, headers=self.headers)
            response = json.loads(result.content)
            res = response['result']
            if (res != 0) and (len(res) != 0):
                group_info = response['result']
                # print "模板获取信息成功:\t%s" % group_info
        except Exception, e:
            message = u'获取模板信息（Get template failure）失败!'
            print message
            return False
        return group_info


def update_host(hostip, method='disable'):
    """
    status: 0——enable   1——disable
    :param hostip:
    :param metod: delete \ enable \ disable
    :return:
    """
    sub_add = hostip.split('.')
    if sub_add[1] in ['80', '90']:
        env = 'zabbixprd'
    elif sub_add[1] == '0' and sub_add[2] in ['0', '1', '3', '60']:
        env = 'zabbixprd'
    else:
        env = 'zabbixnonprd'
    try:
        # 获取hostid
        hostinstance = host(env)
        kwargs = {
            "filter": {"ip": [hostip]}
        }
        host_response = hostinstance.get(**kwargs)
        if "hostid" in host_response[0]:
            hostid = host_response[0]['hostid']
        else:
            print "host_get error please check it"
            return False

        if method == 'delete':
            response = hostinstance.delete(int(hostid))

            if 'hostids' in response:
                message = "zabbix中删除成功: %s" % hostip
            else:
                message = "zabbix中删除失败: %s" % hostip
        elif method == 'enable':
            args = {
                "hostid": hostid,
                "status": 0
            }
            hostinstance.update(**args)

            message = u'主机%s监控开启成功' % hostip
        elif method == 'disable':
            args = {
                "hostid": hostid,
                "status": 1
            }
            hostinstance.update(**args)

            message = u'主机%s监控禁用成功' % hostip
    except Exception, e:
        message = "删除主机异常，可能是主机不存在!"
        print message
        current_app.logger.error(traceback.format_exc())
        return False
    return True


def get_template_by_ip(env):
    hostinstance = host(env)
    templateinstance = template(env)
    try:
        host_list = opt_excel.main()
        if len(host_list) == 0:
            return False
        for hostip in host_list:
            temp_list = []
            # 获取hostid
            kwargs = {
                "filter": {"ip": [hostip]}
            }

            host_response = hostinstance.get(**kwargs)
            if len(host_response) == 0:
                print u"%s\t没有监控" % hostip
                continue
            if "hostid" in host_response[0]:
                hostid = host_response[0]['hostid']
                if hostid is not None:
                    twargs = {
                        "hostids": [hostid]
                    }
                    template_response = templateinstance.get(**twargs)
                    if len(template_response) == 0:
                        print u"%s\t没有关联模板" % hostip
                        continue
                    else:
                        for tem in template_response:
                            temp_list.append(tem['name'])
                        print u"%s\t%s" % (hostip, " ".join(temp_list))
    except Exception, e:
        message = u"删除主机异常，可能是主机不存在!"
        print message, e
        traceback.print_exc()
        return False
    return True


def get_group_by_ip(env):
    hostinstance = host(env)
    groupinstance = hostgroup(env)
    try:
        host_list = opt_excel.main()
        if len(host_list) == 0:
            return False
        for hostip in host_list:
            temp_list = []
            # 获取hostid
            kwargs = {
                "filter": {"ip": [hostip]}
            }

            host_response = hostinstance.get(**kwargs)
            if len(host_response) == 0:
                print u"%s\t没有监控" % hostip
                continue
            if "hostid" in host_response[0]:
                hostid = host_response[0]['hostid']
                if hostid is not None:
                    twargs = {
                        "hostids": [hostid]
                    }
                    template_response = groupinstance.get(**twargs)
                    if len(template_response) == 0:
                        print u"%s\t没有关联主机组" % hostip
                        continue
                    else:
                        for tem in template_response:
                            temp_list.append(tem['name'])
                        print u"%s\t%s" % (hostip, " ".join(temp_list))
    except Exception, e:
        message = u"查询失败，可能是主机不存在!"
        print message, e
        traceback.print_exc()
        return False
    return True


def get_data(vserverip):
    """
    History object types to return.

    Possible values:
    0 - numeric float;
    1 - character;
    2 - log;
    3 - numeric unsigned;
    4 - text.

    Default: 3.
    """
    history_id = {
        'nfloat': 0,
        'char': 1,
        'log': 2,
        'uint': 3,
        'text': 4
    }
    history_dict = {}

    # 声明3个空字典
    dict_cpu = {}
    dict_mem = {}
    dict_disk = {}

    ops = zabbix_ops()
    # get CPU load from zabbix
    hostid = ops.get_hostid_by_hostip(vserverip)
    item_list = ops.get_itemid_by_hostid(hostid, 'system.cpu.load[percpu,avg1]')
    # print item_list
    cpu_data = ops.get_history_by_itemid(item_list, history_id['nfloat'])
    for k in item_list.keys():
        dict_mem[item_list[k]] = cpu_data[k]

    # get MEM from zabbix

    item_list = ops.get_itemid_by_hostid(hostid, 'vm.memory.size[available]')
    # print item_list
    mem_data = ops.get_history_by_itemid(item_list, history_id['uint'])
    for k in item_list.keys():
        dict_mem[item_list[k]] = mem_data[k]

    # get DISK from zabbix

    item_list = ops.get_itemid_by_hostid(hostid, 'vfs.fs.size')
    # print item_list
    disk_data = ops.get_history_by_itemid(item_list, history_id['nfloat'])
    # print disk_data
    for k in item_list.keys():
        dict_mem[item_list[k]] = disk_data[k]

    history_dict = dict_cpu.copy()
    history_dict.update(dict_mem)
    history_dict.update(dict_disk)
    print history_dict
    return history_dict


def getid_list_by_ops(bu, ops):
    hostid_list = []

    hostip_list = getip_from_ops.getnonip_lin_by_bu(bu)
    for hostip in hostip_list:
        hostid = ops.get_hostid_by_hostip(hostip)
        print 'The hostip: %s, the hostid: %s' % (hostip, hostid)
        create_jmx_by_hostip(hostid, hostip, ops)
        tmp = {"hostid": str(hostid)}
        if hostid != -1:
            hostid_list.append(tmp)
    return hostid_list


def create_jmx_by_hostip(hostid, hostip, ops):
    # hostid = ops.get_hostid_by_hostip(hostip)
    hostids = ops.hostinterface_create_by_hostid(hostid=hostid, hostip=hostip, port="12345", type=4)
    return hostids


def add_template_group(templatename, groupname):
    ops = zabbix_ops()
    hosts_list = getid_list_by_ops(u'仓储加工', ops)
    print len(hosts_list), hosts_list
    templateid = ops.get_templateid_by_templatename(templatename=templatename)
    print 'The template id is %s' % templateid

    groupid = ops.get_groupid_by_groupname(groupname=groupname)
    print 'The Hostgroup id is %s' % groupid
    # hosts_list = [{'hostid': '13366'}, {'hostid': '14524'}, {'hostid': '13300'}, {'hostid': '13291'}, {'hostid': '13303'}, {'hostid': '14346'}, {'hostid': '13482'}, {'hostid': '13447'}, {'hostid': '11193'}]
    hostid_lists = ops.update_host_by_hostid(hosts_list, str(groupid), str(templateid))
    print 'success: %s' % len(hostid_lists)


if __name__ == "__main__":
    # get_data("10.80.5.35")
    # create_jmx_by_hostip("10.0.16.202")

    # add_template_group(templatename='CustomTomcat', groupname='Tomcat_Server')
    ops = zabbix_ops()
    ops.get_trigger()
    # create_jmx_by_hostip("10.0.16.202", ops)
    # ops.delete_host_by_id(u'10.0.5.68')
    # update_host('10.0.48.18', method='enable')
    # update_host('10.0.52.227', method='delete')
    # 根据IP地址获取监控模板
    # get_template_by_ip('zabbixprd')

    # 根据IP地址获取主机组
    # get_group_by_ip('zabbixprd')
