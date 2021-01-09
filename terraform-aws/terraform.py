from __future__ import unicode_literals, print_function
import argparse
from collections import defaultdict
from functools import wraps
import json
import os
import re

VERSION = '0.3.0pre'


def tfstates(root=None):
    root = root or os.getcwd()
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if os.path.splitext(name)[-1] == '.tfstate':
                yield os.path.join(dirpath, name)


def iterresources(filenames):
    for filename in filenames:
        with open(filename, 'r') as json_file:
            state = json.load(json_file)
            for module in state['modules']:
                name = module['path'][-1]
                for key, resource in module['resources'].items():
                    yield name, key, resource


PARSERS = {}


def _clean_dc(dcname):

    return re.sub('[^\w_\-]', '-', dcname)


def iterhosts(resources):
   
    for module_name, key, resource in resources:
        resource_type, name = key.split('.', 1)
        try:
            parser = PARSERS[resource_type]
        except KeyError:
            continue

        yield parser(resource, module_name)


def parses(prefix):
    def inner(func):
        PARSERS[prefix] = func
        return func

    return inner


def calculate_mi_vars(func):
    

    @wraps(func)
    def inner(*args, **kwargs):
        name, attrs, groups = func(*args, **kwargs)

      
        if attrs.get('role', '') == 'control':
            attrs['consul_is_server'] = True
        else:
            attrs['consul_is_server'] = False

        
        if attrs.get('publicly_routable', False):
            groups.append('publicly_routable')

        return name, attrs, groups

    return inner


def _parse_prefix(source, prefix, sep='.'):
    for compkey, value in source.items():
        try:
            curprefix, rest = compkey.split(sep, 1)
        except ValueError:
            continue

        if curprefix != prefix or rest == '#':
            continue

        yield rest, value


def parse_attr_list(source, prefix, sep='.'):
    attrs = defaultdict(dict)
    for compkey, value in _parse_prefix(source, prefix, sep):
        idx, key = compkey.split(sep, 1)
        attrs[idx][key] = value

    return attrs.values()


def parse_dict(source, prefix, sep='.'):
    return dict(_parse_prefix(source, prefix, sep))


def parse_list(source, prefix, sep='.'):
    return [value for _, value in _parse_prefix(source, prefix, sep)]


def parse_bool(string_form):
    token = string_form.lower()[0]

    if token == 't':
        return True
    elif token == 'f':
        return False
    else:
        raise ValueError('could not convert %r to a bool' % string_form)


@parses('digitalocean_droplet')
@calculate_mi_vars
def digitalocean_host(resource, tfvars=None):
    raw_attrs = resource['primary']['attributes']
    name = raw_attrs['name']
    groups = []

    attrs = {
        'id': raw_attrs['id'],
        'image': raw_attrs['image'],
        'ipv4_address': raw_attrs['ipv4_address'],
        'locked': parse_bool(raw_attrs['locked']),
        'metadata': json.loads(raw_attrs['user_data']),
        'region': raw_attrs['region'],
        'size': raw_attrs['size'],
        'ssh_keys': parse_list(raw_attrs, 'ssh_keys'),
        'status': raw_attrs['status'],
        
        'ansible_ssh_host': raw_attrs['ipv4_address'],
        'ansible_ssh_port': 22,
        'ansible_ssh_user': 'root',  
        
        'public_ipv4': raw_attrs['ipv4_address'],
        'private_ipv4': raw_attrs['ipv4_address'],
        'provider': 'digitalocean',
    }

   
    attrs.update({
        'consul_dc': _clean_dc(attrs['metadata'].get('dc', attrs['region'])),
        'role': attrs['metadata'].get('role', 'none'),
        'ansible_python_interpreter': attrs['metadata'].get('python_bin','python')
    })

    groups.append('do_image=' + attrs['image'])
    groups.append('do_locked=%s' % attrs['locked'])
    groups.append('do_region=' + attrs['region'])
    groups.append('do_size=' + attrs['size'])
    groups.append('do_status=' + attrs['status'])
    groups.extend('do_metadata_%s=%s' % item
                  for item in attrs['metadata'].items())

    
    groups.append('role=' + attrs['role'])
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


@parses('softlayer_virtualserver')
@calculate_mi_vars
def softlayer_host(resource, module_name):
    raw_attrs = resource['primary']['attributes']
    name = raw_attrs['name']
    groups = []

    attrs = {
        'id': raw_attrs['id'],
        'image': raw_attrs['image'],
        'ipv4_address': raw_attrs['ipv4_address'],
        'metadata': json.loads(raw_attrs.get('user_data', '{}')),
        'region': raw_attrs['region'],
        'ram': raw_attrs['ram'],
        'cpu': raw_attrs['cpu'],
        'ssh_keys': parse_list(raw_attrs, 'ssh_keys'),
        'public_ipv4': raw_attrs['ipv4_address'],
        'private_ipv4': raw_attrs['ipv4_address_private'],
        'ansible_ssh_host': raw_attrs['ipv4_address'],
        'ansible_ssh_port': 22,
        'ansible_ssh_user': 'root',
        'provider': 'softlayer',
    }

    
    attrs.update({
        'consul_dc': _clean_dc(attrs['metadata'].get('dc', attrs['region'])),
        'role': attrs['metadata'].get('role', 'none'),
        'ansible_python_interpreter': attrs['metadata'].get('python_bin','python')
    })

    
    groups.append('role=' + attrs['role'])
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


@parses('openstack_compute_instance_v2')
@calculate_mi_vars
def openstack_host(resource, module_name):
    raw_attrs = resource['primary']['attributes']
    name = raw_attrs['name']
    groups = []

    attrs = {
        'access_ip_v4': raw_attrs['access_ip_v4'],
        'access_ip_v6': raw_attrs['access_ip_v6'],
        'flavor': parse_dict(raw_attrs, 'flavor',
                             sep='_'),
        'id': raw_attrs['id'],
        'image': parse_dict(raw_attrs, 'image',
                            sep='_'),
        'key_pair': raw_attrs['key_pair'],
        'metadata': parse_dict(raw_attrs, 'metadata'),
        'network': parse_attr_list(raw_attrs, 'network'),
        'region': raw_attrs.get('region', ''),
        'security_groups': parse_list(raw_attrs, 'security_groups'),
        
        'ansible_ssh_port': 22,
       
        'host_domain': 'novalocal',
        'use_host_domain': True,
        
        'public_ipv4': raw_attrs['access_ip_v4'],
        'private_ipv4': raw_attrs['access_ip_v4'],
        'provider': 'openstack',
    }

    if 'floating_ip' in raw_attrs:
        attrs['private_ipv4'] = raw_attrs['network.0.fixed_ip_v4']

    try:
        attrs.update({
            'ansible_ssh_host': raw_attrs['access_ip_v4'],
            'publicly_routable': True,
        })
    except (KeyError, ValueError):
        attrs.update({'ansible_ssh_host': '', 'publicly_routable': False})

    
    if 'metadata.ssh_user' in raw_attrs:
        attrs['ansible_ssh_user'] = raw_attrs['metadata.ssh_user']

    
    attrs.update({
        'consul_dc': _clean_dc(attrs['metadata'].get('dc', module_name)),
        'role': attrs['metadata'].get('role', 'none'),
        'ansible_python_interpreter': attrs['metadata'].get('python_bin','python')
    })

    
    groups.append('os_image=' + attrs['image']['name'])
    groups.append('os_flavor=' + attrs['flavor']['name'])
    groups.extend('os_metadata_%s=%s' % item
                  for item in attrs['metadata'].items())
    groups.append('os_region=' + attrs['region'])

    
    groups.append('role=' + attrs['metadata'].get('role', 'none'))
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


@parses('aws_instance')
@calculate_mi_vars
def aws_host(resource, module_name):
    name = resource['primary']['attributes']['tags.Name']
    raw_attrs = resource['primary']['attributes']

    groups = []

    attrs = {
        'ami': raw_attrs['ami'],
        'availability_zone': raw_attrs['availability_zone'],
        'ebs_block_device': parse_attr_list(raw_attrs, 'ebs_block_device'),
        'ebs_optimized': parse_bool(raw_attrs['ebs_optimized']),
        'ephemeral_block_device': parse_attr_list(raw_attrs,
                                                  'ephemeral_block_device'),
        'id': raw_attrs['id'],
        'key_name': raw_attrs['key_name'],
        'private': parse_dict(raw_attrs, 'private',
                              sep='_'),
        'public': parse_dict(raw_attrs, 'public',
                             sep='_'),
        'root_block_device': parse_attr_list(raw_attrs, 'root_block_device'),
        'security_groups': parse_list(raw_attrs, 'security_groups'),
        'subnet': parse_dict(raw_attrs, 'subnet',
                             sep='_'),
        'tags': parse_dict(raw_attrs, 'tags'),
        'tenancy': raw_attrs['tenancy'],
        'vpc_security_group_ids': parse_list(raw_attrs,
                                             'vpc_security_group_ids'),
        
        'ansible_ssh_port': 22,
        'ansible_ssh_host': raw_attrs['public_ip'],
       
        'public_ipv4': raw_attrs['public_ip'],
        'private_ipv4': raw_attrs['private_ip'],
        'provider': 'aws',
    }

    
    if 'tags.sshUser' in raw_attrs:
        attrs['ansible_ssh_user'] = raw_attrs['tags.sshUser']
    if 'tags.sshPrivateIp' in raw_attrs:
        attrs['ansible_ssh_host'] = raw_attrs['private_ip']

    
    attrs.update({
        'consul_dc': _clean_dc(attrs['tags'].get('dc', module_name)),
        'role': attrs['tags'].get('role', 'none'),
        'ansible_python_interpreter': attrs['tags'].get('python_bin','python')
    })

    groups.extend(['aws_ami=' + attrs['ami'],
                   'aws_az=' + attrs['availability_zone'],
                   'aws_key_name=' + attrs['key_name'],
                   'aws_tenancy=' + attrs['tenancy']])
    groups.extend('aws_tag_%s=%s' % item for item in attrs['tags'].items())
    groups.extend('aws_vpc_security_group=' + group
                  for group in attrs['vpc_security_group_ids'])
    groups.extend('aws_subnet_%s=%s' % subnet
                  for subnet in attrs['subnet'].items())

    
    groups.append('role=' + attrs['role'])
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


@parses('google_compute_instance')
@calculate_mi_vars
def gce_host(resource, module_name):
    name = resource['primary']['id']
    raw_attrs = resource['primary']['attributes']
    groups = []

    
    interfaces = parse_attr_list(raw_attrs, 'network_interface')
    for interface in interfaces:
        interface['access_config'] = parse_attr_list(interface,
                                                     'access_config')
        for key in interface.keys():
            if '.' in key:
                del interface[key]

    
    attrs = {
        'can_ip_forward': raw_attrs['can_ip_forward'] == 'true',
        'disks': parse_attr_list(raw_attrs, 'disk'),
        'machine_type': raw_attrs['machine_type'],
        'metadata': parse_dict(raw_attrs, 'metadata'),
        'network': parse_attr_list(raw_attrs, 'network'),
        'network_interface': interfaces,
        'self_link': raw_attrs['self_link'],
        'service_account': parse_attr_list(raw_attrs, 'service_account'),
        'tags': parse_list(raw_attrs, 'tags'),
        'zone': raw_attrs['zone'],
        
        'ansible_ssh_port': 22,
        'provider': 'gce',
    }

    
    if 'metadata.ssh_user' in raw_attrs:
        attrs['ansible_ssh_user'] = raw_attrs['metadata.ssh_user']

    
    attrs.update({
        'consul_dc': _clean_dc(attrs['metadata'].get('dc', module_name)),
        'role': attrs['metadata'].get('role', 'none'),
        'ansible_python_interpreter': attrs['metadata'].get('python_bin','python')
    })

    try:
        attrs.update({
            'ansible_ssh_host': interfaces[0]['access_config'][0]['nat_ip'] or interfaces[0]['access_config'][0]['assigned_nat_ip'],
            'public_ipv4': interfaces[0]['access_config'][0]['nat_ip'] or interfaces[0]['access_config'][0]['assigned_nat_ip'],
            'private_ipv4': interfaces[0]['address'],
            'publicly_routable': True,
        })
    except (KeyError, ValueError):
        attrs.update({'ansible_ssh_host': '', 'publicly_routable': False})

    # add groups based on attrs
    groups.extend('gce_image=' + disk['image'] for disk in attrs['disks'])
    groups.append('gce_machine_type=' + attrs['machine_type'])
    groups.extend('gce_metadata_%s=%s' % (key, value)
                  for (key, value) in attrs['metadata'].items()
                  if key not in set(['sshKeys']))
    groups.extend('gce_tag=' + tag for tag in attrs['tags'])
    groups.append('gce_zone=' + attrs['zone'])

    if attrs['can_ip_forward']:
        groups.append('gce_ip_forward')
    if attrs['publicly_routable']:
        groups.append('gce_publicly_routable')

   
    groups.append('role=' + attrs['metadata'].get('role', 'none'))
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


@parses('vsphere_virtual_machine')
@calculate_mi_vars
def vsphere_host(resource, module_name):
    raw_attrs = resource['primary']['attributes']
    network_attrs = parse_dict(raw_attrs, 'network_interface')
    network = parse_dict(network_attrs, '0')
    ip_address = network.get('ipv4_address', network['ip_address'])
    name = raw_attrs['name']
    groups = []

    attrs = {
        'id': raw_attrs['id'],
        'ip_address': ip_address,
        'private_ipv4': ip_address,
        'public_ipv4': ip_address,
        'metadata': parse_dict(raw_attrs, 'custom_configuration_parameters'),
        'ansible_ssh_port': 22,
        'provider': 'vsphere',
    }

    try:
        attrs.update({
            'ansible_ssh_host': ip_address,
        })
    except (KeyError, ValueError):
        attrs.update({'ansible_ssh_host': '', })

    attrs.update({
        'consul_dc': _clean_dc(attrs['metadata'].get('consul_dc', module_name)),
        'role': attrs['metadata'].get('role', 'none'),
        'ansible_python_interpreter': attrs['metadata'].get('python_bin','python')
    })

   
    if 'ssh_user' in attrs['metadata']:
        attrs['ansible_ssh_user'] = attrs['metadata']['ssh_user']

    groups.append('role=' + attrs['role'])
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups

@parses('azure_instance')
@calculate_mi_vars
def azure_host(resource, module_name):
    name = resource['primary']['attributes']['name']
    raw_attrs = resource['primary']['attributes']

    groups = []

    attrs = {
        'automatic_updates': raw_attrs['automatic_updates'],
        'description': raw_attrs['description'],
        'hosted_service_name': raw_attrs['hosted_service_name'],
        'id': raw_attrs['id'],
        'image': raw_attrs['image'],
        'ip_address': raw_attrs['ip_address'],
        'location': raw_attrs['location'],
        'name': raw_attrs['name'],
        'reverse_dns': raw_attrs['reverse_dns'],
        'security_group': raw_attrs['security_group'],
        'size': raw_attrs['size'],
        'ssh_key_thumbprint': raw_attrs['ssh_key_thumbprint'],
        'subnet': raw_attrs['subnet'],
        'username': raw_attrs['username'],
        'vip_address': raw_attrs['vip_address'],
        'virtual_network': raw_attrs['virtual_network'],
        'endpoint': parse_attr_list(raw_attrs, 'endpoint'),
        
        'ansible_ssh_port': 22,
        'ansible_ssh_user': raw_attrs['username'],
        'ansible_ssh_host': raw_attrs['vip_address'],
    }

    
    attrs.update({
        'consul_dc': attrs['location'].lower().replace(" ", "-"),
        'role': attrs['description']
    })

    
    groups.extend(['azure_image=' + attrs['image'],
                   'azure_location=' + attrs['location'].lower().replace(" ", "-"),
                   'azure_username=' + attrs['username'],
                   'azure_security_group=' + attrs['security_group']])

    
    groups.append('role=' + attrs['role'])
    groups.append('dc=' + attrs['consul_dc'])

    return name, attrs, groups


def query_host(hosts, target):
    for name, attrs, _ in hosts:
        if name == target:
            return attrs

    return {}


def query_list(hosts):
    groups = defaultdict(dict)
    meta = {}

    for name, attrs, hostgroups in hosts:
        for group in set(hostgroups):
            groups[group].setdefault('hosts', [])
            groups[group]['hosts'].append(name)

        meta[name] = attrs

    groups['_meta'] = {'hostvars': meta}
    return groups


def query_hostfile(hosts):
    out = ['## begin hosts generated by terraform.py ##']
    out.extend(
        '{}\t{}'.format(attrs['ansible_ssh_host'].ljust(16), name)
        for name, attrs, _ in hosts
    )

    out.append('## end hosts generated by terraform.py ##')
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(
        __file__, __doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter, )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--list',
                       action='store_true',
                       help='list all variables')
    modes.add_argument('--host', help='list variables for a single host')
    modes.add_argument('--version',
                       action='store_true',
                       help='print version and exit')
    modes.add_argument('--hostfile',
                       action='store_true',
                       help='print hosts as a /etc/hosts snippet')
    parser.add_argument('--pretty',
                        action='store_true',
                        help='pretty-print output JSON')
    parser.add_argument('--nometa',
                        action='store_true',
                        help='with --list, exclude hostvars')
    default_root = os.environ.get('TERRAFORM_STATE_ROOT',
                                  os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                               '..', '..', )))
    parser.add_argument('--root',
                        default=default_root,
                        help='custom root to search for `.tfstate`s in')

    args = parser.parse_args()

    if args.version:
        print('%s %s' % (__file__, VERSION))
        parser.exit()

    hosts = iterhosts(iterresources(tfstates(args.root)))
    if args.list:
        output = query_list(hosts)
        if args.nometa:
            del output['_meta']
        print(json.dumps(output, indent=4 if args.pretty else None))
    elif args.host:
        output = query_host(hosts, args.host)
        print(json.dumps(output, indent=4 if args.pretty else None))
    elif args.hostfile:
        output = query_hostfile(hosts)
        print(output)

    parser.exit()


if __name__ == '__main__':
    main()
