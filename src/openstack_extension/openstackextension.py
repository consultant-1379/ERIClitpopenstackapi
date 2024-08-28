##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import itertools
import netaddr
from urlparse import urlparse

from litp.core.model_type import (Collection, ItemType, Property, PropertyType,
                                  Child, View)
from litp.core.extension import ModelExtension
from litp.core.validators import (PropertyValidator, ValidationError,
                                  ItemValidator)

from litp.core.litp_logging import LitpLogger


log = LitpLogger()

MONITOR_TYPES = "(ping|tcp|http|https)"
PROTOCOL_TYPES = "(tcp|http|https)"
LB_METHODS = "(round_robin|least_connections|source_ip)"
DIRECTION_TYPES = "(in|e)gress"
SECURITY_GROUP_RULE_PROTOCOL_TYPES = "(tcp|udp|icmp)"


class DiskFormatValidator(PropertyValidator):

    """
    Validates disk_format is of allowed values.
    """

    def __init__(self):
        super(DiskFormatValidator, self).__init__()
        self.supported_formats = ('raw', 'qcow2')

    def validate(self, property_value):
        if property_value not in self.supported_formats:
            return ValidationError(
                error_message='Property value "%s" not supported.'
                % (property_value))


class IPVersionValidator(PropertyValidator):

    def __init__(self):
        super(IPVersionValidator, self).__init__()
        self.supported_formats = ('4', '6')

    def validate(self, property_value):
        if property_value not in self.supported_formats:
            return ValidationError(
                error_message='Invalid value "%s" for IP version.'
                % (property_value))


class IPv4OrIPv6NetworkValidator(PropertyValidator):
    """
    Validates the property's value is a valid IPv4 or IPv6 Network
    """
    def validate(self, property_value):
        if not property_value:
            return None
        try:
            if ":" in property_value:
                ip_version = 6
            elif "." in property_value:
                ip_version = 4
            else:
                return ValidationError(
                    error_message="Invalid value for IP Version")
            netaddr.IPNetwork(property_value, version=ip_version)

        #With only except Exception mvn build fails with message
        #"Catching too general exception Exception"
        except netaddr.AddrFormatError as e:
            error_message = e.args[0]
            return ValidationError(error_message=error_message)
        except ValueError as e:
            error_message = e.args[0]
            return ValidationError(error_message=error_message)
        except Exception as e:
            error_message = e.args[0]
            return ValidationError(error_message=error_message)
        if not '/' in property_value:
            return ValidationError(
                error_message="Subnet must include prefix length")


class URLFormatValidator(PropertyValidator):

    def validate(self, property_value):
        if not self._valid_url_format(property_value):
            message = "Invalid URL format for '%s'" % (property_value)
            return ValidationError(error_message=message)

    def _valid_url_format(self, value):
        parsed = urlparse(value)
        return parsed.path and parsed.scheme


class PortValidator(PropertyValidator):

    def validate(self, property_value):
        if not self._valid_port(property_value):
            message = ("Invalid port '%s', select one from range 1-65535"
                       % (property_value))
            return ValidationError(error_message=message)

    @staticmethod
    def _valid_port(value):
        try:
            return 1 <= int(value) <= 65535
        except ValueError:
            return False


class MatchAddressAndIPVersionValidator(ItemValidator):

    def validate(self, properties):
        if 'cidr' in properties and 'ip_version' in properties:
            cidr = properties['cidr']
            ip_version = properties['ip_version']
            cidr_version = netaddr.IPNetwork(cidr).version
            if int(ip_version) != cidr_version:
                return ValidationError(
                    error_message='The property ip_version value "%s"'
                                  'is not coherent with cidr value "%s".'
                                  ' Both have to be of the same IP version.'
                                  % (ip_version, cidr_version))


def security_groups_view(plugin_api_context, query_item):
    if not query_item.security_group_names:
        return []
    return list(itertools.chain.from_iterable(
        [plugin_api_context.query('tenant-security-group',
            is_for_removal=False, name=attached_security_group_name)
            for attached_security_group_name
            in query_item.security_group_names.split(',')]))

config = {
    'property_types': [
        {'id': 'monitor_type',
         'regex': r"^%s$" % MONITOR_TYPES,
         'validators': [],
         },
        {'id': 'protocol_types',
            'regex': r"^%s$" % PROTOCOL_TYPES,
            'validators': [],
         },
        {'id': 'lb_methods',
            'regex': r"^%s$" % LB_METHODS,
            'validators': [],
         },
        {'id': 'url',
            'regex': r"^(.*)$",
            'validators': [URLFormatValidator(), ],
         },
        {'id': 'package',
         'regex': r"[\w.-]*",
         'validators': [],
         },
        {'id': 'cloud_image_format',
         'regex': r"^(.*)$",
         'validators': [DiskFormatValidator()],
         },
        {'id': 'both_ip_version',
         'regex': r"^[0-9.]+$",
         'validators': [IPVersionValidator()],
         },
        {'id': 'cloud_network',
         'regex': r"^.+$",
         'validators': [IPv4OrIPv6NetworkValidator()],
         },
        {'id': 'direction_type',
         'regex': r"^%s$" % DIRECTION_TYPES,
         'validators': [],
         },
        {'id': 'security_protocol_type',
         'regex': r"^%s$" % SECURITY_GROUP_RULE_PROTOCOL_TYPES,
         'validators': [],
         },
        {'id': 'system_port',
         'regex': r"^\d+$",
         'validators': [PortValidator()],
         },
    ],
    'item_types': [
        {'id': 'tenant-image',
         'extends': 'image-base',
         'description': "OpenStack compatible image",
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Name of image',
              'required': True,
              },
             {'name': 'path',
              'type': 'url',
              'description': 'URI of the instance image.',
              'required': True,
              },
             {'name': 'disk_format',
              'type': 'cloud_image_format',
              'description': 'Image format: raw and qcow2 supported',
              'required': True,
              'default': 'qcow2',
              },
         ],
         'collections': [],
         'validators': [],
         },
        {'id': 'openstack-provider',
         'extends': 'system-provider',
         'description': "OpenStack VM provider.",
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Name of OpenStack deployment.',
              'required': True,
              },
             {'name': 'auth_url',
              'type': 'any_string',
              'description': 'Keystone url endpoint of OpenStack cloud.',
              'required': True,
              },
         ],
         'collections': [],
         'validators': [],
         },
        {'id': 'tenant-cluster',
         'extends': 'cluster-base',
         'description': "OpenStack Cloud Cluster.",
         'properties': [
             {'name': 'provider_name',
              'type': 'basic_string',
              'description': 'Name of OpenStack provider to use.',
              'required': True,
              'validators': [],
              },
         ],
         'collections': [
             {'id': 'tenants',
              'type': 'cloud-tenant',
              'min_count': 0,
              'max_count': 1,
              },
         ],
         },
        {'id': 'cloud-tenant',
         'description': 'OpenStack Cloud Tenant.',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Cloud tenant (project) name',
              'required': True,
              'validators': [],
              },
         ],
         'collections': [
             {'id': 'users',
              'type': 'tenant-user',
              'min_count': 1,
              'max_count': 1,
              },
             {'id': 'stacks',
              'type': 'tenant-stack',
              'min_count': 0,
              'max_count': 1,
              },
             {'id': 'volumes',
              'type': 'tenant-volume',
              'min_count': 0,
              'max_count': 10
              }
         ],
         },

        {'id': 'tenant-keypair',
         'description': 'OpenStack Instance Keypair.',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Keypair name for imported key',
              'required': True,
              'validators': [],
              },
             {'name': 'public_key',
              'type': 'any_string',
              'description': 'Public key value to import',
              'required': True,
              'validators': [],
              },
         ],
         'collections': [],
         },

        {'id': 'tenant-stack',
         'description': 'OpenStack Heat Stack.',
         'collections': [
             {'id': 'instances',
              'type': 'tenant-instance',
              'min_count': 0,
              'max_count': 100,
              },
             {'id': 'instance_lb_groups',
              'type': 'tenant-instance-lb-group',
              'min_count': 0,
              'max_count': 100,
              },
             {'id': 'networks',
              'type': 'tenant-network',
              'min_count': 0,
              'max_count': 10,
              },
             {'id': 'routers',
              'type': 'tenant-router',
              'min_count': 0,
              'max_count': 10,
              },
             {'id': 'lb_monitors',
              'type': 'tenant-lb-monitor',
              'min_count': 0,
              'max_count': 10,
              },
             {'id': 'keypairs',
              'type': 'tenant-keypair',
              'min_count': 0,
              'max_count': 1,
              },
             {'id': 'security_groups',
              'type': 'tenant-security-group',
              }
         ],
         },

        {'id': 'tenant-user',
         'description': "OpenStack project's user",
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': "Project's user name",
              'required': True,
              'validators': [],
              },
             {'name': 'password_key',
              'type': 'basic_string',
              'description': 'Password key for OpenStack user.',
              'required': True,
              'validators': [],
              },
         ],
         'collections': [],
         },
        {'id': 'tenant-instance',
         'description': "OpenStack Cloud instance.",
         'properties': [
             {'name': 'flavor',
              'type': 'basic_string',
              'description': 'OpenStack instance flavour.',
              'required': True,
              'validators': [],
              },
             {'name': 'instance_name',
              'type': 'basic_string',
              'description': 'OpenStack instance name.',
              'required': True,
              'validators': [],
              },
             {'name': 'image_name',
              'type': 'any_string',
              'description': 'Name of the image to use for this instance.',
              'required': True,
              'validators': [],
              },
             {'name': 'key_name',
              'type': 'basic_string',
              'description': 'Name of the key to use for this instance.',
              'required': True,
              'validators': [],
              },
             {'name': 'depends_on',
              'type': 'basic_list',
              'description': 'IDs of tenant-instance-group or tenant-instance '
              'to depend on.',
              'required': False,
              'validators': [],
              },
             {'name': 'security_group_names',
              'type': 'basic_list',
              'description': 'Security group names containing rules to be '
              'applied here.',
              'required': False,
              'validators': [],
              },
         ],
         'views': [
             {'name': 'security_groups',
              # prop_type_id is not used properly here because of the view
              # mechanism.
              'prop_type_id': 'basic_list',
              'view_description': 'Security groups to be applied, linked by '
              'security_group_names.',
              'callable_method': security_groups_view
              },
         ],
         'collections': [
             {'id': 'networks',
              # XXX(xluiguz): when an instance is defined in a stack,
              # the network name has to be soft-linked to the tenant-subnet
              # (not to the tenant-network, as it is in non-stack instances)
              'type': 'instance-network',
              'min_count': 1,
              'max_count': 10,
              },
             {'id': 'packages',
              'type': 'tenant-package',
              },
             {'id': 'yumrepos',
              'type': 'tenant-yum-repo',
              },
             {'id': 'volumes',
              'type': 'tenant-volume'
              },
             {'id': 'network_mounts',
              'type': 'tenant-network-file-share'
              },
             {'id': 'hostentries',
              'type': 'tenant-hostentry'
              },
         ],
         'validators': [],
         },
        {'id': 'tenant-volume',
         'description': 'Openstack Cinder Volume attached to instance',
         'properties': [
             {'name': 'size',
              'type': 'integer',
              'description': 'Size of volume',
              'required': False,
              },
             {'name': 'device_name',
              'type': 'basic_string',
              'description': 'Name of devices',
              #'default': 'vdb',
              'required': False
              },
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Name of volume',
              'default': '',
              'required': False
              },
             {'name': 'uuid',
              'type': 'basic_string',
              'description': '',
              'updatable_plugin': True,
              'updatable_rest': False
              }
         ]
         },
        {'id': 'tenant-hostentry',
         'description': 'Openstack host that provides an endpoint',
         'properties': [
             {'name': 'ip',
              'type': 'basic_string',
              'description': 'IP for the endpoint',
              'updatable_plugin': False,
              'updatable_rest': False,
              'required': True
             },
            {'name': 'hostentry',
              'type': 'basic_string',
              'description': 'Hostname alias for the endpoint',
              'updatable_plugin': False,
              'updatable_rest': False,
              'required': True
             }
            ]
        },
        {'id': 'tenant-network-file-share',
         'description': 'Openstack NFS Volume attached to instance',
         'properties': [
             {'name': 'provider',
              'type': 'hostname',
              'description': 'Host exporting file share',
              'required': True,
              },
             {'name': 'export_path',
              'type': 'path_string',
              'description': 'Network share exported by provider',
              'required': True,
              },
             {'name': 'mount_point',
              'type': 'path_string',
              'description': 'Location to mount network share',
              'required': True,
              },
             {'name': 'read_size',
              'type': 'integer',
              'description': 'Data transfer read buffer size',
              'required': False,
              'default': '8192',
              },
             {'name': 'write_size',
              'type': 'integer',
              'description': 'Data transfer read buffer size',
              'required': False,
              'default': '8192',
              },
             {'name': 'timeout',
              'type': 'integer',
              'description': 'Time (in decaseconds) to wait '
              'before retrying operation',
              'required': False,
              'default': '600',
              },
             {'name': 'options',
              'type': 'any_string',
              'description': 'Options typically passed to mount command',
              'required': False,
              },
         ]
        },
        {'id': 'tenant-alarm',
         'description': 'OpenStack tenant alarm',
         'properties': [
           {'name': 'description',
           'type': 'any_string',
           'description': 'Alarm description.',
           'required': False,
           },
           {'name': 'wait_timeout',
            'type': 'integer',
            'description': 'Alarm timeout.',
            'required': True
           },
           {'name': 'period',
            'type': 'integer',
            'description': 'Alarm period',
            'required': True,
           },
           {'name': 'evaluation_periods',
            'type': 'integer',
            'description': 'Evaluation periods.',
            'required': True,
           }
         ],
         'collections': [],
        },

        {'id': 'tenant-lb-monitor',
         'description': "OpenStack Load Balancer monitor component",
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Monitor name',
              'required': True,
              'validators': [],
              },
             {'name': 'type',
              'type': 'monitor_type',
              'description': 'Monitor type, options: "%s"' % MONITOR_TYPES,
              'required': False,
              'default': 'ping',
              'validators': []
              },
             {'name': 'delay',
              'type': 'basic_string',
              'description': 'Monitor delay in seconds.',
              'required': False,
              'default': '20',
              'validators': [],
              },
             {'name': 'max_retries',
              'type': 'basic_string',
              'description': 'Monitor max number of retries.',
              'required': False,
              'default': '1',
              'validators': [],
              },
             {'name': 'timeout',
              'type': 'basic_string',
              'description': 'Monitor timeout in seconds.',
              'required': False,
              'default': '18',
              'validators': [],
              },
             {'name': 'http_method',
              'type': 'basic_string',
              'description': 'HTTP method used for requests by the monitor.',
              'required': False,
              'default': 'GET',
              'validators': [],
              },
             {'name': 'url_path',
              'type': 'any_string',
              'description': 'HTTP path used for requests by the monitor.',
              'required': False,
              'default': '/',
              'validators': [],
              },
             {'name': 'expected_codes',
              'type': 'basic_string',
              'description': 'HTTP status codes expected by the monitor.',
              'required': False,
              'default': '200',
              'validators': [],
              },
         ],
         'collections': [],
         },

        {'id': 'tenant-lb',
         'description': "Openstack Load Balancer component",
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Load Balancer name. Affects the pool too.',
              'required': True,
              'validators': [],
              },
             {'name': 'protocol',
              'type': 'protocol_types',
              'description': ('Protocol that load balancer uses: "%s"'
                              % PROTOCOL_TYPES),
              'required': False,
              'default': 'http',
              'validators': [],
              },
             {'name': 'lb_method',
              'type': 'lb_methods',
              'description': ('Incomming connections handling method: "%s"'
                              % LB_METHODS),
              'required': False,
              'default': 'round_robin',
              'validators': [],
              },
             {'name': 'network_name',
              'type': 'basic_string',
              'description': 'Load Balancer internal network',
              'required': True,
              # TODO(xigomil) Validation on soft-links in the plugin
              'validators': [],
              },
             {'name': 'vip_floating_ip_pool',
              'type': 'basic_string',
              'description': "Floating IP network to use for VIP.",
              'required': False,
              # TODO(xigomil) Validation on soft-links in the plugin
              'validators': [],
              },
             {'name': 'vip_port',
              'type': 'system_port',
              'description': "VIP port to listen on for client traffic.",
              'required': False,
              'default': '80',
              },
             {'name': 'member_port',
              'type': 'system_port',
              'description': "TCP port the pool member listens on for "
              "incoming connections",
              'required': False,
              'default': '80',
              },
             {'name': 'monitors',
              'type': 'basic_list',
              'description': "monitors this LB uses",
              'required': True,
              'validators': [],
              },
         ],
         'collections': [
            {'id': 'alarms',
             'type': 'tenant-alarm',
             'min_count': 0,
             'max_count': 1
            }
         ],
         },

        {'id': 'tenant-instance-lb-group',
         'description': "OpenStack Cloud LoadBalancer Instance Group.",
         'properties': [
             {'name': 'group_name',
              'type': 'basic_string',
              'description': 'OpenStack group-instance name.',
              'required': True,
              'validators': [],
              },
             {'name': 'min',
              'type': 'integer',
              'description': 'Min number of instances in this group.',
              'required': False,
              'validators': [],
              },
             {'name': 'max',
              'type': 'integer',
              'description': 'Max number of instances in this group.',
              'required': False,
              'validators': [],
              },
             {'name': 'depends_on',
              'type': 'basic_list',
              'description': 'IDs of tenant-instance-lb-group or '
              'tenant-instance to depend on.',
              'required': False,
              'validators': [],
              },
         ],
         'children': [
             {'id': 'instance',
              'type': 'tenant-instance',
              'required': True,
              },
         ],
         'collections': [
            {'id': 'loadbalancers',
             'type': 'tenant-lb',
             'min_count': 1,
             'max_count': 2
            }
         ],
         'validators': [],
         },
        {'id': 'tenant-network',
         'description': 'OpenStack tenant network',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Network name.',
              'required': False,
              'validators': [],
              },
         ],
         'collections': [
             {'id': 'subnets',
              'type': 'tenant-network-subnet',
              'min_count': 1,
              'max_count': 1,
              },
         ],
         },
        {'id': 'instance-network',
         'description': "OpenStack Neutron's network, that should be attached "
                        "to instance",
         'properties': [
             {'name': 'network_name',
              'type': 'basic_string',
              'description': 'Network name.',
              'required': True,
              'validators': [],
              },
             {'name': 'floating_ip_pool',
              'type': 'basic_string',
              'description': 'If Floating IP Pool, where addresses should be '
                             'taken from.',
              'required': False,
              'validators': [],
              },
         ],
         'collections': [],
         },
        {'id': 'tenant-network-subnet',
         'description': 'OpenStack tenant network subnet',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Subnet name.',
              'required': False,
              'validators': [],
              },
             {'name': 'cidr',
              'type': 'cloud_network',
              'description': 'CIDR',
              'required': True,
              'validators': [],
              },
             {'name': 'ip_version',
              'type': 'both_ip_version',
              'description': 'IP version for the subnet. 4 or 6',
              'required': True,
              'validators': [],
              },
             {'name': 'enable_dhcp',
              'type': 'basic_boolean',
              'description': 'If DHCP is enable.',
              'required': False,
              'default': 'true',
              'validators': [],
              },
             {'name': 'disable_gateway',
              'type': 'basic_boolean',
              'description': 'Disable gateway on the subnet.',
              'required': False,
              'validators': [],
              },
         ],
         'collections': [],
         'validators': [MatchAddressAndIPVersionValidator()],
         },
        {'id': 'tenant-router',
         'description': 'OpenStack tenant router',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': 'Router name.',
              'required': False,
              'validators': [],
              },
             {'name': 'network_name',
              'type': 'basic_string',
              'description': 'Internal network to attach.',
              'required': False,
              'validators': [],
              },
             {'name': 'public_network',
              'type': 'basic_string',
              'description': 'Public network to provide gateway',
              'required': True,
              'default': 'public',
              'validators': [],
              }
         ],
         'collections': [],
         },
        {'id': 'tenant-package',
         'description': 'Package to install',
         'properties': [
             {'name': 'name',
              'type': 'package',
              'description': "Package name",
              'required': True,
              'validators': []
              },
         ],
         },
        {'id': 'tenant-yum-repo',
         'description': 'Yum repo to add to instance',
         'properties': [
             {'name': 'name',
              'type': 'basic_string',
              'description': "Repo name",
              'required': True,
              'validators': []
              },
             {'name': 'baseurl',
              'type': 'any_string',
              'required': True,
              'validators': [],
              },
             {'name': 'checksum',
              'type': 'checksum_hex_string',
              'description': "Checksum md5 for the repo"
                            " data returned by repoquery.",
              'required': False,
              'default': "",
              'updatable_plugin': True,
              'updatable_rest': False,
              'validators': [],
              }
         ],
         },
         {'id': 'tenant-security-group',
          'description': 'OpenStack tenant security group',
          'properties': [
              {'name': 'name',
               'type': 'basic_string',
               'description': 'Security group name.',
               'required': False,
               },
              {'name': 'description',
               'type': 'any_string',
               'description': 'Security group description.',
               'required': False,
               },
          ],
          'collections': [
            {'id': 'rules',
             'type': 'tenant-security-group-rule'
             },
          ],
        },
        {'id': 'tenant-security-group-rule',
         'description': 'OpenStack tenant security group rule',
         'properties': [
           {'name': 'direction',
            'type': 'direction_type',
            'description': 'Rule direction.',
            'required': True,
            'default': 'ingress',
           },
           {'name': 'protocol',
            'type': 'security_protocol_type',
            'description': 'Rule protocol (tcp, udp or icmp).',
            'required': True,
            'default': 'tcp',
           },
           {'name': 'port_range_min',
            'type': 'system_port',
            'description': 'Minimal port number.',
            'required': False,
           },
           {'name': 'port_range_max',
            'type': 'system_port',
            'description': 'Maximal port number.',
            'required': False,
           },
           {'name': 'remote_ip_prefix',
            'type': 'cloud_network',
            'description': 'Source IP address of the IP packet.',
            'required': True,
            'default': '0.0.0.0/0',
           },
         ],
         'collections': [],
        },
    ],
}


class OpenStackExtension(ModelExtension):

    """
    OpenStack Model Extension
    """

    @staticmethod
    def _get_config(key):
        return config.get(key)

    def _create_property_type(self, property_type_config):
        kwargs = {}
        self._dict_to_dict(property_type_config, 'regex', kwargs)
        self._dict_to_dict(property_type_config, 'validators', kwargs)
        return PropertyType(property_type_config['id'], **kwargs)

    def define_property_types(self):
        property_types = []
        for property_type_config in self._get_config('property_types'):
            property_type = self._create_property_type(property_type_config)
            property_types.append(property_type)
        return property_types

    def _dict_to_dict_keys(self, from_dict, keys, to_dict):
        for key in keys:
            self._dict_to_dict(from_dict, key, to_dict)

    @staticmethod
    def _dict_to_dict(from_dict, key, to_dict, to_key=None):
        """ Copy from one dict to another if present """
        if to_key is None:
            to_key = key
        if from_dict.get(key):
            to_dict[to_key] = from_dict[key]

    def _create_item_type(self, item_type_config):
        item_kwargs = {}
        self._dict_to_dict(item_type_config, 'extends',
                           item_kwargs, to_key='extend_item')
        self._dict_to_dict(item_type_config, 'description',
                           item_kwargs, to_key='item_description')
        if 'properties' in item_type_config:
            self._add_properties(item_type_config.get('properties'),
                                 item_kwargs)
        if 'views' in item_type_config:
            self._add_views(item_type_config.get('views'), item_kwargs)
        if 'collections' in item_type_config:
            self._add_collections(item_type_config.get('collections'),
                                  item_kwargs)
        if 'children' in item_type_config:
            self._add_children(item_type_config.get('children'),
                               item_kwargs)
        if 'validators' in item_type_config:
            item_kwargs['validators'] = item_type_config.get('validators')
        item_type = ItemType(item_type_config['id'], **item_kwargs)
        return item_type

    def _add_properties(self, properties, item_kwargs):
        for property_config in properties:
            property_item = self._create_property(property_config)
            item_kwargs[property_config['name']] = property_item

    def _create_property(self, property_config):
        property_kwargs = {}
        self._dict_to_dict(property_config, 'description',
                           property_kwargs, to_key='prop_description')
        pass_through_keys = ['default', 'required', 'deprecated',
                             'updatable_plugin', 'updatable_rest']
        self._dict_to_dict_keys(property_config, pass_through_keys,
                                property_kwargs)
        property_item = Property(property_config['type'], **property_kwargs)
        return property_item

    def _add_views(self, views, item_kwargs):
        for view_config in views:
            view_item = self._create_view(view_config)
            item_kwargs[view_config['name']] = view_item

    def _create_view(self, view_config):
        view_kwargs = {}
        self._dict_to_dict(view_config, 'view_description',
                           view_kwargs, to_key='view_description')
        pass_through_keys = ['deprecated']
        self._dict_to_dict_keys(view_config, pass_through_keys,
                                view_kwargs)
        view_item = View(view_config['prop_type_id'],
                         view_config['callable_method'],
                         **view_kwargs)
        return view_item

    def _add_collections(self, collections, item_kwargs):
        for collection_config in collections:
            collection = self._create_collection(collection_config)
            item_kwargs[collection_config['id']] = collection

    def _create_collection(self, collection_config):
        collection_kwargs = {}
        pass_through_keys = ['min_count', 'max_count',
                             'require', 'deprecated']
        self._dict_to_dict_keys(collection_config, pass_through_keys,
                                collection_kwargs)
        collection_item = Collection(collection_config['type'],
                                     **collection_kwargs)
        return collection_item

    def _add_children(self, children, item_kwargs):
        for child_config in children:
            child = self._create_child(child_config)
            item_kwargs[child_config['id']] = child

    def _create_child(self, child_config):
        child_kwargs = {}
        pass_through_keys = ['require', 'deprecated']
        self._dict_to_dict_keys(child_config, pass_through_keys,
                                child_kwargs)
        child_item = Child(child_config['type'],
                           **child_kwargs)
        return child_item

    def define_item_types(self):
        item_types = []
        for item_type_config in self._get_config('item_types'):
            item_type = self._create_item_type(item_type_config)
            item_types.append(item_type)
        return item_types
