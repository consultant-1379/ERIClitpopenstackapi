##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


import unittest
from openstack_extension import openstackextension as ext
from openstack_extension.openstackextension import OpenStackExtension


class TestOpenStackExtension(unittest.TestCase):

    def setUp(self):
        self.ext = OpenStackExtension()

    def test_property_types_registered(self):
        prop_types_expected = []
        if 'property_types' in ext.config:
            property_types_config = ext.config['property_types']
            for property_type_config in property_types_config:
                prop_types_expected.append(property_type_config['id'])
        prop_types = [pt.property_type_id for pt in
                      self.ext.define_property_types()]
        self.assertEquals(prop_types_expected, prop_types)

    def test_item_types_registered(self):
        item_types_expected = []
        if 'item_types' in ext.config:
            item_types_config = ext.config['item_types']
            for item_type_config in item_types_config:
                item_types_expected.append(item_type_config['id'])
        item_types = [it.item_type_id for it in
                      self.ext.define_item_types()]
        self.assertEquals(item_types_expected, item_types)

    def test_property_and_item_types_registered_with_config(self):
        ext.config = {
            'property_types': [
                {'id': 'example_property_type_id',
                 'regex':  r"^[1-9][0-9]{0,}G$",
                 'validators': [],
                 },
            ],
            'item_types': [
                {'id': 'example-item-type',
                 'extends': 'software-item',
                 'description':  "Example item type.",
                 'properties': [
                     {'name': 'name',
                      'type': 'basic_string',
                      'description': 'Name of item.',
                      'required': True,
                      'default': 'abc',
                      'validators': [],
                      },
                 ],
                 'collections': [
                     {'id': 'databases',
                      'type': 'database-item',
                      'min_count': 1,
                      'max_count': 100,
                      },
                 ],
                 'validators': [],
                 'views': [],
                 },
            ],
        }
        self.test_property_types_registered()
        self.test_item_types_registered()

if __name__ == '__main__':
    unittest.main()
