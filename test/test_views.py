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
import mock
from openstack_extension.openstackextension import security_groups_view


class TestViews(unittest.TestCase):

    def setUp(self):
        self.security_groups_view = security_groups_view
        self.plugin_api_context = mock.Mock()
        self.query_item = mock.Mock(security_group_names=None)
        self.sg1 = mock.Mock()
        self.sg1.name = 'a'
        self.sg2 = mock.Mock()
        self.sg2.name = 'b'

    def test_security_groups_view_returns_empty(self):
        self.assertEquals([], self.security_groups_view(
            self.plugin_api_context, self.query_item))

    def test_security_groups_view_returns_groups(self):
        self.plugin_api_context.query.side_effect = [[self.sg1], [self.sg2]]
        self.query_item.security_group_names = 'a,b'
        self.assertEquals([self.sg1, self.sg2],
            self.security_groups_view(self.plugin_api_context,
                self.query_item))

if __name__ == '__main__':
    unittest.main()
