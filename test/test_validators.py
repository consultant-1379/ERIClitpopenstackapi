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

from litp.core.validators import ValidationError

from openstack_extension.openstackextension import (URLFormatValidator,
                                                    DiskFormatValidator,
                                                    PortValidator,
                                                    IPVersionValidator,
                                                    IPv4OrIPv6NetworkValidator,
                                                    MatchAddressAndIPVersionValidator)


class TestMatchAddressAndIPVersionValidator(unittest.TestCase):

    def setUp(self):
        self.validator = MatchAddressAndIPVersionValidator()

    def test_match_address_and_version_ip(self):
        v = self.validator
        properties = {'ip_version': "6", 'cidr': '10.10.10.0/24'}
        self.assertFalse(v.validate(properties) is None)
        properties = {'ip_version': "4", 'cidr': '10.10.10.0/24'}
        self.assertTrue(v.validate(properties) is None)
        properties = {'ip_version': "6", 'cidr': '2001:db8::/32'}
        self.assertTrue(v.validate(properties) is None)
        properties = {'ip_version': "4", 'cidr': '2001:db8::/32'}
        self.assertFalse(v.validate(properties) is None)


class TestIPv4OrIPv6NetworkValidator(unittest.TestCase):

    def setUp(self):
        self.validator = IPv4OrIPv6NetworkValidator()

    def test_valid_cidr_(self):
        v = self.validator
        self.assertTrue(isinstance(v.validate("121DA:00D3:0000:2F3B"),
                        ValidationError))
        self.assertTrue(isinstance(v.validate("1233456"), ValidationError))
        self.assertTrue(v.validate('21DA:00D3:0000:2F3B::/64') is None)
        self.assertTrue(v.validate('2001:db8::/32') is None)
        self.assertTrue(v.validate('10.10.0.0/24') is None)
        self.assertTrue(isinstance(v.validate("121DA:00D3:0000:2F3B::/64"),
                        ValidationError))
        self.assertTrue(isinstance(v.validate("2a001:db8::/32"),
                        ValidationError))


class TestIPVersionValidator(unittest.TestCase):

    def setUp(self):
        self.validator = IPVersionValidator()

    def test_valid_ip_version(self):
        v = self.validator
        self.assertTrue(v.validate("4") is None)
        self.assertTrue(v.validate("6") is None)
        self.assertTrue(isinstance(v.validate("5"), ValidationError))
        self.assertTrue(isinstance(v.validate("7"), ValidationError))
        self.assertTrue(isinstance(v.validate("a"), ValidationError))


class TestURLFormatValidator(unittest.TestCase):

    def setUp(self):
        self.validator = URLFormatValidator()

    def test_valid_url_format(self):
        v = self.validator
        self.assertFalse(v._valid_url_format(""))
        self.assertFalse(v._valid_url_format("/"))
        self.assertFalse(v._valid_url_format("file://"))
        self.assertTrue(v._valid_url_format("file:///some/f.img"))
        self.assertTrue(v._valid_url_format("http://ex.com/img.img"))
        self.assertTrue(v._valid_url_format("file:///tmp/"
                                            "cirros-0.3.2-x86_64-disk.img"))

    def test_validator_throws_error(self):
        v = self.validator
        self.assertTrue(isinstance(v.validate(""), ValidationError))


class TestDiskFormatValidator(unittest.TestCase):

    def setUp(self):
        self.validator = DiskFormatValidator()

    def test_valid_disk_format(self):
        v = self.validator
        validate = "a"
        self.assertTrue(isinstance(v.validate(validate), ValidationError))
        validate = "pepe"
        self.assertTrue(isinstance(v.validate(validate), ValidationError))

        validate = "raw"
        self.assertTrue(v.validate(validate) is None)
        validate = "qcow2"
        self.assertTrue(v.validate(validate) is None)

if __name__ == '__main__':
    unittest.main()


class TestPortValidator(unittest.TestCase):

    def setUp(self):
        self.validator = PortValidator()

    def test_valid_port_format(self):
        v = self.validator
        validate = -1
        self.assertTrue(isinstance(v.validate(validate), ValidationError))
        validate = 0
        self.assertTrue(isinstance(v.validate(validate), ValidationError))
        validate = 123123
        self.assertTrue(isinstance(v.validate(validate), ValidationError))

        validate = 80
        self.assertTrue(v.validate(validate) is None)
        validate = 1
        self.assertTrue(v.validate(validate) is None)
        validate = 65535
        self.assertTrue(v.validate(validate) is None)

    def test_validator_throws_error(self):
        v = self.validator
        self.assertTrue(isinstance(v.validate(""), ValidationError))

if __name__ == '__main__':
    unittest.main()
