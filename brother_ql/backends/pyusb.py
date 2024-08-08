#!/usr/bin/env python

"""
Backend to support Brother QL-series printers via PyUSB.
Works on Mac OS X and Linux.

Requires PyUSB: https://github.com/walac/pyusb/
Install via `pip install pyusb`
"""

import time
import sys
import usb.core
import usb.util
import logging

logger = logging.getLogger(__name__)
from .generic import BrotherQLBackendGeneric

BROTHER_VID = 0x04f9

def list_available_devices(ums_warning=True):
    """
    List all available devices for the respective backend

    :param bool ums_warning: enable warinings when printers in P-Touch Editor Lite are detected

    returns: devices: a list of dictionaries with the keys 'identifier' and 'instance': \
        [ {'identifier': 'usb://0x04f9:0x2015/C5Z315686', 'instance': pyusb.core.Device()}, ]
        The 'identifier' is of the format idVendor:idProduct/iSerialNumber.
    """

    class find_class(object):
        def __init__(self, class_):
            self._class = class_
        def __call__(self, device):
            # first, let's check the device
            if device.bDeviceClass == self._class:
                return True
            # ok, transverse all devices to find an interface that matches our class
            for cfg in device:
                # find_descriptor: what's it?
                intf = usb.util.find_descriptor(cfg, bInterfaceClass=self._class)
                if intf is not None:
                    return True
            return False

    # get a list of Brother printers with the printer class
    printers = usb.core.find(find_all=1, custom_match=find_class(usb.CLASS_PRINTER), idVendor=BROTHER_VID)
    ums_printers = usb.core.find(find_all=1, custom_match=find_class(usb.CLASS_MASS_STORAGE), idVendor=BROTHER_VID)

    def get_descriptor(dev, descriptor):
        result = None
        try:
            result = usb.util.get_string(dev, descriptor)
        except ValueError:
            # Sometimes this is caused by a permission issue, but some printers (such as the QL-700 in ums mode)
            # are not compliant with the USB spec and won't present a LANGID array. Hard-code US English and try again.
            result = usb.util.get_string(dev, descriptor, langid=0x0409)
        if result is None:
            logger.warn("Cannot read device descriptor string, possible permission issue.")
        return result

    def identifier(dev):
        serial = get_descriptor(dev, dev.iSerialNumber)
        if serial is None:
            return 'usb://0x{:04x}:0x{:04x}'.format(dev.idVendor, dev.idProduct)
        else:
            return "usb://0x{:04x}:0x{:04x}/{}".format(
                dev.idVendor, dev.idProduct, serial
            )

    if ums_warning and ums_printers is not None:
        for p in ums_printers:
            logger.warn(f"Detected USB label printer in the unsupported P-Touch Editor Lite mode: {get_descriptor(p, p.iProduct)}")
            logger.warn("Disable P-Touch Editor Lite mode by holding down the corresponding button on the printer until the light goes off.")

    return [{'identifier': identifier(printer), 'instance': printer} for printer in printers]

class BrotherQLBackendPyUSB(BrotherQLBackendGeneric):
    """
    BrotherQL backend using PyUSB
    """

    def __init__(self, device_specifier):
        """
        device_specifier: string or pyusb.core.Device: identifier of the \
            format usb://idVendor:idProduct/iSerialNumber or pyusb.core.Device instance.
        """

        self.dev = None
        self.read_timeout =    10. # ms
        self.write_timeout = 15000. # ms
        # strategy : try_twice or select
        self.strategy = 'try_twice'
        if isinstance(device_specifier, str):
            if device_specifier.startswith('usb://'):
                device_specifier = device_specifier[6:]
            vendor_product, _, serial = device_specifier.partition('/')
            vendor, _, product = vendor_product.partition(':')
            vendor, product = int(vendor, 16), int(product, 16)
            for result in list_available_devices(ums_warning=False):
                printer = result['instance']
                if printer.idVendor == vendor and printer.idProduct == product or (serial and printer.iSerialNumber == serial):
                    self.dev = printer
                    break
            if self.dev is None:
                raise ValueError('Device not found')
        elif isinstance(device_specifier, usb.core.Device):
            self.dev = device_specifier
        else:
            raise NotImplementedError('Currently the printer can be specified either via an appropriate string or via a usb.core.Device instance.')

        # Now we are sure to have self.dev around, start using it:

        try:
            assert self.dev.is_kernel_driver_active(0)
            logger.debug("Detaching kernel driver")
            self.dev.detach_kernel_driver(0)
            self.was_kernel_driver_active = True
        except (NotImplementedError, AssertionError):
            self.was_kernel_driver_active = False

        try:
            # set the active configuration. With no arguments, the first configuration will be the active one
            self.dev.set_configuration()
            cfg = self.dev.get_active_configuration()
            intf = usb.util.find_descriptor(cfg, bInterfaceClass=7)
            assert intf is not None

            ep_match_in  = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            ep_match_out = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT

            ep_in  = usb.util.find_descriptor(intf, custom_match=ep_match_in)
            ep_out = usb.util.find_descriptor(intf, custom_match=ep_match_out)

            assert ep_in  is not None
            assert ep_out is not None

            self.write_dev = ep_out
            self.read_dev  = ep_in
        except (usb.core.USBError, AssertionError) as e:
            # re-attach kernel driver and exit gracefully if libusb reports errors
            logger.error(f"Cannot initialize device {device_specifier}: {e}")
            self.dispose()
            sys.exit(1)

    def _raw_read(self, length):
        # pyusb Device.read() operations return array() type - let's convert it to bytes()
        return bytes(self.read_dev.read(length))

    def _read(self, length=32):
        if self.strategy == 'try_twice':
            data = self._raw_read(length)
            if data:
                return bytes(data)
            else:
                time.sleep(self.read_timeout/1000.)
                return self._raw_read(length)
        elif self.strategy == 'select':
            data = b''
            start = time.time()
            while (not data) and (time.time() - start < self.read_timeout/1000.):
                result, _, _ = select.select([self.read_dev], [], [], 0)
                if self.read_dev in result:
                    data += self._raw_read(length)
                if data: break
                time.sleep(0.001)
            if not data:
                # one last try if still no data:
                return self._raw_read(length)
            else:
                return data
        else:
            raise NotImplementedError('Unknown strategy')

    def _write(self, data):
        self.write_dev.write(data, int(self.write_timeout))

    def _dispose(self):
        usb.util.dispose_resources(self.dev)
        del self.write_dev, self.read_dev
        if self.was_kernel_driver_active:
            logger.debug("Re-attaching kernel driver")
            self.dev.attach_kernel_driver(0)
        del self.dev
