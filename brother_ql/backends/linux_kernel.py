#!/usr/bin/env python

"""
Backend to support Brother QL-series printers via the linux kernel USB printer interface.
Works on Linux.
"""

import glob, os, time, select
import re
import logging

logger = logging.getLogger(__name__)

from .generic import BrotherQLBackendGeneric

def __parse_ieee1284_id(id: str) -> dict:
    # parse IEEE1284 ID info into a dictionary
    # MFG:Brother;CMD:PT-CBP;MDL:PT-P700;CLS:PRINTER;CID:Brother LabelPrinter TypeA1;
    # MFG:Kyocera Mita;Model:Kyocera Mita Ci-1100;COMMAND SET: POSTSCRIPT,PJL,PCL
    elements = id.split(";")[:-1] # discard the last blank element
    return {kv[0].casefold(): kv[1] for kv in map(lambda s: s.split(':'), elements)}

def list_available_devices(ums_warning: bool = True) -> list:
    """
    List all available compatible devices for the linux kernel backend
    The function will attempt to read the IEEE1284 ID of all USB printers and verify:
    - Manufacturer is Brother
    - Command set is PT-CBP, aka the raster command set

    :param bool ums_warning: enable warinings when printers in P-Touch Editor Lite are detected

    returns: devices: a list of dictionaries with the keys 'identifier' and 'instance': \
        [ {'identifier': 'file:///dev/usb/lp0', 'instance': None}, ] \
        Instance is set to None because we don't want to open (and thus potentially block) the device here.
    """

    all_printer_names = [re.search('(lp\d+)$', path).group(0) for path in glob.glob('/dev/usb/lp*')]
    pt_printer_info = {}

    # read printer info into a dictionary like the following:
    # {'lp1': {'mfg': 'Brother', 'cmd': 'PT-CBP', 'mdl': 'QL-700', 'cls': 'PRINTER'}}
    for name in all_printer_names:
        printer_path = f"/dev/usb/{name}"
        id_path = f"/sys/class/usbmisc/{name}/device/ieee1284_id"
        info = None
        try:
            with open(id_path, "r") as f:
                info = __parse_ieee1284_id(f.read())
        except FileNotFoundError:
            logger.warn(f"Unable to retrieve device info for printer {name}, cannot check for compatibility.")
            continue

        # check IEEE1284 MFG and CMD fields
        manufacturer = ''
        for m in 'mfg', 'manufacturer':
            if info.get(m) is not None:
                manufacturer = info.get(m)

        model = ''
        for m in 'model', 'mdl':
            if info.get(m) is not None:
                model = info.get(m)

        command_set = ''
        for c in 'cmd', 'command set':
            if info.get(c) is not None:
                command_set = info.get(c)

        logger.debug(f"Checking printer {info}")
        if manufacturer == 'Brother' and 'PT-CBP' in command_set:
            logger.info(f"Compatible printer at {name}: {manufacturer} {model}")
        else:
            logger.info(f"Inompatible printer at {name}: {manufacturer} {model}")
            logger.info(f"Command set: {command_set}")
            continue

        # check permissions
        if not os.access(printer_path, os.W_OK):
            logger.info(
                f"Cannot access device {printer_path} due to insufficient permissions. You need to be a part of the lp group to access printers with this backend."
            )
            continue

        # if everything is ok, add printer to the list
        pt_printer_info[name] = info

    logger.debug(pt_printer_info)
    pt_printer_names = pt_printer_info.keys()

    # P-Touch Editor Lite (ums) detection
    # look for paths created via persistent block device naming from udev
    if ums_warning:
        ums_paths = [os.path.basename(path) for path in glob.glob('/dev/disk/by-id/usb-Brother_*_*-0:0-part1')] 
        for path in ums_paths:
            try:
                model = re.search('^(?:usb-Brother_)((?:PT|QL)-[A-Z0-9]{2,5})(?:_[A-Z0-9]+-0:0-part1)$', path).group(1)
                logger.warn(f"Detected a label printer {model} in the unsupported P-Touch Editor Lite mode.")
            except (AttributeError, IndexError):
                logger.warn(f"Detected a label printer in the unsupported P-Touch Editor Lite mode at {path}")
            logger.warn("Disable P-Touch Editor Lite by holding down the corresponding button on the printer until the light goes off.")

    return [{'identifier': 'file://' + '/dev/usb/' + n, 'instance': None} for n in pt_printer_names]

class BrotherQLBackendLinuxKernel(BrotherQLBackendGeneric):
    """
    BrotherQL backend using the Linux Kernel USB Printer Device Handles
    """

    def __init__(self, device_specifier: str | int):
        """
        device_specifier: string or os.open(): identifier in the \
            format file:///dev/usb/lp0 or os.open() raw device handle.
        """

        self.read_timeout = 0.01
        # strategy : try_twice or select
        self.strategy = 'select'
        if isinstance(device_specifier, str):
            if device_specifier.startswith('file://'):
                device_specifier = device_specifier[7:]
            self.dev = os.open(device_specifier, os.O_RDWR)
        elif isinstance(device_specifier, int):
            self.dev = device_specifier
        else:
            raise NotImplementedError('Currently the printer can be specified either via an appropriate string or via an os.open() handle.')

        self.write_dev = self.dev
        self.read_dev  = self.dev

    def _write(self, data: bytes):
        os.write(self.write_dev, data)

    def _read(self, length: int = 32) -> bytes:
        if self.strategy == 'try_twice':
            data = os.read(self.read_dev, length)
            if data:
                return data
            else:
                time.sleep(self.read_timeout)
                return os.read(self.read_dev, length)
        elif self.strategy == 'select':
            data = b''
            start = time.time()
            while (not data) and (time.time() - start < self.read_timeout):
                result, _, _ = select.select([self.read_dev], [], [], 0)
                if self.read_dev in result:
                    data += os.read(self.read_dev, length)
                if data: break
                time.sleep(0.001)
            if not data:
                # one last try if still no data:
                return os.read(self.read_dev, length)
            else:
                return data
        else:
            raise NotImplementedError('Unknown strategy')

    def _dispose(self):
        os.close(self.dev)
