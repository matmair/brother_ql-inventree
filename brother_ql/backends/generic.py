import logging

logger = logging.getLogger(__name__)

def list_available_devices(ums_warning: bool = True) -> list:
    """ List all available devices for the respective backend """
    # returns a list of dictionaries with the keys 'identifier' and 'instance':
    # [ {'identifier': '/dev/usb/lp0', 'instance': os.open('/dev/usb/lp0', os.O_RDWR)}, ]
    raise NotImplementedError()


class BrotherQLBackendGeneric(object):

    def __init__(self, device_specifier: str):
        """
        device_specifier can be either a string or an instance
        of the required class type.
        """
        self.write_dev = None
        self.read_dev  = None
        raise NotImplementedError()

    def _write(self, data: bytes):
        self.write_dev.write(data)

    def _read(self, length: int = 32) -> bytes:
        return bytes(self.read_dev.read(length))

    def write(self, data: bytes):
        logger.debug('Writing %d bytes.', len(data))
        self._write(data)

    def read(self, length: int = 32) -> bytes:
        try:
            ret_bytes = self._read(length)
            if ret_bytes: logger.debug('Read %d bytes.', len(ret_bytes))
            return ret_bytes
        except Exception as e:
            logger.debug('Error reading... %s', e)
            raise

    def dispose(self):
        try:
            self._dispose()
        except Exception:
            pass

    def _dispose(self):
        raise NotImplementedError()

    def __del__(self):
        self.dispose()

    def list_available_devices(self) -> list:
        raise NotImplementedError()