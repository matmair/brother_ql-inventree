#!/usr/bin/env python

"""
Helpers for the subpackage brother_ql.backends

* device discovery
* printing
"""

import logging, time

from brother_ql.backends import backend_factory, guess_backend
from brother_ql.reader import interpret_response
from brother_ql.backends import BrotherQLBackendGeneric

logger = logging.getLogger(__name__)

def discover(backend_identifier: str = 'linux_kernel') -> list:
    if backend_identifier is None:
        logger.info("Backend for discovery not specified, defaulting to linux_kernel.")
        backend_identifier = "linux_kernel"
    be = backend_factory(backend_identifier)
    list_available_devices = be['list_available_devices']
    BrotherQLBackend       = be['backend_class']
    available_devices = list_available_devices()
    return available_devices

def send(instructions: bytes, printer_identifier: str = None, backend_identifier: str = None, blocking: bool = True):
    """
    Send instruction bytes to a printer.

    :param bytes instructions: The instructions to be sent to the printer.
    :param str printer_identifier: Identifier for the printer.
    :param str backend_identifier: Can enforce the use of a specific backend.
    :param bool blocking: Indicates whether the function call should block while waiting for the completion of the printing.
    """

    status = {
      'instructions_sent': True, # The instructions were sent to the printer.
      'outcome': 'unknown', # String description of the outcome of the sending operation like: 'unknown', 'sent', 'printed', 'error'
      'printer_state': None, # If the selected backend supports reading back the printer state, this key will contain it.
      'did_print': False, # If True, a print was produced. It defaults to False if the outcome is uncertain (due to a backend without read-back capability).
      'ready_for_next_job': False, # If True, the printer is ready to receive the next instructions. It defaults to False if the state is unknown.
    }
    selected_backend = None
    if backend_identifier:
        selected_backend = backend_identifier
    else:
        try:
            selected_backend = guess_backend(printer_identifier)
        except ValueError:
            logger.info("No backend stated. Selecting the default linux_kernel backend.")
            selected_backend = 'linux_kernel'

    be = backend_factory(selected_backend)
    list_available_devices = be['list_available_devices']
    BrotherQLBackend       = be['backend_class']

    printer: BrotherQLBackendGeneric = BrotherQLBackend(printer_identifier)

    start = time.time()
    logger.info('Sending instructions to the printer. Total: %d bytes.', len(instructions))
    printer.write(instructions)
    status['outcome'] = 'sent'

    if not blocking:
        return status
    if selected_backend == 'network':
        """ No need to wait for completion. The network backend doesn't support readback. """
        return status

    while time.time() - start < 10:
        data = printer.read()
        if not data:
            time.sleep(0.005)
            continue
        try:
            result = interpret_response(data)
        except ValueError:
            logger.error("TIME %.3f - Couln't understand response: %s", time.time()-start, data)
            continue
        status['printer_state'] = result
        logger.debug('TIME %.3f - result: %s', time.time()-start, result)
        if result['errors']:
            logger.error('Errors occured: %s', result['errors'])
            status['outcome'] = 'error'
            break
        if result['status_type'] == 'Printing completed':
            status['did_print'] = True
            status['outcome'] = 'printed'
        if result['status_type'] == 'Phase change' and result['phase_type'] == 'Waiting to receive':
            status['ready_for_next_job'] = True
        if status['did_print'] and status['ready_for_next_job']:
            break

    if not status['did_print']:
        logger.warning("'printing completed' status not received.")
    if not status['ready_for_next_job']:
        logger.warning("'waiting to receive' status not received.")
    if (not status['did_print']) or (not status['ready_for_next_job']):
        logger.warning('Printing potentially not successful?')
    if status['did_print'] and status['ready_for_next_job']:
        logger.info("Printing was successful. Waiting for the next job.")

    return status

def get_printer(
    printer_identifier: str = None,
    backend_identifier: str = None,
) -> BrotherQLBackendGeneric:
    """
    Instantiate a printer object for communication. Only bidirectional transport backends are supported.

    :param str printer_identifier: Identifier for the printer.
    :param str backend_identifier: Can enforce the use of a specific backend.
    """

    selected_backend = None
    if backend_identifier:
        selected_backend = backend_identifier
    else:
        try:
            selected_backend = guess_backend(printer_identifier)
        except ValueError:
            logger.info("No backend stated. Selecting the default linux_kernel backend.")
            selected_backend = "linux_kernel"
    if selected_backend == "network":
        # Not implemented due to lack of an available test device
        raise NotImplementedError

    be = backend_factory(selected_backend)
    BrotherQLBackend = be["backend_class"]
    printer = BrotherQLBackend(printer_identifier)
    return printer

def get_status(
    printer: BrotherQLBackendGeneric,
    receive_only: bool = False,
    target_status: int = None,
) -> dict:
    """
    Get printer status.

    :param BrotherQLBackendGeneric printer: A printer instance.
    :param bool receive_only: Don't send the status request command.
    :param int target_status: Expected status code.
    """

    result = {}
    if not receive_only:
        printer.write(b"\x1b\x69\x53")  # "ESC i S" Status information request
    data = printer.read()
    try:
        result = interpret_response(data)
    except ValueError:
        logger.error("Failed to parse response data: %s", data)
    if target_status is not None:
        if result['status_code'] != target_status:
            raise ValueError(f"Printer reported 0x{result['status_code']:02x} status instead of 0x{target_status:02x}")
    return result


def get_setting(
    printer: BrotherQLBackendGeneric,
    setting: int,
    payload: bytes = None,
) -> dict:
    """
    Get setting from printer.

    :param BrotherQLBackendGeneric printer: A printer instance.
    :param int setting: The code for the setting.
    :param bytes payload: Optional additional payload, usually not required.
    """

    # ensure printer is free of errors before proceeding
    get_status(printer, target_status=0x0)
    # switch to raster command mode
    printer.write(b"\x1b\x69\x61\x01")
    # send command
    # 0x1b 0x69 0x55 setting
    # u8 setting
    # 0x01 read
    # optional extra payload
    command = b"\x1b\x69\x55" + setting.to_bytes(1, "big") + b"\x01"
    if payload is not None:
        command += payload
    printer.write(command)
    result = get_status(printer, receive_only=True, target_status=0xF0)
    return result


def write_setting(
    printer: BrotherQLBackendGeneric,
    setting: int,
    payload: bytes,
) -> dict:
    """
    Write setting to printer.

    :param BrotherQLBackendGeneric printer: A printer instance.
    :param int setting: The code for the setting.
    :param bytes payload: Payload for the setting.
    """

    # switch to raster command mode
    printer.write(b"\x1b\x69\x61\x01")
    # write settings
    # 0x1b 0x69 0x55 setting
    # u8 setting
    # 0x0 write
    # payload (size dependent on setting and machine series)
    command = b"\x1b\x69\x55" + setting.to_bytes(1, 'big') + b"\x00"
    command += payload
    printer.write(command)
    # retrieve status to make sure no errors occured
    result = get_status(printer)
    if result['status_code'] != 0x0:
        raise ValueError("Failed to modify settings")
    return result


def configure(
    printer_identifier=None,
    backend_identifier=None,
    action="get",
    key=None,
    value=None,
):
    """
    Read or modify power settings.

    :param str printer_identifier: Identifier for the printer
    :param str backend_identifier: Can enforce the use of a specific backend
    :param str action: Action to perform, get or set
    :param str key: Key name for the settings
    :param int value: Value to update for the specified key
    """

    printer=get_printer(printer_identifier, backend_identifier)

    if action not in ['get', 'set']:
        raise ValueError(f"Invalid action '{action}'")
    if key not in ['power-off-delay', 'auto-power-on']:
        raise ValueError(f"Invalid key '{key}'")
    if action == 'set':
        if value is None:
            raise ValueError(f"Specify a valid value for key '{key}'")

    series_code = get_status(printer, target_status=0x0)['series_code']

    if action == 'set':
        if key == 'auto-power-on':
            payload = value.to_bytes(1, "big")
            write_setting(printer, 0x70, payload)
            get_status(printer, 0x0)
        elif key == 'power-off-delay':
            payload = b''
            # 0x30 series needs an extra byte here
            if series_code == 0x30:
                payload += b"\x00"
            payload += value.to_bytes(1, "big")
            write_setting(printer, 0x41, payload)
            get_status(printer, 0x0)
        else:
            raise ValueError(f"Key {key} is invalid")

    # retrieve settings
    retrieved_val = None
    if key == 'auto-power-on':
        retrieved_val = get_setting(printer, 0x70)['setting']
    elif key == 'power-off-delay':
        payload = b''
        # 0x30 series needs an extra byte here
        if series_code == 0x30:
            payload += b"\x00"
        retrieved_val = get_setting(printer, 0x41, payload)['setting']
    else:
        raise ValueError(f"Key {key} is invalid")

    logger.info(f"{key}: {retrieved_val}")
    return retrieved_val
