#!/usr/bin/env python

"""
Helpers for the subpackage brother_ql.backends

* device discovery
* printing
"""

import logging, time

from brother_ql.backends import backend_factory, guess_backend
from brother_ql.reader import interpret_response

logger = logging.getLogger(__name__)

def discover(backend_identifier="pyusb"):
    if backend_identifier is None:
        logger.info("Backend for discovery not specified, defaulting to pyusb")
        backend_identifier = "pyusb"
    be = backend_factory(backend_identifier)
    list_available_devices = be['list_available_devices']
    BrotherQLBackend       = be['backend_class']
    available_devices = list_available_devices()
    return available_devices

def send(instructions, printer_identifier=None, backend_identifier=None, blocking=True):
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
        except:
            logger.info("No backend stated. Selecting the default pyusb backend.")
            selected_backend = "pyusb"

    be = backend_factory(selected_backend)
    list_available_devices = be['list_available_devices']
    BrotherQLBackend       = be['backend_class']

    printer = BrotherQLBackend(printer_identifier)

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


def status(
    printer_identifier=None,
    backend_identifier=None,
):
    """
    Retrieve status info from the printer, including model and currently loaded media size.

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
            logger.info("No backend stated. Selecting the default pyusb backend.")
            selected_backend = "pyusb"
    if selected_backend == "network":
        # Not implemented due to lack of an available test device
        raise NotImplementedError

    be = backend_factory(selected_backend)
    BrotherQLBackend = be["backend_class"]
    printer = BrotherQLBackend(printer_identifier)

    logger.info("Sending status information request to the printer.")
    printer.write(b"\x1b\x69\x53")  # "ESC i S" Status information request
    data = printer.read()
    try:
        result = interpret_response(data)
    except ValueError:
        logger.error("Failed to parse response data: %s", data)

    logger.info(f"Printer Series Code: 0x{result["series_code"]:02x}")
    logger.info(f"Printer Model Code: 0x{result["model_code"]:02x}")
    logger.info(f"Printer Status Type: {result["status_type"]} ")
    logger.info(f"Printer Phase Type: {result["phase_type"]})")
    logger.info(f"Printer Errors: {result["errors"]}")
    logger.info(f"Media Type: {result["media_type"]}")
    logger.info(f"Media Size: {result["media_width"]} x {result["media_length"]} mm")

    return result
