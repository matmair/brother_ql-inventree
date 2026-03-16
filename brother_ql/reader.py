#!/usr/bin/env python

import struct
import io
import logging
import sys
from brother_ql.models import ModelsManager

from PIL import Image
from PIL.ImageOps import colorize

logger = logging.getLogger(__name__)

OPCODES = {
    # signature              name    following bytes   description
    b'\x00':                 ("preamble",       -1, "Preamble, 200-300x 0x00 to clear comamnd buffer"),
    b'\x4D':                 ("compression",     1, ""),
    b'\x67':                 ("raster QL",         -1, ""),
    b'\x47':                 ("raster P-touch",    -1, ""),
    b'\x77':                 ("2-color raster QL", -1, ""),
    b'\x5a':                 ("zero raster",     0, "empty raster line"),
    b'\x0C':                 ("print",           0, "print intermediate page"),
    b'\x1A':                 ("print",           0, "print final page"),
    b'\x1b\x40':             ("init",            0, "initialization"),
    b'\x1b\x69\x61':         ("mode setting",    1, ""),
    b'\x1b\x69\x21':         ("automatic status",1, ""),
    b'\x1b\x69\x7A':         ("media/quality",  10, "print-media and print-quality"),
    b'\x1b\x69\x4D':         ("various",         1, "Auto cut flag in bit 7"),
    b'\x1b\x69\x41':         ("cut-every",       1, "cut every n-th page"),
    b'\x1b\x69\x4B':         ("expanded",        1, ""),
    b'\x1b\x69\x64':         ("margins",         2, ""),
    b'\x1b\x69\x55\x77\x01': ('amedia',        127, "Additional media information command"),
    b'\x1b\x69\x55\x41':     ('auto_power_off',       -1, "Auto power off setting command"),
    b'\x1b\x69\x55\x4A':     ('jobid',          14, "Job ID setting command"),
    b'\x1b\x69\x55\x70':     ('auto_power_on',       -1, "Auto power on setting command"),
    b'\x1b\x69\x58\x47':     ("request_config",  0, "Request transmission of .ini config file of printer"),
    b'\x1b\x69\x6B\x63':     ("number_of_copies",  2, "Internal specification commands"),
    b'\x1b\x69\x53':         ('status request',  0, "A status information request sent to the printer"),
    b'\x80\x20\x42':         ('status response',29, "A status response received from the printer"),
}

dot_widths = {
  62: 90*8,
}

RESP_ERROR_INFORMATION_1_DEF = {
  0: 'No media when printing',
  1: 'End of media (die-cut size only)',
  2: 'Tape cutter jam',
  3: 'Weak batteries',
  4: 'Main unit in use (QL-560/650TD/1050)',
  5: 'Printer turned off',
  6: 'High-voltage adapter (not used)',
  7: 'Fan doesn\'t work (QL-1050/1060N)',
}

RESP_ERROR_INFORMATION_2_DEF = {
  0: 'Replace media error',
  1: 'Expansion buffer full error',
  2: 'Transmission / Communication error',
  3: 'Communication buffer full error (not used)',
  4: 'Cover opened while printing (Except QL-500)',
  5: 'Cancel key (not used) or Overheating error (PT-E550W/P750W/P710BT)',
  6: 'Media cannot be fed (also when the media end is detected)',
  7: 'System error',
}

RESP_MEDIA_TYPES = {
  0x00: 'No media',
  0x01: 'Laminated tape',
  0x03: 'Non-laminated type',
  0x04: 'Fabric tape',
  0x11: 'Heat-Shrink Tube (HS 2:1)',
  0x13: 'Fle tape',
  0x14: 'Flexible ID tape',
  0x15: 'Satin tape',
  0x17: 'Heat-Shrink Tube (HS 3:1)',
  0x0A: 'Continuous length tape',
  0x0B: 'Die-cut labels',
  0x4A: 'Continuous length tape',
  0x4B: 'Die-cut labels',
  0xFF: 'Incompatible tape',
}

RESP_MEDIA_CATEGORIES = {
  0x00: 'No media',
  0x01: 'TZe', # probably also HGe (high grade)
  0x03: 'TZe', # probably also STe (stencil)
  0x04: 'TZe',
  0x11: 'HSe',
  0x13: 'Fle',
  0x14: 'TZe',
  0x15: 'TZe',
  0x17: 'HSe',
  0x0A: 'DK',
  0x0B: 'DK',
  0x4A: 'DK', # RD for TD series
  0x4B: 'DK', # RD for TD series
  0xFF: 'Incompatible',
}

RESP_TAPE_COLORS = {
  0x00: 'No Media',
  0x01: 'White',
  0x02: 'Other',
  0x03: 'Clear',
  0x04: 'Red',
  0x05: 'Blue',
  0x06: 'Yellow',
  0x07: 'Green',
  0x08: 'Black',
  0x09: 'Clear(White text)',
  0x20: 'Matte White',
  0x21: 'Matte Clear',
  0x22: 'Matte Silver',
  0x23: 'Satin Gold',
  0x24: 'Satin Silver',
  0x30: 'Blue(D)',
  0x31: 'Red(D)',
  0x40: 'Fluorescent Orange',
  0x41: 'Fluorescent Yellow',
  0x50: 'Berry Pink(S)',
  0x51: 'Light Gray(S)',
  0x52: 'Lime Green(S)',
  0x60: 'Yellow(F)',
  0x61: 'Pink(F)',
  0x62: 'Blue(F)',
  0x70: 'White(Heat-shrink Tube)',
  0x90: 'White(Flex. ID)',
  0x91: 'Yellow(Flex. ID)',
  0xF0: 'Cleaning',
  0xF1: 'Stencil',
  0xFF: 'Incompatible',
}

RESP_TEXT_COLORS = {
  0x00: 'No Media',
  0x01: 'White',
  0x04: 'Red',
  0x05: 'Blue',
  0x08: 'Black',
  0x0A: 'Gold',
  0x62: 'Blue(F)',
  0xF0: 'Cleaning',
  0xF1: 'Stencil',
  0x02: 'Other',
  0xFF: 'Incompatible',
}

RESP_STATUS_TYPES = {
  0x00: 'Reply to status request',
  0x01: 'Printing completed',
  0x02: 'Error occurred',
  0x03: 'Exit IF mode',
  0x04: 'Turned off',
  0x05: 'Notification',
  0x06: 'Phase change',
  0xF0: 'Settings report',
}

RESP_PHASE_TYPES = {
  0x00: 'Waiting to receive',
  0x01: 'Printing state',
}

RESP_BYTE_NAMES = [
  'Print head mark (0x80)',
  'Size (0x20)',
  'Brother code (B=0x42)',
  'Series code',
  'Model code',
  'Country code',
  'Power status',
  'Reserved',
  'Error information 1',
  'Error information 2',
  'Media width',
  'Media type',
  'Number of colors',
  'Media length (high)',
  'Media sensor value',
  'Mode',
  'Density',
  'Media length (low)',
  'Status type',
  'Phase type',
  'Phase number (high)',
  'Phase number (low)',
  'Notification number',
  'Expansion area',
  'Tape color information',
  'Text color information',
  'Hardware settings 1',
  'Hardware settings 2',
  'Hardware settings 3',
  'Hardware settings 4',
  'Requested setting',
  'Reserved',
]

def hex_format(data: bytes) -> str:
    return ' '.join('{:02X}'.format(byte) for byte in data)

def chunker(data, raise_exception: bool = False):
    """
    Breaks data stream (bytes) into a list of bytes objects containing single instructions each.

    Logs warnings for unknown opcodes or raises an exception instead, if raise_exception is set to True.

    returns: list of bytes objects
    """
    instructions = []
    data = bytes(data)
    while True:
        if len(data) == 0: break
        try:
            opcode = match_opcode(data)
        except KeyError:
            msg = 'unknown opcode starting with {}...)'.format(hex_format(data[0:4]))
            if raise_exception:
                raise ValueError(msg)
            else:
                logger.warning(msg)
                data = data[1:]
                continue
        opcode_def = OPCODES[opcode]
        num_bytes = len(opcode)
        if opcode_def[1] > 0: num_bytes += opcode_def[1]
        elif opcode_def[0] in ('raster QL', '2-color raster QL'):
            num_bytes += data[2] + 2
        elif opcode_def[0] in ('raster P-touch',):
            num_bytes += data[1] + data[2]*256 + 2
        #payload = data[len(opcode):num_bytes]
        instructions.append(data[:num_bytes])
        yield instructions[-1]
        data = data[num_bytes:]
    #return instructions

def match_opcode(data: bytes):
    matching_opcodes = [opcode for opcode in OPCODES.keys() if data.startswith(opcode)]
    assert len(matching_opcodes) == 1
    return matching_opcodes[0]

def interpret_response(data: bytes) -> dict:
    data = bytes(data)
    if len(data) < 32:
        raise NameError('Insufficient amount of data received', hex_format(data))
    if not data.startswith(b'\x80\x20\x42'):
        raise NameError("Printer response doesn't start with the usual header (80:20:42)", hex_format(data))
    for i, byte_name in enumerate(RESP_BYTE_NAMES):
        logger.debug('Byte %2d %24s %02X', i, byte_name+':', data[i])
    series_code = data[3]
    model_code = data[4]

    # printer model detection
    model = "Unknown"
    for m in ModelsManager().iter_elements():
        if series_code == m.series_code and model_code == m.model_code:
            model = m.identifier
            break

    errors = []
    error_info_1 = data[8]
    error_info_2 = data[9]
    for error_bit in RESP_ERROR_INFORMATION_1_DEF:
        if error_info_1 & (1 << error_bit):
            logger.error('Error: ' + RESP_ERROR_INFORMATION_1_DEF[error_bit])
            errors.append(RESP_ERROR_INFORMATION_1_DEF[error_bit])
    for error_bit in RESP_ERROR_INFORMATION_2_DEF:
        if error_info_2 & (1 << error_bit):
            logger.error('Error: ' + RESP_ERROR_INFORMATION_2_DEF[error_bit])
            errors.append(RESP_ERROR_INFORMATION_2_DEF[error_bit])

    media_width  = data[10]
    media_length = data[17]

    media_code = data[11]
    media_sensor = data[14]
    media_category = ""
    if media_code in RESP_MEDIA_TYPES:
        media_type = RESP_MEDIA_TYPES[media_code]
        media_category = RESP_MEDIA_CATEGORIES[media_code]
        logger.debug("Media type: %s", media_type)
    else:
        logger.error("Unknown media type %02X", media_code)

    tape_color_code = data[24]
    text_color_code = data[25]
    tape_color = ''
    text_color = ''
    if model.startswith('PT'):
        tape_color = RESP_TAPE_COLORS[tape_color_code]
        text_color = RESP_TEXT_COLORS[text_color_code]

    status_code = data[18]
    if status_code in RESP_STATUS_TYPES:
        status_type = RESP_STATUS_TYPES[status_code]
        logger.debug("Status type: %s", status_type)
    else:
        logger.error("Unknown status type %02X", status_code)

    phase_code = data[19]
    phase_type = ''
    if phase_code in RESP_PHASE_TYPES:
        phase_type = RESP_PHASE_TYPES[phase_code]
        logger.debug("Phase type: %s", phase_type)
    else:
        logger.error("Unknown phase type %02X", phase_code)

    # settings report
    setting = None
    if status_code == 0xF0:
        logger.debug("Settings report detected")
        setting = data[30]

    response = {
      'series_code': series_code,
      'model_code': model_code,
      'model': model,
      'status_type': status_type,
      'status_code': status_code,
      'phase_type': phase_type,
      'phase_code': phase_code,
      'media_type': media_type,
      'media_category': media_category,
      'media_sensor': media_sensor,
      'tape_color': tape_color,
      'text_color': text_color,
      'media_width': media_width,
      'media_length': media_length,
      'setting': setting,
      'errors': errors,
    }
    return response


def merge_specific_instructions(chunks, join_preamble: bool = True, join_raster: bool = True):
    """
    Process a list of instructions by merging subsequent instuctions with
    identical opcodes into "large instructions".
    """
    new_instructions = []
    last_opcode = None
    instruction_buffer = b''
    for instruction in chunks:
        opcode = match_opcode(instruction)
        if   join_preamble and OPCODES[opcode][0] == 'preamble' and last_opcode == 'preamble':
            instruction_buffer += instruction
        elif join_raster   and 'raster' in OPCODES[opcode][0] and 'raster' in last_opcode:
            instruction_buffer += instruction
        else:
            if instruction_buffer:
                new_instructions.append(instruction_buffer)
            instruction_buffer = instruction
        last_opcode = OPCODES[opcode][0]
    if instruction_buffer:
        new_instructions.append(instruction_buffer)
    return new_instructions

class BrotherQLReader(object):
    DEFAULT_FILENAME_FMT = 'label{counter:04d}.png'

    def __init__(self, brother_file):
        if type(brother_file) in (str,):
            brother_file = io.open(brother_file, 'rb')
        self.brother_file = brother_file
        self.mwidth, self.mheight = None, None
        self.raster_no = None
        self.black_rows = []
        self.red_rows = []
        self.compression = False
        self.page_counter = 1
        self.two_color_printing = False
        self.cut_at_end = False
        self.high_resolution_printing = False
        self.filename_fmt = self.DEFAULT_FILENAME_FMT

    def analyse(self):
        instructions = self.brother_file.read()
        for instruction in chunker(instructions):
            for opcode in OPCODES.keys():
                if instruction.startswith(opcode):
                    opcode_def = OPCODES[opcode]
                    if opcode_def[0] == 'init':
                        self.mwidth, self.mheight = None, None
                        self.raster_no = None
                        self.black_rows = []
                        self.red_rows = []
                    payload = instruction[len(opcode):]
                    logger.info(" {} ({}) --> found! (payload: {})".format(opcode_def[0], hex_format(opcode), hex_format(payload)))
                    if opcode_def[0] == 'compression':
                        self.compression = payload[0] == 0x02
                    if opcode_def[0] == 'zero raster':
                        self.black_rows.append(bytes())
                        if self.two_color_printing:
                            self.red_rows.append(bytes())
                    if opcode_def[0] in ('raster QL', '2-color raster QL', 'raster P-touch'):
                        rpl = bytes(payload[2:]) # raster payload
                        if self.compression:
                            row = bytes()
                            index = 0
                            while True:
                                num = rpl[index]
                                if num & 0x80:
                                    num = num - 0x100
                                if num < 0:
                                    num = -num + 1
                                    row += bytes([rpl[index+1]] * num)
                                    index += 2
                                else:
                                    num = num + 1
                                    row += rpl[index+1:index+1+num]
                                    index += 1 + num
                                if index >= len(rpl): break
                        else:
                            row = rpl
                        if opcode_def[0] in ('raster QL', 'raster P-touch'):
                            self.black_rows.append(row)
                        else: # 2-color
                            if   payload[0] == 0x01:
                                self.black_rows.append(row)
                            elif payload[0] == 0x02:
                                self.red_rows.append(row)
                            else:
                                raise NotImplementedError("color: 0x%x" % payload[0])
                    if opcode_def[0] == 'expanded':
                        self.two_color_printing = bool(payload[0] & (1 << 0))
                        self.cut_at_end = bool(payload[0] & (1 << 3))
                        self.high_resolution_printing = bool(payload[0] & (1 << 6))
                    if opcode_def[0] == 'media/quality':
                        self.raster_no = struct.unpack('<L', payload[4:8])[0]
                        self.mwidth = instruction[len(opcode) + 2]
                        self.mlength = instruction[len(opcode) + 3]*256
                        fmt = " media width: {} mm, media length: {} mm, raster no: {} rows"
                        logger.info(fmt.format(self.mwidth, self.mlength, self.raster_no))
                    if opcode_def[0] == 'print':
                        logger.info("Len of black rows: %d", len(self.black_rows))
                        logger.info("Len of red   rows: %d", len(self.red_rows))
                        def get_im(rows):
                            if not len(rows): return None
                            width_dots  = max(len(row) for row in rows)
                            height_dots = len(rows)
                            size = (width_dots*8, height_dots)
                            expanded_rows = []
                            for row in rows:
                                if len(row) == 0:
                                    expanded_rows.append(b'\x00'*width_dots)
                                else:
                                    expanded_rows.append(row)
                            data = bytes(b''.join(expanded_rows))
                            data = bytes([2**8 + ~byte for byte in data]) # invert b/w
                            im = Image.frombytes("1", size, data, decoder_name='raw')
                            return im
                        if not self.two_color_printing:
                            im_black = get_im(self.black_rows)
                            im = im_black
                        else:
                            im_black, im_red = (get_im(rows) for rows in (self.black_rows, self.red_rows))
                            im_black = im_black.convert("RGBA")
                            im_red = im_red.convert("L")
                            im_red = colorize(im_red, (255, 0, 0), (255, 255, 255))
                            im_red = im_red.convert("RGBA")
                            pixdata_black = im_black.load()
                            width, height = im_black.size
                            for y in range(height):
                                for x in range(width):
                                    # replace "white" with "transparent"
                                    if pixdata_black[x, y] == (255, 255, 255, 255):
                                        pixdata_black[x, y] = (255, 255, 255, 0)
                            im_red.paste(im_black, (0, 0), im_black)
                            im = im_red
                        im = im.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
                        img_name = self.filename_fmt.format(counter=self.page_counter)
                        im.save(img_name)
                        print('Page saved as {}'.format(img_name))
                        self.page_counter += 1
