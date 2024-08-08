from attr import attrs, attrib
from typing import Tuple

import copy

from brother_ql.helpers import ElementsManager

@attrs
class Model(object):
    """
    This class represents a printer model. All specifics of a certain model
    and the opcodes it supports should be contained in this class.
    """

    #: A string identifier given to each model implemented. Eg. 'QL-500'.
    identifier = attrib(type=str)
    #: Minimum and maximum number of rows or 'dots' that can be printed.
    #: Together with the dpi this gives the minimum and maximum length
    #: for continuous tape printing.
    min_max_length_dots = attrib(type=Tuple[int, int])
    #: The minimum and maximum amount of feeding a label
    min_max_feed = attrib(type=Tuple[int, int], default=(35, 1500))
    number_bytes_per_row = attrib(type=int, default=90)
    #: The required additional offset from the right side
    additional_offset_r = attrib(type=int, default=0)
    #: Support for the 'mode setting' opcode
    mode_setting = attrib(type=bool, default=True)
    #: Model has a cutting blade to automatically cut labels
    cutting = attrib(type=bool, default=True)
    #: Model has support for the 'expanded mode' opcode.
    #: (So far, all models that have cutting support do).
    expanded_mode = attrib(type=bool, default=True)
    #: Model has support for compressing the transmitted raster data.
    #: Some models with only USB connectivity don't support compression.
    compression_support = attrib(type=bool, default=True)
    #: Support for two color printing (black/red/white)
    #: available only on some newer models.
    two_color = attrib(type=bool, default=False)
    #: Number of NULL bytes needed for the invalidate command.
    num_invalidate_bytes = attrib(type=int, default=200)
    #: Hardware IDs
    # series code and model code are obtained from the status reply sent by the printer
    # product id is the USB PID for the printer
    series_code = attrib(type=int, default=0xFFFF)
    model_code = attrib(type=int, default=0xFFFF)
    product_id = attrib(type=int, default=0xFFFF)

    @property
    def name(self):
        return self.identifier

ALL_MODELS = [
    Model(
        identifier="QL-500",
        min_max_length_dots=(295, 11811),
        compression_support=False,
        mode_setting=False,
        expanded_mode=False,
        cutting=False,
        series_code=0x30,
        model_code=0x4F,
        product_id=0x2015,
    ),
    Model(
        identifier="QL-550",
        min_max_length_dots=(295, 11811),
        compression_support=False,
        mode_setting=False,
        series_code=0x30,
        model_code=0x4F,
        product_id=0x2016,
    ),
    Model(
        identifier="QL-560",
        min_max_length_dots=(295, 11811),
        compression_support=False,
        mode_setting=False,
        series_code=0x34,
        model_code=0x31,
        product_id=0x2027,
    ),
    Model(
        identifier="QL-570",
        min_max_length_dots=(150, 11811),
        compression_support=False,
        mode_setting=False,
        series_code=0x34,
        model_code=0x32,
        product_id=0x2028,
    ),
    Model(
        identifier="QL-580N",
        min_max_length_dots=(150, 11811),
        series_code=0x34,
        model_code=0x33,
        product_id=0x2029,
    ),
    Model(
        identifier="QL-600",
        min_max_length_dots=(150, 11811),
        series_code=0x34,
        model_code=0x47,
        product_id=0x20C0,
    ),
    Model(
        identifier="QL-650TD",
        min_max_length_dots=(295, 11811),
        series_code=0x30,
        model_code=0x51,
        product_id=0x201B,
    ),
    Model(
        identifier="QL-700",
        min_max_length_dots=(150, 11811),
        compression_support=False,
        mode_setting=False,
        series_code=0x34,
        model_code=0x35,
        product_id=0x2042,
    ),
    Model(
        identifier="QL-710W",
        min_max_length_dots=(150, 11811),
        series_code=0x34,
        model_code=0x36,
        product_id=0x2043,
    ),
    Model(
        identifier="QL-720NW",
        min_max_length_dots=(150, 11811),
        series_code=0x34,
        model_code=0x37,
        product_id=0x2044,
    ),
    Model(
        identifier="QL-800",
        min_max_length_dots=(150, 11811),
        two_color=True,
        compression_support=False,
        num_invalidate_bytes=400,
        series_code=0x34,
        model_code=0x38,
        product_id=0x209B,
    ),
    Model(
        identifier="QL-810W",
        min_max_length_dots=(150, 11811),
        two_color=True,
        num_invalidate_bytes=400,
        series_code=0x34,
        model_code=0x39,
        product_id=0x209C,
    ),
    Model(
        identifier="QL-820NWB",
        min_max_length_dots=(150, 11811),
        two_color=True,
        num_invalidate_bytes=400,
        series_code=0x34,
        model_code=0x41,
        product_id=0x209D,
    ),
    Model(
        identifier="QL-1050",
        min_max_length_dots=(295, 35433),
        number_bytes_per_row=162,
        additional_offset_r=44,
        series_code=0x30,
        model_code=0x50,
        product_id=0x2020,
    ),
    Model(
        identifier="QL-1060N",
        min_max_length_dots=(295, 35433),
        number_bytes_per_row=162,
        additional_offset_r=44,
        series_code=0x34,
        model_code=0x34,
        product_id=0x202A,
    ),
    Model(
        identifier="QL-1100",
        min_max_length_dots=(301, 35434),
        number_bytes_per_row=162,
        additional_offset_r=44,
        series_code=0x34,
        model_code=0x43,
        product_id=0x20A7,
    ),
    Model(
        identifier="QL-1110NWB",
        min_max_length_dots=(301, 35434),
        number_bytes_per_row=162,
        additional_offset_r=44,
        series_code=0x34,
        model_code=0x44,
        product_id=0x20A8,
    ),
    Model(
        identifier="QL-1115NWB",
        min_max_length_dots=(301, 35434),
        number_bytes_per_row=162,
        additional_offset_r=44,
        series_code=0x34,
        model_code=0x45,
        product_id=0x20AB,
    ),
    Model(
        identifier="PT-E550W",
        min_max_length_dots=(31, 14172),
        number_bytes_per_row=16,
        series_code=0x30,
        model_code=0x68,
        product_id=0x2060,
    ),
    Model(
        identifier="PT-P700",
        min_max_length_dots=(31, 7086),
        number_bytes_per_row=16,
        series_code=0x30,
        model_code=0x67,
        product_id=0x2061,
    ),
    Model(
        identifier="PT-P750W",
        min_max_length_dots=(31, 7086),
        number_bytes_per_row=16,
        series_code=0x30,
        model_code=0x68,
        product_id=0x2062,
    ),
    Model(
        identifier="PT-P900W",
        min_max_length_dots=(57, 28346),
        number_bytes_per_row=70,
        series_code=0x30,
        model_code=0x69,
        product_id=0x2085,
    ),
    Model(
        identifier="PT-P950NW",
        min_max_length_dots=(57, 28346),
        number_bytes_per_row=70,
        series_code=0x30,
        model_code=0x70,
        product_id=0x2086,
    ),
]

class ModelsManager(ElementsManager):
    DEFAULT_ELEMENTS = copy.copy(ALL_MODELS)
    ELEMENTS_NAME = 'model'
