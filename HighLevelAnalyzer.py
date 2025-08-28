# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
    StringSetting,
    NumberSetting,
    ChoicesSetting,
)


def parse_voltage(data: bytearray) -> str:
    return f"{(int.from_bytes(bytes(data), byteorder='little', signed=True) * 0.000150) + 1.5:.3f}V"


def print_bytes(data: bytearray) -> str:
    value = int.from_bytes(bytes(data), byteorder="little", signed=False)
    return f"0x{value:04X}"


REGISTER_MAP = {
    0x0260: {"name": "ADCV", "parse_fn": print_bytes},
    0x0168: {"name": "ADSV", "parse_fn": print_bytes},
    0x0200: {"name": "ADI1", "parse_fn": print_bytes},
    0x0108: {"name": "ADI2", "parse_fn": print_bytes},
    0x0240: {"name": "ADCIV", "parse_fn": print_bytes},
    0x0410: {"name": "ADAX", "parse_fn": print_bytes},
    0x0400: {"name": "ADAX2", "parse_fn": print_bytes},
    0x0028: {"name": "MUTE", "parse_fn": print_bytes},
    0x0029: {"name": "UNMUTE", "parse_fn": print_bytes},
    0x004C: {"name": "RDACALL", "parse_fn": print_bytes},
    0x0001: {"name": "WRCFGA", "parse_fn": print_bytes},
    0x0024: {"name": "WRCFGB", "parse_fn": print_bytes},
    0x0081: {"name": "WRCFGC", "parse_fn": print_bytes},
    0x00A4: {"name": "WRCFGD", "parse_fn": print_bytes},
    0x0073: {"name": "WRCFGE", "parse_fn": print_bytes},
    0x0075: {"name": "WRCFGF", "parse_fn": print_bytes},
    0x0077: {"name": "WRCFGG", "parse_fn": print_bytes},
    0x0079: {"name": "WRCFGH", "parse_fn": print_bytes},
    0x007B: {"name": "WRCFGI", "parse_fn": print_bytes},
    0x0002: {"name": "RDCFGA", "parse_fn": print_bytes},
    0x0026: {"name": "RDCFGB", "parse_fn": print_bytes},
    0x0082: {"name": "RDCFGC", "parse_fn": print_bytes},
    0x00A6: {"name": "RDCFGD", "parse_fn": print_bytes},
    0x0074: {"name": "RDCFGE", "parse_fn": print_bytes},
    0x0076: {"name": "RDCFGF", "parse_fn": print_bytes},
    0x0078: {"name": "RDCFGG", "parse_fn": print_bytes},
    0x007A: {"name": "RDCFGH", "parse_fn": print_bytes},
    0x007C: {"name": "RDCFGI", "parse_fn": print_bytes},
    # CADC Registers
    0x0004: {"name": "RDCVA", "parse_fn": parse_voltage, "offset": 0},
    0x0006: {"name": "RDCVB", "parse_fn": parse_voltage, "offset": 3},
    0x0008: {"name": "RDCVC", "parse_fn": parse_voltage, "offset": 6},
    0x000A: {"name": "RDCVD", "parse_fn": parse_voltage, "offset": 9},
    0x0009: {"name": "RDCVE", "parse_fn": parse_voltage, "offset": 12},
    0x000B: {"name": "RDCVF", "parse_fn": parse_voltage, "offset": 15},
    0x000C: {"name": "RDCVALL", "parse_fn": parse_voltage},
    0x0003: {"name": "RDSVA", "parse_fn": parse_voltage, "offset": 0},
    0x0005: {"name": "RDSVB", "parse_fn": parse_voltage, "offset": 3},
    0x0007: {"name": "RDSVC", "parse_fn": parse_voltage, "offset": 6},
    0x000D: {"name": "RDSVD", "parse_fn": parse_voltage, "offset": 9},
    0x000E: {"name": "RDSVE", "parse_fn": parse_voltage, "cell_offset": 12},
    0x000F: {"name": "RDSVF", "parse_fn": parse_voltage, "cell_offset": 15},
    0x0010: {"name": "RDSVALL", "parse_fn": parse_voltage},
    # CADC Filtered Registers
    0x0012: {"name": "RDFCA", "parse_fn": print_bytes},
    0x0013: {"name": "RDFCB", "parse_fn": print_bytes},
    0x0014: {"name": "RDFCC", "parse_fn": print_bytes},
    0x0015: {"name": "RDFCD", "parse_fn": print_bytes},
    0x0016: {"name": "RDFCE", "parse_fn": print_bytes},
    0x0017: {"name": "RDFCF", "parse_fn": print_bytes},
    0x0018: {"name": "RDFCALL", "parse_fn": print_bytes},
    # AUX Registers
    0x0019: {"name": "RDAUXA", "parse_fn": print_bytes},
    0x001A: {"name": "RDAUXB", "parse_fn": print_bytes},
    0x001B: {"name": "RDAUXC", "parse_fn": print_bytes},
    0x001F: {"name": "RDAUXD", "parse_fn": print_bytes},
    # ID Register
    0x002C: {"name": "RDSID", "parse_fn": print_bytes},
    # Balance PWM Registers
    0x0020: {"name": "WRPWMA", "parse_fn": print_bytes},
    0x0022: {"name": "RDPWMA", "parse_fn": print_bytes},
    0x0021: {"name": "WRPWMB", "parse_fn": print_bytes},
    0x0023: {"name": "RDPWMB", "parse_fn": print_bytes},
}


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=("A", "B"))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        "Command": {"format": "{{data.command}}"},
        "PEC": {"format": "PEC: {{data.pec}}"},
        "Data": {"format": "{{data.data}}"},
    }

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """

        print(
            "Settings:",
            self.my_string_setting,
            self.my_number_setting,
            self.my_choices_setting,
        )

        self.frames = []
        self.word_start_time = None
        self.spi_enable = False
        self.error = False

    def handle_enable(self, frame: AnalyzerFrame):
        self.frames = []
        self.spi_enable = True
        self.error = False
        self.transaction_start_time = frame.start_time

    def reset(self):
        self.frames = []
        self.spi_enable = False
        self.error = False
        self.transaction_start_time = None

    def is_valid_transaction(self) -> bool:
        return (
            self.spi_enable
            and (not self.error)
            and (self.transaction_start_time is not None)
        )

    def handle_result(self, frame):
        if self.spi_enable:
            self.frames.append(frame)

    def get_frame_data(self) -> list:
        analyzer_frames: list[AnalyzerFrame] = []

        if len(self.frames) < 4:
            return []

        mosi_stream = bytearray()
        miso_stream = bytearray()
        for f in self.frames:
            mosi = f.data.get("mosi", 0)
            miso = f.data.get("miso", 0)
            if isinstance(mosi, (bytes, bytearray)):
                mosi_stream += mosi
            elif isinstance(mosi, int):
                mosi_stream.append(mosi & 0xFF)
            if isinstance(miso, (bytes, bytearray)):
                miso_stream += miso
            elif isinstance(miso, int):
                miso_stream.append(miso & 0xFF)

        # COMMAND
        command = bytes(mosi_stream[0:2])
        cmd_val = int.from_bytes(command, byteorder="big", signed=False)
        cmd_entry = REGISTER_MAP.get(cmd_val, {})
        command_label = (
            cmd_entry.get("name") if isinstance(cmd_entry, dict) else f"0x{cmd_val:04X}"
        )

        analyzer_frames.append(
            AnalyzerFrame(
                "Command",
                self.frames[0].start_time,
                self.frames[1].end_time,
                {
                    "command": command_label,
                },
            )
        )

        # COMMAND PEC
        command_pec = bytes(mosi_stream[2:4])
        pec_val = int.from_bytes(command_pec, byteorder="big", signed=False)
        command_pec_label = f"0x{pec_val:04X}"

        analyzer_frames.append(
            AnalyzerFrame(
                "PEC",
                self.frames[2].start_time,
                self.frames[3].end_time,
                {
                    "pec": command_pec_label,
                },
            )
        )

        data_frames = []
        if len(self.frames) > 4:
            data_frames = self.frames[4:]

        if not data_frames or len(data_frames) % 8 != 0:
            return analyzer_frames

        # Split into lists of 8 frames per group
        self.data_frame_groups = [
            data_frames[i : i + 8] for i in range(0, len(data_frames), 8)
        ]
        parse_fn = cmd_entry.get("parse_fn") if isinstance(cmd_entry, dict) else None

        for asic_index, group in enumerate(self.data_frame_groups):
            data_stream = miso_stream[4 + asic_index * 8 :]
            for data_index in [1, 3, 5]:
                cell_index = (data_index - 1) / 2
                if callable(parse_fn):
                    parsed_data = parse_fn(data_stream[data_index - 1 : data_index + 1])
                else:
                    parsed_data = print_bytes(
                        data_stream[data_index - 1 : data_index + 1]
                    )

                analyzer_frames.append(
                    AnalyzerFrame(
                        "Data",
                        group[data_index - 1].start_time,
                        group[data_index].end_time,
                        {
                            "data": f"A{asic_index + 1}C{cmd_entry.get('offset', 0) + cell_index}: {parsed_data}"
                        },
                    )
                )

            data_pec = print_bytes(data_stream[6:8])

            analyzer_frames.append(
                AnalyzerFrame(
                    "PEC",
                    group[6].start_time,
                    group[7].end_time,
                    {"pec": data_pec},
                )
            )

        return analyzer_frames

    def handle_disable(self, frame):
        if self.is_valid_transaction():
            result = self.get_frame_data()
            # result = AnalyzerFrame(
            #     "SpiTransaction",
            #     self.transaction_start_time,
            #     frame.end_time,
            #     self.get_frame_data(),
            # )
        else:
            result = AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Invalid SPI transaction (spi_enable={}, error={}, transaction_start_time={})".format(
                        self.spi_enable,
                        self.error,
                        self.transaction_start_time,
                    )
                },
            )

        self.reset()
        return result

    def handle_error(self, frame):
        result = AnalyzerFrame(
            "SpiTransactionError",
            frame.start_time,
            frame.end_time,
            {
                "error_info": "The clock was in the wrong state when the enable signal transitioned to active"
            },
        )
        self.reset()
        return result

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "enable":
            return self.handle_enable(frame)
        elif frame.type == "result":
            return self.handle_result(frame)
        elif frame.type == "disable":
            return self.handle_disable(frame)
        elif frame.type == "error":
            return self.handle_error(frame)
        else:
            return AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Unexpected frame type from input analyzer: {}".format(
                        frame.type
                    )
                },
            )
