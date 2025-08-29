# ADBMS6830 SPI

ADBMS6830 SPI high level analyzer to label SPI traffic between controller and ADBMS6830 or ADBMS6822 isoSPI XCVR.

## Features
* Command name parsing
* Command PEC validation
* Data parsing, ASIC #, Cell #, and voltage
* Data PEC validation

## Setup
* Add standard SPI analyzer
* SPI settings
  * MSB
  * CPOL=1
  * CPHA=1
  * CS active low
* Add ADBMS6830 high level analyzer and configure with SPI

![Example](https://raw.githubusercontent.com/atopile/adbms6830-saleae-analyzer/refs/heads/main/sample_voltage.png)
