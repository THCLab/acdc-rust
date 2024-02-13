## Overview

This is the reference implementation of all the work being done under [Authentic Chained Data Container (ACDC) Task Force](https://github.com/trustoverip/TSS0033-technology-stack-acdc) which has been constituted for further developments of the concept presented [here](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/ACDC.web.pdf).

ACDC utilize the same concept of containers that we all know from the global supply chains, where goods are transported in a standardized boxes, hence the logistics is simplified. Since all the world operates with the same standard, no matter what kind of goods need to be shipped from A to B, they'll be shipped used a common platform, so in containers. ACDC aims for the same, but for data so the data is being encapsulated into a container, so a standardized platform with known schema. The data is also tamper-proof and verifiable to its source. Not only that, ACDC also include Authentic Provenance Chain characteristic so a proof of all the changes (ie. transformations, aggragations) that have been made to the data during their lifetime.

## Usage

For usage examples checkout [`tests`](tests) folder.

## Development

* Run `cargo build`.
