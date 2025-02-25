## PAN-OS Device Management
This integration ingests PAN-OS NGFW and Panorama devices into an XSIAM lookup table using a standard indicator fetch.

You must have a valid [Panorama API key](https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key) and access to the Panorama server from XSIAM (or an engine).

This integration **must** be connected to Panorama and does not support direct connection to a PAN-OS NGFW specifically.

Due to adding the firewall/Panorama information into a lookup table, this integration also needs an XSIAM API key.

## Setup 
### Authentication
The recommended method of adding the Panorama and XSIAM API keys into XSIAM is via XSIAM credentials - https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Manage-credentials.
* For the Panorama API key, store the key in the "Password" credential field
* For the XSIAM API key, store the key in the "Password" credential field and store the key ID in the "Username" credential field

### Other parameters
* "PAN-OS Integration Name" - this is the instance name of the PAN-OS integration to be used with this device management integration instance.  If you have multiple Panoramas, you will need a separate PAN-OS instance paired with a separate Device Management instance.
* "Lookup Table Name" - this is the name of the XSIAM lookup table that will store the firewall/Panorama data
* "XSIAM API Auth method" - the type of XSIAM API key