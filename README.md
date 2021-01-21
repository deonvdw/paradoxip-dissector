# paradoxip-dissector
paradoxip is a Wireshark dissector for the IP protocol used by Paradox  IP150, PCS250 and similar IP interfaces. This repository is a working space to build and test features before submitting an initial version to the Wireshark project.

Here is a screenshot of the development in progress:![Screenshot of paradoxip in action](https://github.com/deonvdw/paradoxip-dissector/raw/main/screenshot.jpg)

## Status
 - Decodes encrypted message payloads [based on the PAI decryption code at https://github.com/ParadoxAlarmInterface/pai/blob/master/paradox/lib/crypto.py].
 - Properly interprets IP messages versus Serial passthrough messages
 - Displays the name of most serial messages and decodes the parameters for a few of them.
 - Wireshark preferences to save default module password or module passwords per IP address.

## Help wanted
I am basing the protocol decoding on the structures defined in the PAI project's parsers.py files. While they are a great starting point there are some inconsistencies and some fields not fully documented. Here is what needs to be done:

 - Create a proper protocol document for EVO and SP/Magellan serial messages - try various iterations of actions and map out the fields and values. The PAI structures can serve as starting point.
 - Capture EVO and SP/Magellan communication traces for analysis along with details of the operations performed and system info/configuration
 - Verify that paradoxip correctly decodes above traces

## Building
Building paradoxip follows the standard Wireshark building process as described at https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html.
Perform the following two steps before running CMake to generate the build files (step 2.2.12 in the URL above):

 - Copy the paradoxip directory from the repository to the `plugins/epan` directory of the Wireshark sources.
 
 - Add the line `plugins/epan/paradoxip` underneath the `set(PLUGIN_SRC_DIRS` line in `CMakeLists.txt` within the source code root directory.  The resulting section of the file should look like this:
 
       set(PLUGIN_SRC_DIRS
           plugins/epan/paradoxip
           plugins/epan/ethercat
           plugins/epan/gryphon
           plugins/epan/irda
           plugins/epan/mate
           plugins/epan/opcua

## Credits
Credit to João Paulo Barraca and Jevgeni Kiski for the [PAI - Paradox Alarm Interface](https://github.com/ParadoxAlarmInterface/pai) project which did a lot of the ground work.
