/* packet-paradoxip.c
 * Routines for Paradox alarm IP100/IP150 message dissection
 * Copyright 2021, Deon van der Westhuysen <deonvdw@gmail.com>
 *
 * Packet structure and constants derived from "PAI - Paradox Alarm Interface" (https://github.com/ParadoxAlarmInterface/pai)
 * Authors João Paulo Barraca and Jevgeni Kiski
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/conversation.h>
#include <epan/expert.h> /* Include only as needed */
#include <epan/packet.h> /* Should be first Wireshark include (other than config.h) */
#include <epan/prefs.h> /* Include only as needed */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet-paradoxip.h"
#include "pdxcrypt.h"

/**********************************************************************************************/

/* Initialize the protocol and registered fields */
static int proto_paradoxip = -1;
static dissector_handle_t paradoxip_handle;

static const value_string MessageType_id_values[] = {
    { 1, "IP Response" },
    { 2, "Serial pass-thru Response" },
    { 3, "IP Request" },
    { 4, "Serial pass-thru Request" },
    { 0, NULL }
};
static value_string_ext MessageType_id_values_ext = VALUE_STRING_EXT_INIT(MessageType_id_values);

static const value_string Command_id_values[] = {
    { 0x00, "Passthrough" },
    { 0xF0, "Connect" },
    { 0xF1, "Send user label" },
    { 0xF2, "Keep-alive" },
    { 0xF3, "Upload-download connection" },
    { 0xF4, "Upload-download disconnection" },
    { 0xF5, "boot_loader" },
    { 0xF6, "Web page connect" },
    { 0xF7, "Web page disconnect" },
    { 0xF8, "Toggle keep-alive" },
    { 0xF9, "Reset" },
    { 0xFA, "Set baud rate" },
    { 0xFB, "Multicommand" },
    { 0xFC, "single_panel" },
    { 0xFD, "Unsupported Request" },
    { 0xFE, "boot_ip" },
    { 0xFF, "Disconnect" },
    { 0, NULL }
};
static value_string_ext Command_id_values_ext = VALUE_STRING_EXT_INIT(Command_id_values);

static const value_string SubCommand_id_values[] = {
    { 0, NULL }
};
static value_string_ext SubCommand_id_values_ext = VALUE_STRING_EXT_INIT(SubCommand_id_values);

static const value_string CryptType_id_values[] = {
    { 0, "none" },
    { 1, "aes_256_ecb" },
    { 0xEE, "old_module" },
    { 0, NULL }
};
static value_string_ext CryptType_id_values_ext = VALUE_STRING_EXT_INIT(CryptType_id_values);

static const value_string ConnectResult_id_values[] = {
    { 0, "success" },
    { 1, "invalid password" },
    { 2, "user_already_connected" },
    { 4, "user_already_connected1" },
    { 0, NULL }
};
static value_string_ext ConnectResult_id_values_ext = VALUE_STRING_EXT_INIT(ConnectResult_id_values);

static const value_string IPModuleModel_id_values[] = {
    { 0x70, "IP100" },
    { 0x71, "IP150" },
    { 0, NULL }
};
static value_string_ext IPModuleModel_id_values_ext = VALUE_STRING_EXT_INIT(IPModuleModel_id_values);

static const value_string SPTResponseCommand_id_values[] = {
    { 0x10, "LoginConfirmation" },
    { 0x30, "SetTimeDate" },
    { 0x40, "PerformAction" },
    { 0x50, "ReadMemory" },
    { 0x70, "ResultCode" },
    { 0x80, "SetUnreadEventID" },
    { 0xA0, "Broadcast" },
    { 0xC0, "ReadSomething" },
    { 0xD0, "PerformZoneAction" },
    { 0xE0, "EventMessage" }, /* PAI RequestedEvent */
    { 0, NULL }
};
static value_string_ext SPTResponseCommand_id_values_ext = VALUE_STRING_EXT_INIT(SPTResponseCommand_id_values);

/* InitiateCommunication response is handled as special case in dissector */
static const value_string SPTResponseCmd37_id_values[] = {
    { 0x00, "StartCommunication" },
    { 0x10, "InitializeCommunication" }, /* No flags nibble? */
    { 0x30, "SetTimeDate" },
    { 0x40, "PerformAction" },
    { 0x50, "ReadMemory" },
    { 0x70, "ResultCode" }, /* Also InitiateCommunication response if byte 2 == FF */
    { 0xE0, "EventMessage" }, /* PAI RequestedEvent */
    { 0, NULL }
};
static value_string_ext SPTResponseCmd37_id_values_ext = VALUE_STRING_EXT_INIT(SPTResponseCmd37_id_values);

static const value_string SPTRequestCommand_id_values[] = {
    { 0x00, "InitializeCommunication" },
    { 0x30, "SetTimeDate" },
    { 0x40, "PerformAction" },
    { 0x50, "ReadMemory" }, /* Or general read command ???  Also maps to SP PanelStatus */
    { 0x51, "ReadMemory" },
    { 0x52, "ReadMemory" },
    { 0x53, "ReadMemory" },
    { 0x54, "ReadMemory" },
    { 0x55, "ReadMemory" },
    { 0x56, "ReadMemory" },
    { 0x57, "ReadMemory" },
    { 0x58, "ReadMemory" },
    { 0x59, "ReadMemory" },
    { 0x5A, "ReadMemory" },
    { 0x5B, "ReadMemory" },
    { 0x5C, "ReadMemory" },
    { 0x5D, "ReadMemory" },
    { 0x5E, "ReadMemory" },
    { 0x5F, "ReadMemory" }, /* Handle Command 5F StartCommunication as special case in dissector code */
    { 0x70, "CloseConnection" },
    { 0x72, "InitiateCommunication" },
    { 0x80, "SetUnreadEventID" },
    { 0xA0, "Broadcast" },
    { 0xA1, "Broadcast" },
    { 0xA2, "Broadcast" },
    { 0xA3, "Broadcast" },
    { 0xA4, "Broadcast" },
    { 0xA5, "Broadcast" },
    { 0xA6, "Broadcast" },
    { 0xA7, "Broadcast" },
    { 0xA8, "Broadcast" },
    { 0xA9, "Broadcast" },
    { 0xAA, "Broadcast" },
    { 0xAB, "Broadcast" },
    { 0xAC, "Broadcast" },
    { 0xAD, "Broadcast" },
    { 0xAE, "Broadcast" },
    { 0xAF, "Broadcast" },
    { 0xC8, "ReadSomething" },
    { 0xD0, "PerformZoneAction" },
    { 0xE0, "GetEvents" },
    { 0, NULL }
};
static value_string_ext SPTRequestCommand_id_values_ext = VALUE_STRING_EXT_INIT(SPTRequestCommand_id_values);

/* Request names for 37 byte messages */
static const value_string SPTRequestCmd37_id_values[] = {
    { 0x00, "InitializeCommunication" },
    { 0x30, "SetTimeDate" },
    { 0x40, "PerformAction" },
    { 0x50, "ReadMemory" },
    { 0x5F, "StartCommunication" },
    { 0x70, "CloseConnection" },
    { 0x72, "InitiateCommunication" },
    { 0, NULL }
};
static value_string_ext SPTRequestCmd37_id_values_ext = VALUE_STRING_EXT_INIT(SPTRequestCmd37_id_values);

/* Same Family ID as used in PUF files */
static const value_string SPTInitFamilyID_id_values[] = {
    { 0xA1, "Digiplex" },
    { 0, NULL }
};
static value_string_ext SPTInitFamilyID_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitFamilyID_id_values);

/* Same Product ID as used in PUF files */
static const value_string SPTInitProductID_id_values[] = {
    { 0x6D, "EVOHD" },
    { 0, NULL }
};
static value_string_ext SPTInitProductID_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitProductID_id_values);

/* Same Encryption ID as used in PUF files? */
static const value_string SPTInitCryptoID_id_values[] = {
    { 0x3B, "Original" },
    { 0x57, "Extended" },
    { 0xA6, "NONE" },
    { 0, NULL }
};
static value_string_ext SPTInitCryptoID_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitCryptoID_id_values);

static const value_string SPTGenProductID_id_values[] = {
    { 0, "DIGIPLEX_v13" },
    { 1, "DIGIPLEX_v2" },
    { 2, "DIGIPLEX_NE" },
    { 3, "DIGIPLEX_EVO_48" },
    { 4, "DIGIPLEX_EVO_96" },
    { 5, "DIGIPLEX_EVO_192" },
    { 7, "DIGIPLEX_EVO_HD" },
    { 21, "SPECTRA_SP5500" },
    { 22, "SPECTRA_SP6000" },
    { 23, "SPECTRA_SP7000" },
    { 26, "SPECTRA_SP4000" },
    { 27, "SPECTRA_SP65" },
    { 64, "MAGELLAN_MG5000" },
    { 65, "MAGELLAN_MG5050" },
    { 66, "MAGELLAN_MG5075" },
    { 0, NULL }
};
static value_string_ext SPTGenProductID_id_values_ext = VALUE_STRING_EXT_INIT(SPTGenProductID_id_values);

static const value_string SPTInitCommsTalker_id_values[] = {
    { 0, "Bootloader" },
    { 1, "Controller Application" },
    { 2, "Module Application" },
    { 0, NULL }
};
static value_string_ext SPTInitCommsTalker_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitCommsTalker_id_values);

static const value_string SPTSourceID_id_values[] = {
    { 0, "NonValid Source" },
    { 1, "Winload Direct" },
    { 2, "Winload IP" },
    { 3, "Winload GSM" },
    { 4, "Winload Dialer" },
    { 5, "NeWare Direct" },
    { 6, "NeWare IP" },
    { 7, "NeWare GSM" },
    { 8, "NeWare Dialer" },
    { 9, "IP Direct=9," },
    { 10, "VDMP3 Direct" },
    { 11, "VDMP3 GSM" },
    { 0, NULL }
};
static value_string_ext SPTSourceID_id_values_ext = VALUE_STRING_EXT_INIT(SPTSourceID_id_values);

static const value_string ResultCode_id_values[] = {
    { 0x00, "Requested command failed" },
    { 0x01, "Invalid user code" },
    { 0x02, "Partition in code lockout" },
    { 0x05, "Panel will disconnect" },
    { 0x10, "Panel not connected" },
    { 0x11, "Panel already connected" },
    { 0x12, "Invalid pc password" },
    { 0x13, "Winload on phone line" },
    { 0x14, "Invalid module address" },
    { 0x15, "Cannot write in ram" },
    { 0x16, "Upgrade request fail" },
    { 0x17, "Record number out of range" },
    { 0x19, "Invalid record type" },
    { 0x1A, "Multibus not supported" },
    { 0x1B, "Incorrect number of users" },
    { 0x1C, "Invalid label number" },
    { 0, NULL }
};
static value_string_ext ResultCode_id_values_ext = VALUE_STRING_EXT_INIT(ResultCode_id_values);

static const value_string ActionNames_id_values[] = {
    { 0, "Partition?" },
    { 2, "Door" },
    { 6, "PGM" },
    { 9, "Send Panic" },
    { 0, NULL }
};
static value_string_ext ActionNames_id_values_ext = VALUE_STRING_EXT_INIT(ActionNames_id_values);

/**********************************************************************************************/

static int hf_header_tree = -1;
static int hf_serial_tree = -1;
static int hf_payload_unknown = -1;
static int hf_paradoxip_sof = -1;
static int hf_paradoxip_length = -1;
static int hf_paradoxip_msgtype = -1;
static int hf_paradoxip_flags = -1;
static int hf_paradoxip_flags_b8 = -1;
static int hf_paradoxip_flags_ka = -1;
static int hf_paradoxip_flags_le = -1;
static int hf_paradoxip_flags_nw = -1;
static int hf_paradoxip_flags_im = -1;
static int hf_paradoxip_flags_b3 = -1;
static int hf_paradoxip_flags_ud = -1;
static int hf_paradoxip_flags_cr = -1;
static int hf_paradoxip_command = -1;
static int hf_paradoxip_subcmd = -1;
static int hf_paradoxip_wt = -1;
static int hf_paradoxip_sb = -1;
static int hf_paradoxip_crypttype = -1;
static int hf_paradoxip_unused = -1;
static int hf_paradoxip_seqid = -1;
static int hf_paradoxip_cryptmsg = -1;
static int hf_paradoxip_payload = -1;
static int hf_paradoxip_cmdsummary = -1;
static int hf_ip_con_req_password = -1;
static int hf_ip_con_resp_result = -1;
static int hf_ip_con_resp_sessionkey = -1;
static int hf_ip_con_resp_hwver = -1;
static int hf_ip_con_resp_fwver = -1;
static int hf_ip_con_resp_serialno = -1;
static int hf_ip_con_resp_model = -1;

static int hf_spt_req_cmd = -1;
static int hf_spt_resp_cmd = -1;
static int hf_spt_req_cmd37 = -1;
static int hf_spt_resp_cmd37 = -1;
static int hf_spt_resp_status = -1;
static int hf_spt_resp_flags_re = -1;
static int hf_spt_resp_flags_ar = -1;
static int hf_spt_resp_flags_wl = -1;
static int hf_spt_resp_flags_ne = -1;

static int hf_spt_checksum = -1;
static int hf_spt_reserved = -1;
static int hf_spt_unknown = -1;

static int hf_spt_messagecentre = -1;
static int hf_spt_newprotocol = -1;
static int hf_spt_protocolid = -1;
static int hf_spt_protcolver = -1;
static int hf_spt_icfamilyid = -1;
static int hf_spt_icproductid = -1;
static int hf_spt_talker = -1;
static int hf_spt_appver = -1;
static int hf_spt_serialno = -1;
static int hf_spt_hwver = -1;
static int hf_spt_bootver = -1;
static int hf_spt_bootdate = -1;
static int hf_spt_cpuid = -1;
static int hf_spt_cryptoid = -1;

static int hf_spt_validation = -1;
static int hf_spt_sourceid = -1;
static int hf_spt_userid = -1;
static int hf_spt_fwver = -1;
static int hf_spt_productid = -1;
static int hf_spt_panelid = -1;
static int hf_spt_transceiver = -1;
static int hf_spt_trxfwver = -1;
static int hf_spt_trxfamily = -1;
static int hf_spt_trxnoise = -1;
static int hf_spt_trxstatus = -1;
static int hf_spt_trxflags_nu = -1;
static int hf_spt_trxflags_nh = -1;
static int hf_spt_trxflags_cc = -1;
static int hf_spt_trxhwrev = -1;

static int hf_spt_length = -1;
static int hf_spt_length16 = -1;
static int hf_spt_resultcode = -1;
static int hf_spt_moduleaddr = -1;
static int hf_spt_pcpasswd = -1;
static int hf_spt_modemspeed = -1;
static int hf_spt_usercode = -1;
static int hf_spt_systemoptions = -1;
static int hf_spt_carrierlen = -1;
static int hf_spt_sourcemethod = -1;

static int hf_spt_address16 = -1;
static int hf_spt_address32 = -1;
static int hf_spt_addresslow = -1;
static int hf_spt_addresshigh = -1;
static int hf_spt_index16 = -1;
static int hf_spt_eventnr = -1;
static int hf_spt_recstoread = -1;
static int hf_spt_recstoread16 = -1;
static int hf_spt_numrecords16 = -1;
static int hf_spt_bytestoread = -1;
static int hf_spt_compsize = -1;
static int hf_spt_date = -1;
static int hf_spt_time = -1;

static int hf_spt_memblock = -1;
static int hf_spt_readctl = -1;
static int hf_spt_readctl_ram = -1;
static int hf_spt_readctl_ar = -1;
static int hf_spt_readctl_wl = -1;
static int hf_spt_readctl_ne = -1;
static int hf_spt_readctl_nu = -1;
static int hf_spt_busaddress = -1;
static int hf_spt_memorydata = -1;

static int hf_spt_packedevent = -1;
static int hf_spt_eventdate = -1;
static int hf_spt_eventtime = -1;
static int hf_spt_eventgroup = -1;
static int hf_spt_event1 = -1;
static int hf_spt_event2 = -1;
static int hf_spt_labeltype = -1;
static int hf_spt_label = -1;

static int hf_spt_partition = -1;
static int hf_spt_action = -1;

/* Setup list of header fields */
static hf_register_info hf[] = {
    { &hf_header_tree, { "Header fields", "paradoxip.header", FT_NONE, BASE_NONE, NULL, 0x0, "IP message header fields", HFILL } },
    { &hf_serial_tree, { "Paradox alarm serial message", "paradoxip.serialmessage", FT_NONE, BASE_NONE, NULL, 0x0, "Serial passthrough message", HFILL } },
    { &hf_paradoxip_sof, { "Start marker", "paradoxip.sof", FT_UINT8, BASE_HEX, NULL, 0x0, "Marks the start of an message frame - should always be 0xAA", HFILL } },
    { &hf_paradoxip_length, { "Message length", "paradoxip.msglength", FT_UINT16, BASE_DEC, NULL, 0x0, "Message payload length", HFILL } },
    { &hf_paradoxip_msgtype, { "Message Type", "paradoxip.msgtype", FT_INT8, BASE_DEC | BASE_EXT_STRING, &MessageType_id_values_ext, 0x0, NULL, HFILL } },
    { &hf_paradoxip_flags, { "Flags", "paradoxip.flags", FT_UINT8, BASE_HEX, NULL, 0xFF, "Message flags", HFILL } },
    { &hf_paradoxip_flags_b8, { "bit8", "paradoxip.flags.bit8", FT_BOOLEAN, 8, NULL, 0x80, "Flags bit8 (unknown)", HFILL } },
    { &hf_paradoxip_flags_ka, { "keep_alive", "paradoxip.flags.keep_alive", FT_BOOLEAN, 8, NULL, 0x40, "Flags keep-alive bit", HFILL } },
    { &hf_paradoxip_flags_le, { "live_events", "paradoxip.flags.live_events", FT_BOOLEAN, 8, NULL, 0x20, "Flags live-events bit", HFILL } },
    { &hf_paradoxip_flags_nw, { "neware", "paradoxip.flags.neware", FT_BOOLEAN, 8, NULL, 0x10, "Flags neware bit", HFILL } },
    { &hf_paradoxip_flags_im, { "installer_mode", "paradoxip.flags.installer_mode", FT_BOOLEAN, 8, NULL, 0x08, "Flags installer-mode bit", HFILL } },
    { &hf_paradoxip_flags_b3, { "bit3", "paradoxip.flags.bit3", FT_BOOLEAN, 8, NULL, 0x04, "Flags bit3 (unknown)", HFILL } },
    { &hf_paradoxip_flags_ud, { "upload_download", "paradoxip.flags.upload_download", FT_BOOLEAN, 8, NULL, 0x02, "Flags upload_download bit", HFILL } },
    { &hf_paradoxip_flags_cr, { "encrypted", "paradoxip.flags.encrypted", FT_BOOLEAN, 8, NULL, 0x01, "Flags encrypted bit", HFILL } },
    { &hf_payload_unknown, { "Unknown", "paradoxip.payloadunknown", FT_BYTES, BASE_NONE, NULL, 0x0, "Unknown byte values in message payload", HFILL } },

    { &hf_paradoxip_command, { "Command", "paradoxip.command", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &Command_id_values_ext, 0x0, "Command to be executed", HFILL } },
    /* How do we handle sub-command - different string values based on command... will sort out later */
    { &hf_paradoxip_subcmd, { "Sub-command", "paradoxip.subcmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SubCommand_id_values_ext, 0x0, "Sub-command - depends on Command", HFILL } },
    { &hf_paradoxip_wt, { "WT", "paradoxip.wt", FT_UINT8, BASE_DEC, NULL, 0x0, "Header WT (watchdog timer?) field", HFILL } },
    { &hf_paradoxip_sb, { "SB", "paradoxip.sb", FT_UINT8, BASE_DEC, NULL, 0x0, "Header SB field", HFILL } },
    { &hf_paradoxip_crypttype, { "Encryption Type", "paradoxip.crypttype", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &CryptType_id_values_ext, 0x0, "Encryption type used for message payload", HFILL } },
    { &hf_paradoxip_unused, { "Unused bytes", "paradoxip.unused", FT_BYTES, BASE_NONE, NULL, 0x0, "Unused/undefined bytes in message header", HFILL } },
    { &hf_paradoxip_seqid, { "SequenceID", "paradoxip.seqid", FT_UINT8, BASE_HEX, NULL, 0x0, "Sequence ID for this message", HFILL } },
    { &hf_paradoxip_cryptmsg, { "Encrypted payload bytes", "paradoxip.cryptmsg", FT_BYTES, BASE_NONE, NULL, 0x0, "Encrypted payload bytes", HFILL } },
    { &hf_paradoxip_payload, { "Payload bytes", "paradoxip.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "Message payload", HFILL } },
    { &hf_paradoxip_cmdsummary, { "Command", "paradoxip.cmdsummary", FT_UINT8, BASE_HEX, NULL, 0x0, "Command to execute and direction", HFILL } },

    { &hf_ip_con_req_password, { "Login password", "paradoxip.ip.password", FT_STRING, BASE_NONE, NULL, 0x0, "Password for logging into IP Module", HFILL } },
    { &hf_ip_con_resp_result, { "Connection result", "paradoxip.ip.conresult", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ConnectResult_id_values_ext, 0x0, "Connection result for IP Module connection request", HFILL } },
    { &hf_ip_con_resp_sessionkey, { "Session key", "paradoxip.ip.sessionkey", FT_STRING, BASE_NONE, NULL, 0x0, "Session key used to encrypt the rest of this IP session", HFILL } },
    { &hf_ip_con_resp_hwver, { "Hardware version", "paradoxip.ip.hwver", FT_UINT16, BASE_HEX, NULL, 0x0, "IP Module hardware version", HFILL } },
    { &hf_ip_con_resp_fwver, { "Firmware version", "paradoxip.ip.fwver", FT_STRING, BASE_NONE, NULL, 0x0, "IP Module firmware version", HFILL } },
    { &hf_ip_con_resp_serialno, { "Serial number", "paradoxip.ip.serialno", FT_STRING, BASE_NONE, NULL, 0x0, "IP Module serial number", HFILL } },
    { &hf_ip_con_resp_model, { "Model", "paradoxip.ip.model", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &IPModuleModel_id_values_ext, 0x0, "Model number of connected IP module", HFILL } },

    { &hf_spt_req_cmd, { "Request", "paradoxip.spt.req_cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTRequestCommand_id_values_ext, 0x0, "Serial passthrough request command code", HFILL } },
    { &hf_spt_resp_cmd, { "Response", "paradoxip.spt.res_cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTResponseCommand_id_values_ext, 0x0, "Serial passthrough response command code", HFILL } },
    { &hf_spt_req_cmd37, { "Request", "paradoxip.spt.req_cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTRequestCmd37_id_values_ext, 0x0, "Serial passthrough request command code", HFILL } },
    { &hf_spt_resp_cmd37, { "Response", "paradoxip.spt.res_cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTResponseCmd37_id_values_ext, 0x0, "Serial passthrough response command code", HFILL } },
    { &hf_spt_resp_status, { "Status", "paradoxip.spt.status", FT_UINT8, BASE_HEX, NULL, 0xFF, "Response message status flags", HFILL } },
    { &hf_spt_resp_flags_re, { "reserved", "paradoxip.spt.status.reserved", FT_BOOLEAN, 8, NULL, 0x08, "Response message status flags reserved bit", HFILL } },
    { &hf_spt_resp_flags_ar, { "alarm_reporting_pending", "paradoxip.spt.status.alarmreport", FT_BOOLEAN, 8, NULL, 0x04, "Response message alarm reporting pending flag", HFILL } },
    { &hf_spt_resp_flags_wl, { "Winload_connected", "paradoxip.spt.status.winload", FT_BOOLEAN, 8, NULL, 0x02, "Response message Winload connected flag", HFILL } },
    { &hf_spt_resp_flags_ne, { "NeWare_connected", "paradoxip.spt.status.neware", FT_BOOLEAN, 8, NULL, 0x01, "Response message NeWare connected flag", HFILL } },
    { &hf_spt_length, { "Length", "paradoxip.spt.length", FT_UINT8, BASE_DEC, NULL, 0x00, "Serial packet total length", HFILL } },
    { &hf_spt_length16, { "Length", "paradoxip.spt.length", FT_UINT16, BASE_DEC, NULL, 0x00, "Serial packet total length", HFILL } },
    { &hf_spt_checksum, { "Checksum", "paradoxip.spt.checksum", FT_UINT8, BASE_HEX, NULL, 0x00, "Checksum for the serial message", HFILL } },
    { &hf_spt_reserved, { "Reserved/padding", "paradoxip.spt.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, "Reserved / padding bytes", HFILL } },
    { &hf_spt_unknown, { "Unknown", "paradoxip.spt.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, "Unknown bytes", HFILL } },

    { &hf_spt_messagecentre, { "message centre", "paradoxip.spt.messagecentre", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_newprotocol, { "new_protocol", "paradoxip.spt.new_protocol", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_protocolid, { "Protocol ID", "paradoxip.spt.protocolid", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_protcolver, { "Protocol version", "paradoxip.spt.protover", FT_STRING, BASE_NONE, NULL, 0x0, "Protocol version", HFILL } },
    { &hf_spt_icfamilyid, { "Family ID", "paradoxip.spt.icfamilyid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTInitFamilyID_id_values_ext, 0x00, NULL, HFILL } },
    { &hf_spt_icproductid, { "Product ID", "paradoxip.spt.icproductid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTInitProductID_id_values_ext, 0x00, NULL, HFILL } },
    { &hf_spt_productid, { "Product ID", "paradoxip.spt.productid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTGenProductID_id_values_ext, 0x00, NULL, HFILL } },
    { &hf_spt_talker, { "Talker", "paradoxip.spt.talker", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTInitCommsTalker_id_values_ext, 0x00, NULL, HFILL } },
    { &hf_spt_appver, { "Application version", "paradoxip.spt.appver", FT_STRING, BASE_NONE, NULL, 0x0, "Application version", HFILL } },
    { &hf_spt_serialno, { "Serial number", "paradoxip.spt.serialno", FT_STRING, BASE_NONE, NULL, 0x0, "Serial number", HFILL } },
    { &hf_spt_hwver, { "Hardware version", "paradoxip.spt.hwver", FT_STRING, BASE_NONE, NULL, 0x0, "Hardware version.revision", HFILL } },
    { &hf_spt_bootver, { "Bootloader version", "paradoxip.spt.bootver", FT_STRING, BASE_NONE, NULL, 0x0, "Bootloader version", HFILL } },
    { &hf_spt_bootdate, { "Bootloader date", "paradoxip.spt.bootdate", FT_STRING, BASE_NONE, NULL, 0x0, "Bootloader build data", HFILL } },
    { &hf_spt_cpuid, { "Processor ID", "paradoxip.spt.cpuid", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_cryptoid, { "Encryption ID", "paradoxip.spt.cryptoid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTInitCryptoID_id_values_ext, 0x00, NULL, HFILL } },

    { &hf_spt_validation, { "validation", "paradoxip.spt.validation", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_sourceid, { "Source ID", "paradoxip.spt.sourceid", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SPTSourceID_id_values_ext, 0x00, NULL, HFILL } },
    { &hf_spt_userid, { "User ID", "paradoxip.spt.userid", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_fwver, { "Firmware version", "paradoxip.spt.fwver", FT_STRING, BASE_NONE, NULL, 0x0, "Firmware version", HFILL } },
    { &hf_spt_panelid, { "Panel ID", "paradoxip.spt.panelid", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_transceiver, { "Transceiver", "paradoxip.spt.transceiver", FT_NONE, BASE_NONE, NULL, 0x0, "Transceiver details", HFILL } },
    { &hf_spt_trxfwver, { "Firmware version", "paradoxip.spt.trxfwver", FT_STRING, BASE_NONE, NULL, 0x0, "Transceiver firmware version", HFILL } },
    { &hf_spt_trxfamily, { "Family", "paradoxip.spt.trxfamily", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_trxnoise, { "Noise floor level", "paradoxip.spt.trxnoise", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_trxstatus, { "Status", "paradoxip.spt.trxstatus", FT_UINT8, BASE_HEX, NULL, 0xFF, "Transceiver status flags", HFILL } },
    { &hf_spt_trxflags_nu, { "not used", "paradoxip.spt.trxstatus.notused", FT_BOOLEAN, 8, NULL, 0xFC, NULL, HFILL } },
    { &hf_spt_trxflags_nh, { "noise floor high", "paradoxip.spt.trxstatus.noisehigh", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
    { &hf_spt_trxflags_cc, { "constant carrier", "paradoxip.spt.trxstatus.constcarrier", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
    { &hf_spt_trxhwrev, { "Hardware revision", "paradoxip.spt.trxhwrev", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },

    { &hf_spt_resultcode, { "Result code", "paradoxip.spt.result", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ResultCode_id_values_ext, 0x00, "Result code for the previous request", HFILL } },

    { &hf_spt_moduleaddr, { "Module address", "paradoxip.spt.moduleaddr", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_pcpasswd, { "PC password", "paradoxip.spt.pcpassword", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_modemspeed, { "Modem speed", "paradoxip.spt.modemspeed", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_usercode, { "User code", "paradoxip.spt.usercode", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_systemoptions, { "System options", "paradoxip.spt.systemoptions", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_carrierlen, { "carrier_len", "paradoxip.spt.carrier_len", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_sourcemethod, { "carrier_len", "paradoxip.spt.carrier_len", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

    { &hf_spt_address32, { "Address", "paradoxip.spt.address", FT_UINT32, BASE_HEX, NULL, 0x00, "Memory read/write address", HFILL } },
    { &hf_spt_address16, { "Address", "paradoxip.spt.address", FT_UINT16, BASE_HEX, NULL, 0x00, "Memory read/write address", HFILL } },
    { &hf_spt_addresslow, { "Address low word", "paradoxip.spt.addresslow", FT_UINT16, BASE_HEX, NULL, 0x00, "Low word of memory address", HFILL } },
    { &hf_spt_addresshigh, { "Address high word", "paradoxip.spt.addresshigh", FT_UINT8, BASE_HEX, NULL, 0x00, "High word of memory address", HFILL } },
    { &hf_spt_index16, { "Index", "paradoxip.spt.address", FT_UINT16, BASE_HEX, NULL, 0x00, "Record index", HFILL } },
    { &hf_spt_eventnr, { "Event number", "paradoxip.spt.address", FT_UINT16, BASE_DEC, NULL, 0x00, "Event number", HFILL } },
    { &hf_spt_recstoread, { "Records to read", "paradoxip.spt.rectoread", FT_UINT8, BASE_DEC, NULL, 0x00, "Number of records to read from panel", HFILL } },
    { &hf_spt_recstoread16, { "Records to read", "paradoxip.spt.rectoread", FT_UINT16, BASE_DEC, NULL, 0x00, "Number of records to read from panel", HFILL } },
    { &hf_spt_numrecords16, { "Number of records", "paradoxip.spt.numrecords", FT_UINT16, BASE_DEC, NULL, 0x00, "Number of records", HFILL } },
    { &hf_spt_bytestoread, { "Bytes to read", "paradoxip.spt.bytestoread", FT_UINT8, BASE_HEX, NULL, 0x00, "Number of bytes to read", HFILL } },
    { &hf_spt_compsize, { "Computed size", "paradoxip.spt.compsize", FT_UINT8, BASE_HEX, NULL, 0x00, "Computed datasize", HFILL } },
    { &hf_spt_date, { "Date", "paradoxip.spt.date", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_time, { "Time", "paradoxip.spt.time", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },

    { &hf_spt_memblock, { "Memory block", "paradoxip.spt.memblock", FT_UINT8, BASE_DEC, NULL, 0x00, "Memory block to read/write", HFILL } },
    { &hf_spt_readctl, { "Control flags", "paradoxip.spt.readctl", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL } },
    { &hf_spt_readctl_ram, { "RAM access", "paradoxip.spt.readctl.ramaccess", FT_BOOLEAN, 8, NULL, 0x80, "Read RAM memory", HFILL } },
    { &hf_spt_readctl_ar, { "alarm_reporting_pending", "paradoxip.spt.readctl.alarmreport", FT_BOOLEAN, 8, NULL, 0x40, "Response message alarm reporting pending flag", HFILL } },
    { &hf_spt_readctl_wl, { "Winload_connected", "paradoxip.spt.readctl.winload", FT_BOOLEAN, 8, NULL, 0x20, "Response message Winload connected flag", HFILL } },
    { &hf_spt_readctl_ne, { "NeWare_connected", "paradoxip.spt.readctl.neware", FT_BOOLEAN, 8, NULL, 0x10, "Response message NeWare connected flag", HFILL } },
    { &hf_spt_readctl_nu, { "not used? ", "paradoxip.spt.readctl.notused", FT_BOOLEAN, 8, NULL, 0xC, "not used?", HFILL } },
    { &hf_spt_busaddress, { "Bus address", "paradoxip.spt.busaddress", FT_UINT8, BASE_DEC, NULL, 0x00, "Bus address. 0= Panel >0= Modules", HFILL } },
    { &hf_spt_memorydata, { "Memory contents", "paradoxip.spt.memorydata", FT_BYTES, BASE_NONE, NULL, 0x0, "Data read from panel or module memory", HFILL } },

    { &hf_spt_packedevent, { "Event", "paradoxip.spt.packedevent", FT_BYTES, BASE_NONE, NULL, 0x00, "Packed event from panel", HFILL } },
    { &hf_spt_eventdate, { "Event Date", "paradoxip.spt.eventdate", FT_STRING, BASE_NONE, NULL, 0x00, "Event date", HFILL } },
    { &hf_spt_eventtime, { "Event Time", "paradoxip.spt.eventtime", FT_STRING, BASE_NONE, NULL, 0x00, "Event time", HFILL } },
    { &hf_spt_eventgroup, { "Event Group", "paradoxip.spt.eventgroup", FT_UINT8, BASE_DEC, NULL, 0x00, "Event group", HFILL } },
    { &hf_spt_event1, { "Event #1", "paradoxip.spt.event1", FT_UINT16, BASE_DEC, NULL, 0x00, "Event number 1", HFILL } },
    { &hf_spt_event2, { "Event #2", "paradoxip.spt.event2", FT_UINT16, BASE_DEC, NULL, 0x00, "Event number 2", HFILL } },
    { &hf_spt_partition, { "Partition", "paradoxip.spt.partition", FT_UINT8, BASE_DEC, NULL, 0x00, "Partition number", HFILL } },
    { &hf_spt_labeltype, { "Label type", "paradoxip.spt.labeltype", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_spt_label, { "Label", "paradoxip.spt.label", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_spt_action, { "Action", "paradoxip.spt.action", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ActionNames_id_values_ext, 0x00, "Requested action to perform", HFILL } },

};

/* Initialize the subtree pointers */
static gint ett_paradoxip = -1;
static gint ett_header = -1;
static gint ett_header_flags = -1;
static gint ett_serialmessage = -1;
static gint ett_spt_responsestatus = -1;
static gint ett_spt_trxdetails = -1;
static gint ett_spt_trxstatus = -1;
static gint ett_spt_readmemctl = -1;
static gint ett_spt_cmpevent = -1;

/* Setup protocol subtree array */
static gint* ett[] = {
    &ett_paradoxip,
    &ett_header,
    &ett_header_flags,
    &ett_serialmessage,
    &ett_spt_responsestatus,
    &ett_spt_trxdetails,
    &ett_spt_trxstatus,
    &ett_spt_readmemctl,
    &ett_spt_cmpevent
};

static expert_field ei_decodeerror = EI_INIT;
static expert_field ei_decodewarn = EI_INIT;

/* Setup protocol expert items */
static ei_register_info ei[] = {
    { &ei_decodeerror, { "packet-paradoxip.expert", PI_UNDECODED, PI_ERROR, "Paradox Alarm IP protocol", EXPFILL } },
    { &ei_decodewarn, { "packet-paradoxip.expert", PI_UNDECODED, PI_WARN, "Paradox Alarm IP protocol", EXPFILL } },
};

/**********************************************************************************************/

typedef struct _savedippwd_t {
    unsigned char ipaddr[4];
    unsigned char password[1];
} savedippwd_t;

typedef struct _conv_info_t {
    char correctippwd;
    unsigned char* sessionkey;
} conv_info_t;

/* Global preferences */
#define PARADOXIP_TCP_PORT 10000
static guint tcp_default_port = PARADOXIP_TCP_PORT;
static guint tcp_current_port = 0;
static char* ip150_default_password = "paradox";
static char* ip150_password_filename = "";
static gboolean show_encrypted_bytes = FALSE;
static gboolean show_payload_bytes = TRUE;
static int numsavedpwd = 0;
static int numallocpwd = 0;
static savedippwd_t** savedpwds = NULL;

/* offsets for message header elements */
#define PIH_MAGIC 0
#define PIH_PAYLOADLEN 1
#define PIH_MSGTYPE 3
#define PIH_FLAGS 4
#define PIH_COMMAND 5
#define PIH_SUBCMD 6
#define PIH_WT 7
#define PIH_SB 8
#define PIH_CRYPTTYPE 9
#define PIH_UNUSED 10
#define PIH_SEQID 15 /* Is this location of SeqID byte correct? When is this used? */
#define PIH_PAYLOAD 16

/* Values for message header flags */
#define PIH_FLAGS_ENCRYPTED 0x01 /* 'Encrypted' bit in header flags field */

static unsigned char*(MessageTypeName[]) = { "", "IP Resp: ", "SerialResp: ", "IP Req: ", "SerialReq: " };

enum MessageTypeEnum {
    IPResponse = 1,
    SPTResponse = 2,
    IPRequest = 3,
    SPTRequest = 4
};

static unsigned char*(CommandNamesF0[]) = { "Connect ", "SendUserLabel ", "KeepAlive ", "UpDownConnect ", "UpDownDisconnect ", "BootLoader ", "WebPageConnect ", "WebPageDisconnect ", "ToggleKeepAlive ", "Reset ", "SetBaudRate ", "MultiCommand ", "SinglePanel ", "UnsupportedRequest ", "BootIP ", "Disconnect " };

enum CommandsEnum {
    Passthrough = 0,
    Connect = 0xF0,
    SendUserLabel,
    KeepAlive,
    UpDownConnect,
    UpDownDisconnect,
    BootLoader,
    WebPageConnect,
    WebPageDisconnect,
    ToggleKeepAlive,
    Reset,
    SetBaudRate,
    MultiCommand,
    SinglePanel,
    UnsupportedRequest,
    BootIP,
    Disconnect
};

enum SPTResponseEnum {
    StartCommunicationResp = 0x00,
    LoginConfirmationResp = 0x10,
    InitializeCommunicationResp = 0x10,
    SetTimeDateResp = 0x30,
    PerformActionResp = 0x40,
    ReadMemoryResp = 0x50,
    ResultCodeResp = 0x70,
    InitiateCommunication = 0x70,
    SetUnreadEventIDResp = 0x80,
    BroadcastResp = 0xA0,
    ReadSomethingResp = 0xC0,
    PerformZoneActionResp = 0xD0,
    EventMessageResp = 0xE0
};

enum SPTRequestEnum {
    InitializeCommunicationReq = 0x00,
    SetTimeDateReq = 0x30,
    PerformActionReq = 0x40,
    ReadMemoryReq50 = 0x50,
    ReadMemoryReq51,
    ReadMemoryReq52,
    ReadMemoryReq53,
    ReadMemoryReq54,
    ReadMemoryReq55,
    ReadMemoryReq56,
    ReadMemoryReq57,
    ReadMemoryReq58,
    ReadMemoryReq59,
    ReadMemoryReq5A,
    ReadMemoryReq5B,
    ReadMemoryReq5C,
    ReadMemoryReq5D,
    ReadMemoryReq5E,
    ReadMemoryReq5F,
    StartCommunicationReq = 0x5F,
    CloseConnectionReq = 0x70,
    SetUnreadEventIDReq = 0x80,
    InitiateCommunicationReq = 0x72,
    BroadcastReqA0 = 0xA0,
    BroadcastReqA1,
    BroadcastReqA2,
    BroadcastReqA3,
    BroadcastReqA4,
    BroadcastReqA5,
    BroadcastReqA6,
    BroadcastReqA7,
    BroadcastReqA8,
    BroadcastReqA9,
    BroadcastReqAA,
    BroadcastReqAB,
    BroadcastReqAC,
    BroadcastReqAD,
    BroadcastReqAE,
    BroadcastReqAF,
    PerformZoneActionReq = 0xD0,
    ReadSomethingReq = 0xC8,
    GetEventsReq = 0xE0
};

/* Get the IP module password associated with a given address or return default if no matching address */
unsigned char* getip150password(address* ip150addr)
{
    int c;
    int wildcard_idx = -1;
    unsigned char wildcard_addr[4] = { 0, 0, 0, 0 };

    if (savedpwds && (ip150addr->type == AT_IPv4)) {
        for (c = 0; c < numsavedpwd; c++) {
            if (!memcmp(savedpwds[c]->ipaddr, ip150addr->data, 4))
                return savedpwds[c]->password;
            if (!memcmp(savedpwds[c]->ipaddr, wildcard_addr, 4))
                wildcard_idx = c;
        }

        if (wildcard_idx >= 0)
            return savedpwds[wildcard_idx]->password;
    }
    return ip150_default_password;
}

int validate_serial_checksum(tvbuff_t* tvb)
{
    guint len = tvb_reported_length(tvb);
    const guint8* p = tvb_get_ptr(tvb, 0, len);
    guint8 sum = 0;

    if (len < 2)
        return 1;

    while (--len)
        sum += *(p++);

    return *p == sum;
}

void dissect_spt_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_item* item_ti;
    proto_tree* field_tree;
    guint8 command_code = tvb_get_guint8(tvb, 0);
    guint msgsize = tvb_reported_length(tvb);
    guint32 address;
    guint32 flags;
    guint32 index;
    guint32 count;
    guint8 strbuf[256];
    guint8* s1;
    guint8* s2;

    if (msgsize == 37) {
        /* Handle 37 byte fixed size messages ... older messages ... mostly SP/Magellan */
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(command_code, &SPTRequestCmd37_id_values_ext, "<unknown>%02X"));
        item_ti = proto_tree_add_item(tree, hf_spt_req_cmd37, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        switch (command_code) {
        case InitializeCommunicationReq:
            // todo: needs more work
            item_ti = proto_tree_add_item(tree, hf_spt_moduleaddr, tvb, 1, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_productid, tvb, 4, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_string(tree, hf_spt_fwver, tvb, 5, 3, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 5), tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7)));
            item_ti = proto_tree_add_item(tree, hf_spt_panelid, tvb, 8, 2, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_pcpasswd, tvb, 10, 2, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_modemspeed, tvb, 12, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_sourcemethod, tvb, 13, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_usercode, tvb, 14, 3, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_string(tree, hf_spt_serialno, tvb, 17, 4, wmem_strdup_printf(wmem_packet_scope(), "%08X", tvb_get_guint32(tvb, 17, ENC_BIG_ENDIAN)));
            /* todo: break this out into flags. also todo: check if we are on EVO or not, only define for EVO? - use productID in this message */
            item_ti = proto_tree_add_item(tree, hf_spt_systemoptions, tvb, 21, 9, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 30, 4, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_sourceid, tvb, 34, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_carrierlen, tvb, 35, 1, ENC_LITTLE_ENDIAN);
            break;
        case SetTimeDateReq:
        case PerformActionReq:
        case ReadMemoryReq50:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;
        case StartCommunicationReq:
            item_ti = proto_tree_add_item(tree, hf_spt_validation, tvb, 1, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 2, 31, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_sourceid, tvb, 33, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_userid, tvb, 34, 2, ENC_LITTLE_ENDIAN);
            break;
        case CloseConnectionReq:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;
        case InitiateCommunicationReq:
            /* PAI has command as upper nibble, and lower nibble as reserved (2). We treat it as command 0x72 */
            item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 1, 35, ENC_NA);
            break;
        default:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;
        }
    } else {
        /* Handle variable length messages - any message with size!=37 bytes SEEM to have a length byte */
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(command_code, &SPTRequestCommand_id_values_ext, "<unknown>%02X"));
        item_ti = proto_tree_add_item(tree, hf_spt_req_cmd, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        if (command_code != ReadSomethingReq) {
            /* Most messages have an 8 byte length */
            item_ti = proto_tree_add_item(tree, hf_spt_length, tvb, 1, 1, ENC_BIG_ENDIAN);
            if (tvb_get_guint8(tvb, 1) != msgsize)
                expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Length field does not match actual message size");
        } else {
            /* Message C8 (ReadSomething) is an exception with 16 bit length */
            item_ti = proto_tree_add_item(tree, hf_spt_length16, tvb, 1, 2, ENC_BIG_ENDIAN);
            if (tvb_get_guint16(tvb, 1, ENC_BIG_ENDIAN) != msgsize)
                expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Length field does not match actual message size");
        }

        switch (command_code) {
        case SetTimeDateReq:
            item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 2, 4, ENC_NA);
            s1 = wmem_strdup_printf(wmem_packet_scope(), "%02d%02d/%d/%d", tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7), tvb_get_guint8(tvb, 8), tvb_get_guint8(tvb, 9));
            item_ti = proto_tree_add_string(tree, hf_spt_date, tvb, 6, 4, s1);
            s2 = wmem_strdup_printf(wmem_packet_scope(), "%02d:%02d", tvb_get_guint8(tvb, 10), tvb_get_guint8(tvb, 11));
            item_ti = proto_tree_add_string(tree, hf_spt_time, tvb, 10, 2, s2);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " %s %s", s1, s2));
            break;

        case PerformActionReq:
            item_ti = proto_tree_add_item(tree, hf_spt_action, tvb, 2, 1, ENC_LITTLE_ENDIAN);
            // todo: determine the protocol data per action type and decode
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 3, msgsize - 4, ENC_NA);
            break;

        case ReadMemoryReq50: /* fallthrough */
        case ReadMemoryReq51: /* fallthrough */
        case ReadMemoryReq52: /* fallthrough */
        case ReadMemoryReq53: /* fallthrough */
        case ReadMemoryReq54: /* fallthrough */
        case ReadMemoryReq55: /* fallthrough */
        case ReadMemoryReq56: /* fallthrough */
        case ReadMemoryReq57: /* fallthrough */
        case ReadMemoryReq58: /* fallthrough */
        case ReadMemoryReq59: /* fallthrough */
        case ReadMemoryReq5A: /* fallthrough */
        case ReadMemoryReq5B: /* fallthrough */
        case ReadMemoryReq5C: /* fallthrough */
        case ReadMemoryReq5D: /* fallthrough */
        case ReadMemoryReq5E: /* fallthrough */
        case ReadMemoryReq5F:
            flags = tvb_get_guint8(tvb, 2);
            if (!g_snprintf(strbuf, sizeof(strbuf), "%s%s%s%s%s", flags & 0x80 ? " RAM access" : "", flags & 0x40 ? " report_pending" : "", flags & 0x20 ? " winload" : "", flags & 0x10 ? " neware" : "", flags & 0x0C ? " not-used" : ""))
                strbuf[1] = 0;
            item_ti = proto_tree_add_uint_format(tree, hf_spt_readctl, tvb, 2, 1, flags & 0xFC, "Control flags: 0x%02x (%s)", flags & 0xFC, strbuf + 1);
            field_tree = proto_item_add_subtree(item_ti, ett_spt_readmemctl);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ram, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ar, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_wl, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ne, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_nu, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_uint(tree, hf_spt_memblock, tvb, 0, 1, tvb_get_guint8(tvb, 0) & 0x0F);
            item_ti = proto_tree_add_item(tree, hf_spt_busaddress, tvb, 3, 1, ENC_NA);
            address = (tvb_get_guint8(tvb, 2) & 0x03) << 16 | tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_uint(tree, hf_spt_address32, tvb, 2, 4, address);
            item_ti = proto_tree_add_uint(tree, hf_spt_addresshigh, tvb, 2, 1, tvb_get_guint8(tvb, 2) & 0x03);
            item_ti = proto_tree_add_item(tree, hf_spt_addresslow, tvb, 4, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_bytestoread, tvb, 6, 1, ENC_NA);

            g_snprintf(strbuf, sizeof(strbuf), " %s Bus:%d Addresss:%X Size:%02X", flags & 0x80 ? "RAM" : "EEPROM", tvb_get_guint8(tvb, 3), address, tvb_get_guint8(tvb, 6));
            col_append_str(pinfo->cinfo, COL_INFO, strbuf);
            break;

        case CloseConnectionReq:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case SetUnreadEventIDReq:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_eventnr, tvb, 4, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 6, 2, ENC_NA);
            index = tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " EventNr:%d", index));
            break;

        case BroadcastReqA0: /* fallthrough */
        case BroadcastReqA1: /* fallthrough */
        case BroadcastReqA2: /* fallthrough */
        case BroadcastReqA3: /* fallthrough */
        case BroadcastReqA4: /* fallthrough */
        case BroadcastReqA5: /* fallthrough */
        case BroadcastReqA6: /* fallthrough */
        case BroadcastReqA7: /* fallthrough */
        case BroadcastReqA8: /* fallthrough */
        case BroadcastReqA9: /* fallthrough */
        case BroadcastReqAA: /* fallthrough */
        case BroadcastReqAB: /* fallthrough */
        case BroadcastReqAC: /* fallthrough */
        case BroadcastReqAD: /* fallthrough */
        case BroadcastReqAE: /* fallthrough */
        case BroadcastReqAF:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;

        case ReadSomethingReq:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 3, 1, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 4, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_index16, tvb, 6, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_recstoread16, tvb, 8, 2, ENC_BIG_ENDIAN);
            index = tvb_get_guint16(tvb, 6, ENC_BIG_ENDIAN);
            count = tvb_get_guint16(tvb, 8, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " Index:%X NumRequested:%X Unknown1:%02X, Unknown2:%04X", index, count, tvb_get_guint8(tvb, 3), tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN)));
            break;

        case PerformZoneActionReq:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;

        case GetEventsReq:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_eventnr, tvb, 4, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_recstoread, tvb, 6, 1, ENC_BIG_ENDIAN);
            index = tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
            count = tvb_get_guint8(tvb, 6);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " EventNr:%d NumRequested:%d", index, count));
            break;

        default:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;
        }
    }

    item_ti = proto_tree_add_item(tree, hf_spt_checksum, tvb, msgsize - 1, 1, ENC_UTF_8 | ENC_NA);
    if (!validate_serial_checksum(tvb))
        expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Warning: Incorrect checksum for this message");
}

void dissect_spt_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_item* item_ti;
    proto_tree* field_tree;
    proto_tree* trx_tree;
    guint8 command_code = tvb_get_guint8(tvb, 0) & 0xF0;
    guint msgsize = tvb_reported_length(tvb);
    guint32 address;
    guint32 flags;
    guint32 index;
    guint32 offset;
    guint32 count;
    guint32 ui;
    guint8 strbuf[256];
    guint8* s1;
    guint8* s2;

    if ((msgsize == 37) && (command_code == InitiateCommunication) && (tvb_get_guint8(tvb, 1) == 0xFF)) {
        /* Special case for overloaded command code. Handle InitiateCommunication here */
        col_append_str(pinfo->cinfo, COL_INFO, "InitiateCommunication");
        item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_cmd, tvb, 0, 1, command_code, wmem_strdup_printf(wmem_packet_scope(), "Response: InitiateCommunication (0x%Xx)", command_code >> 4));
        item_ti = proto_tree_add_uint(tree, hf_spt_messagecentre, tvb, 0, 1, tvb_get_guint8(tvb, 0) & 0x0F);

        /* todo: dissect InitiateCommunicationResponse message */
        item_ti = proto_tree_add_item(tree, hf_spt_newprotocol, tvb, 1, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_spt_protocolid, tvb, 2, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_string(tree, hf_spt_protcolver, tvb, 3, 3, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 3), tvb_get_guint8(tvb, 4), tvb_get_guint8(tvb, 5)));

        item_ti = proto_tree_add_item(tree, hf_spt_icfamilyid, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_spt_icproductid, tvb, 7, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_spt_talker, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_string(tree, hf_spt_appver, tvb, 9, 3, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 9), tvb_get_guint8(tvb, 10), tvb_get_guint8(tvb, 11)));
        item_ti = proto_tree_add_string(tree, hf_spt_serialno, tvb, 12, 4, wmem_strdup_printf(wmem_packet_scope(), "%08X", tvb_get_guint32(tvb, 12, ENC_BIG_ENDIAN)));
        item_ti = proto_tree_add_string(tree, hf_spt_hwver, tvb, 16, 2, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X", tvb_get_guint8(tvb, 16), tvb_get_guint8(tvb, 17)));
        item_ti = proto_tree_add_string(tree, hf_spt_bootver, tvb, 18, 3, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 18), tvb_get_guint8(tvb, 19), tvb_get_guint8(tvb, 20)));
        item_ti = proto_tree_add_string(tree, hf_spt_bootdate, tvb, 21, 3, wmem_strdup_printf(wmem_packet_scope(), "%02X/%02X/%02X", tvb_get_guint8(tvb, 23), tvb_get_guint8(tvb, 22), tvb_get_guint8(tvb, 21)));
        item_ti = proto_tree_add_item(tree, hf_spt_cpuid, tvb, 24, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_spt_cryptoid, tvb, 25, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 26, 2, ENC_NA);
        item_ti = proto_tree_add_item(tree, hf_spt_label, tvb, 28, 8, ENC_LITTLE_ENDIAN);
    } else if (msgsize == 37) {
        /* Handle 37 byte fixed size messages ... older messages ... mostly SP/Magellan */
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(command_code, &SPTResponseCmd37_id_values_ext, "<unknown>%02X"));
        item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_cmd37, tvb, 0, 1, command_code, wmem_strdup_printf(wmem_packet_scope(), "Response: %s (0x%Xx)", val_to_str_ext(command_code, &SPTResponseCmd37_id_values_ext, "<unknown>%02X"), command_code >> 4));

        /* Dissect the status flags in lower nibble of command byte */
        flags = tvb_get_guint8(tvb, 0) & 0x0F;
        if (!g_snprintf(strbuf, sizeof(strbuf), "%s%s%s%s", flags & 0x08 ? " reserved" : "", flags & 0x04 ? " report_pending" : "", flags & 0x02 ? " winload" : "", flags & 0x01 ? " neware" : ""))
            strbuf[1] = 0;
        item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_status, tvb, 0, 1, flags, "Status flags: 0x%02x (%s)", flags, strbuf + 1);
        field_tree = proto_item_add_subtree(item_ti, ett_spt_responsestatus);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_re, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_ar, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_wl, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_ne, tvb, 0, 1, flags);

        /* Handle specific commands */
        switch (command_code) {
        case StartCommunicationResp:
            item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 1, 3, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_productid, tvb, 4, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_string(tree, hf_spt_fwver, tvb, 5, 3, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 5), tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7)));
            item_ti = proto_tree_add_item(tree, hf_spt_panelid, tvb, 8, 2, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 10, 5, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_transceiver, tvb, 15, 7, ENC_NA);
            trx_tree = proto_item_add_subtree(item_ti, ett_spt_trxdetails);
            item_ti = proto_tree_add_string(trx_tree, hf_spt_trxfwver, tvb, 15, 4, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X.%d", tvb_get_guint8(tvb, 17), tvb_get_guint8(tvb, 18), tvb_get_guint8(tvb, 15)));
            item_ti = proto_tree_add_item(trx_tree, hf_spt_trxfamily, tvb, 16, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(trx_tree, hf_spt_trxnoise, tvb, 19, 1, ENC_LITTLE_ENDIAN);

            flags = tvb_get_guint8(tvb, 20);
            if (!g_snprintf(strbuf, sizeof(strbuf), "%s%s%s", flags & 0xFC ? " not_used" : "", flags & 0x02 ? " high_noise" : "", flags & 0x01 ? " constant_carrier" : ""))
                strbuf[1] = 0;
            item_ti = proto_tree_add_uint_format(trx_tree, hf_spt_trxstatus, tvb, 20, 1, flags, "Status flags: 0x%02x (%s)", flags, strbuf + 1);
            field_tree = proto_item_add_subtree(item_ti, ett_spt_trxstatus);
            proto_tree_add_boolean(field_tree, hf_spt_trxflags_nu, tvb, 20, 1, flags);
            proto_tree_add_boolean(field_tree, hf_spt_trxflags_nh, tvb, 20, 1, flags);
            proto_tree_add_boolean(field_tree, hf_spt_trxflags_cc, tvb, 20, 1, flags);
            item_ti = proto_tree_add_item(trx_tree, hf_spt_trxhwrev, tvb, 21, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 22, 14, ENC_NA);
            break;

        case InitializeCommunicationResp:
        case SetTimeDateResp:
        case PerformActionResp:
        case ReadMemoryResp:
        case ResultCodeResp:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;

        case EventMessageResp:
            item_ti = proto_tree_add_item(tree, hf_spt_newprotocol, tvb, 1, 1, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_eventnr, tvb, 2, 2, ENC_NA);
            s1 = wmem_strdup_printf(wmem_packet_scope(), "%02d%02d/%d/%d", tvb_get_guint8(tvb, 4), tvb_get_guint8(tvb, 5), tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7));
            s2 = wmem_strdup_printf(wmem_packet_scope(), "%02d:%02d", tvb_get_guint8(tvb, 8), tvb_get_guint8(tvb, 9));
            item_ti = proto_tree_add_string(tree, hf_spt_eventdate, tvb, 4, 4, s1);
            item_ti = proto_tree_add_string(tree, hf_spt_eventtime, tvb, 8, 2, s2);
            item_ti = proto_tree_add_item(tree, hf_spt_eventgroup, tvb, 10, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_uint(tree, hf_spt_partition, tvb, 11, 1, tvb_get_guint8(tvb, 11) & 0x0F);
            item_ti = proto_tree_add_uint(tree, hf_spt_event1, tvb, 12, 1, ((tvb_get_guint8(tvb, 11) >> 6) & 0x0300) | tvb_get_guint8(tvb, 12));
            item_ti = proto_tree_add_uint(tree, hf_spt_event2, tvb, 13, 1, ((tvb_get_guint8(tvb, 11) >> 4) & 0x0300) | tvb_get_guint8(tvb, 13));
            item_ti = proto_tree_add_string(tree, hf_spt_serialno, tvb, 14, 4, wmem_strdup_printf(wmem_packet_scope(), "%08X", tvb_get_guint32(tvb, 14, ENC_BIG_ENDIAN)));
            item_ti = proto_tree_add_item(tree, hf_spt_labeltype, tvb, 18, 1, ENC_LITTLE_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_label, tvb, 19, 16, ENC_UTF_8);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 35, 1, ENC_NA);

            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " EventNr:%d partition %d: group %d event1 %d event2 %d - %s", tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN), tvb_get_guint8(tvb, 11) & 0x0F, tvb_get_guint8(tvb, 10), ((tvb_get_guint8(tvb, 11) >> 6) & 0x0300) | tvb_get_guint8(tvb, 12), ((tvb_get_guint8(tvb, 11) >> 4) & 0x0300) | tvb_get_guint8(tvb, 13), tvb_get_string_enc(wmem_packet_scope(), tvb, 19, 16, ENC_UTF_8)));
            break;

        default:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 1, msgsize - 2, ENC_NA);
            break;
        }
    } else {
        /* Handle variable length messages here  */
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(command_code, &SPTResponseCommand_id_values_ext, "<unknown>%02X"));
        item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_cmd37, tvb, 0, 1, command_code, wmem_strdup_printf(wmem_packet_scope(), "Response: %s (0x%Xx)", val_to_str_ext(command_code, &SPTResponseCommand_id_values_ext, "<unknown>%02X"), command_code >> 4));

        /* Dissect the status flags in lower nibble of command byte */
        flags = tvb_get_guint8(tvb, 0) & 0x0F;
        if (!g_snprintf(strbuf, sizeof(strbuf), "%s%s%s%s", flags & 0x08 ? " reserved" : "", flags & 0x04 ? " report_pending" : "", flags & 0x02 ? " winload" : "", flags & 0x01 ? " neware" : ""))
            strbuf[1] = 0;
        item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_status, tvb, 0, 1, flags, "Status flags: 0x%02x (%s)", flags, strbuf + 1);
        field_tree = proto_item_add_subtree(item_ti, ett_spt_responsestatus);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_re, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_ar, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_wl, tvb, 0, 1, flags);
        proto_tree_add_boolean(field_tree, hf_spt_resp_flags_ne, tvb, 0, 1, flags);

        if ((command_code == EventMessageResp) && (tvb_get_guint8(tvb, 1) == 0xFF)) {
            /* Special case for live events messages. They can be != 37 but does not have length field */
            /* This was actually two concatenated live event messages... can this happen with other msg? */
        } else if (command_code != ReadSomethingResp) {
            /* Most messages have an 8 byte length */
            item_ti = proto_tree_add_item(tree, hf_spt_length, tvb, 1, 1, ENC_BIG_ENDIAN);
            if (tvb_get_guint8(tvb, 1) != msgsize)
                expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Length field does not match actual message size");
        } else {
            /* Message C8 (ReadSomething) is an exception with 16 bit length */
            item_ti = proto_tree_add_item(tree, hf_spt_length16, tvb, 1, 2, ENC_BIG_ENDIAN);
            if (tvb_get_guint16(tvb, 1, ENC_BIG_ENDIAN) != msgsize)
                expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Length field does not match actual message size");
        }

        /* Handle specific commands */
        switch (command_code) {
        case LoginConfirmationResp:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case SetTimeDateResp:
            // We don't better about message contents. Suspect it is a result code.
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case PerformActionResp:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case ReadMemoryResp:
            flags = tvb_get_guint8(tvb, 2);
            if (!g_snprintf(strbuf, sizeof(strbuf), "%s%s%s%s%s", flags & 0x80 ? " RAM access" : "", flags & 0x40 ? " report_pending" : "", flags & 0x20 ? " winload" : "", flags & 0x10 ? " neware" : "", flags & 0x0C ? " not-used" : ""))
                strbuf[1] = 0;
            item_ti = proto_tree_add_uint_format(tree, hf_spt_readctl, tvb, 2, 1, flags & 0xFC, "Control flags: 0x%02x (%s)", flags & 0xFC, strbuf + 1);
            field_tree = proto_item_add_subtree(item_ti, ett_spt_readmemctl);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ram, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ar, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_wl, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_ne, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(field_tree, hf_spt_readctl_nu, tvb, 2, 1, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_busaddress, tvb, 3, 1, ENC_NA);
            address = (tvb_get_guint8(tvb, 2) & 0x03) << 16 | tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_uint(tree, hf_spt_address32, tvb, 2, 4, address);
            item_ti = proto_tree_add_uint(tree, hf_spt_addresshigh, tvb, 2, 1, tvb_get_guint8(tvb, 2) & 0x03);
            item_ti = proto_tree_add_item(tree, hf_spt_addresslow, tvb, 4, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_memorydata, tvb, 6, msgsize - 7, ENC_NA);
            item_ti = proto_tree_add_uint(tree, hf_spt_compsize, tvb, 0, 0, msgsize - 7);

            g_snprintf(strbuf, sizeof(strbuf), " %s Bus:%d Addresss:%X Size:%02X", flags & 0x80 ? "RAM" : "EEPROM", tvb_get_guint8(tvb, 3), address, msgsize - 7);
            col_append_str(pinfo->cinfo, COL_INFO, strbuf);
            break;

        case ResultCodeResp:
            item_ti = proto_tree_add_item(tree, hf_spt_resultcode, tvb, 2, 1, ENC_LITTLE_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, " Result:");
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(tvb_get_guint8(tvb, 2), &ResultCode_id_values_ext, "<unknown>%02X"));
            break;

        case SetUnreadEventIDResp:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_eventnr, tvb, 4, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 6, 2, ENC_NA);
            index = tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " EventNr:%d", index));
            break;

        case BroadcastResp:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case ReadSomethingResp:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 3, 1, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 4, 2, ENC_NA);
            item_ti = proto_tree_add_item(tree, hf_spt_index16, tvb, 6, 2, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_item(tree, hf_spt_numrecords16, tvb, 8, 2, ENC_BIG_ENDIAN);
            index = tvb_get_guint16(tvb, 6, ENC_BIG_ENDIAN);
            count = tvb_get_guint16(tvb, 8, ENC_BIG_ENDIAN);
            item_ti = proto_tree_add_uint(tree, hf_spt_compsize, tvb, 0, 0, msgsize - 11);
            col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " Index:%X NumReturned:%X Unknown1:%02X, Unknown2:%04X, Size:%02X", index, count, tvb_get_guint8(tvb, 3), tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN), msgsize - 11));
            // todo: must still decode this - also unrol this into records once we figure out the record size!
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 10, msgsize - 11, ENC_NA);
            break;

        case PerformZoneActionResp:
            // todo: must still decode this
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;

        case EventMessageResp:
            if (tvb_get_guint8(tvb, 1) == 0xFF) {
                /* Live events message */
                // todo: must still decode this
                // If we get here we have multiple 37 byte messages in one packet :( How to handle....
            } else {
                /* Stored / compressed event message */
                item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, 2, ENC_NA);
                item_ti = proto_tree_add_item(tree, hf_spt_eventnr, tvb, 4, 2, ENC_BIG_ENDIAN);
                index = tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN);
                count = 0;
                offset = 6;
                while (offset + 12 < tvb_reported_length(tvb)) {
                    /* Unpacked event... unpack the various fields */
                    ui = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    s1 = wmem_strdup_printf(wmem_packet_scope(), "%02d%02d/%d/%d", (ui >> 16) & 0x7F, (ui >> 9) & 0x7F, (ui >> 23) & 0x0F, ui >> 27);
                    ui = tvb_get_guint32(tvb, offset + 2, ENC_BIG_ENDIAN);
                    s2 = wmem_strdup_printf(wmem_packet_scope(), "%02d:%02d", (ui >> 20) & 0x1F, (ui >> 14) & 0x3F);
                    ui = tvb_get_guint32(tvb, offset + 4, ENC_BIG_ENDIAN);

                    item_ti = proto_tree_add_bytes_format(tree, hf_spt_packedevent, tvb, offset, 12, tvb_get_ptr(tvb, offset, 12), wmem_strdup_printf(wmem_packet_scope(), " EventNumber %X %s %s partition %d: group %d event1 %d event2 %d", index + count, s1, s2, (ui >> 20) & 0x0F, (ui >> 24) & 0x3F, ((ui >> 10) & 0x0300) | ((ui >> 8) & 0xFF), ((ui >> 8) & 0x0300) | (ui & 0xFF)));
                    field_tree = proto_item_add_subtree(item_ti, ett_spt_cmpevent);
                    item_ti = proto_tree_add_string(field_tree, hf_spt_eventdate, tvb, offset, 3, s1);
                    item_ti = proto_tree_add_string(field_tree, hf_spt_eventtime, tvb, offset + 2, 3, s2);
                    item_ti = proto_tree_add_uint(field_tree, hf_spt_eventgroup, tvb, offset + 4, 1, (ui >> 24) & 0x3F);
                    item_ti = proto_tree_add_uint(field_tree, hf_spt_partition, tvb, offset + 5, 1, (ui >> 20) & 0x0F);
                    item_ti = proto_tree_add_uint(field_tree, hf_spt_event1, tvb, offset + 6, 1, ((ui >> 10) & 0x0300) | ((ui >> 8) & 0xFF));
                    item_ti = proto_tree_add_uint(field_tree, hf_spt_event2, tvb, offset + 7, 1, ((ui >> 8) & 0x0300) | (ui & 0xFF));
                    item_ti = proto_tree_add_string(field_tree, hf_spt_serialno, tvb, offset + 8, 4, wmem_strdup_printf(wmem_packet_scope(), "%08X", tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN)));
                    offset += 12;
                    count += 1;
                }
                col_append_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(wmem_packet_scope(), " EventNr:%d NumRequested:%d", index, count));
                break;
            }

        default:
            item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 2, msgsize - 3, ENC_NA);
            break;
        }
    }
    item_ti = proto_tree_add_item(tree, hf_spt_checksum, tvb, msgsize - 1, 1, ENC_LITTLE_ENDIAN);
    if (!validate_serial_checksum(tvb))
        expert_add_info_format(pinfo, item_ti, &ei_decodewarn, "Warning: Incorrect checksum for this message");
}

void dissect_ip_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int command)
{
    proto_item* item_ti;

    switch (command) {
    case Connect:
        item_ti = proto_tree_add_item(tree, hf_ip_con_req_password, tvb, 0, -1, ENC_UTF_8 | ENC_NA);
        col_append_str(pinfo->cinfo, COL_INFO, " Password:");
        col_append_str(pinfo->cinfo, COL_INFO, tvb_get_string_enc(wmem_packet_scope(), tvb, 0, tvb_reported_length(tvb), ENC_UTF_8 | ENC_NA));
        break;
    default:
        item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 0, -1, ENC_NA);
        break;
    }
}

void dissect_ip_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int command)
{
    proto_item* item_ti;

    switch (command) {
    case Connect:
        item_ti = proto_tree_add_item(tree, hf_ip_con_resp_result, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_item(tree, hf_ip_con_resp_sessionkey, tvb, 1, 16, ENC_UTF_8 | ENC_NA);
        item_ti = proto_tree_add_item(tree, hf_ip_con_resp_hwver, tvb, 17, 2, ENC_LITTLE_ENDIAN);
        item_ti = proto_tree_add_string(tree, hf_ip_con_resp_fwver, tvb, 19, 2, wmem_strdup_printf(wmem_packet_scope(), "%X.%02X", tvb_get_guint8(tvb, 19), tvb_get_guint8(tvb, 20)));
        item_ti = proto_tree_add_string(tree, hf_ip_con_resp_serialno, tvb, 21, 4, wmem_strdup_printf(wmem_packet_scope(), "%08X", tvb_get_guint32(tvb, 21, ENC_BIG_ENDIAN)));
        /* Following item not present in tested IP150 data... maybe later models? */
        /* item_ti= proto_tree_add_item(tree,hf_ip_con_resp_model,tvb,25,1,ENC_LITTLE_ENDIAN); */

        col_append_str(pinfo->cinfo, COL_INFO, " Result:");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(tvb_get_guint8(tvb, 0), &ConnectResult_id_values_ext, "<unknown>%02X"));
        col_append_str(pinfo->cinfo, COL_INFO, " Session:");
        col_append_str(pinfo->cinfo, COL_INFO, tvb_get_string_enc(wmem_packet_scope(), tvb, 1, 16, ENC_UTF_8 | ENC_NA));

        break;
    default:
        item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 0, -1, ENC_NA);
        break;
    }
}

/* Code to actually dissect the packets */
static int dissect_paradoxip(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* protocol_ti;
    proto_item* serial_ti;
    proto_item* header_ti;
    proto_item* item_ti;
    proto_tree* encbytes_ti;
    proto_tree* paradoxip_tree;
    proto_tree* header_tree;
    proto_tree* serial_tree;
    proto_tree* field_tree;
    tvbuff_t* next_tvb;
    conversation_t* conversation;
    conv_info_t* conv_info;

    int flags;
    char flags_str[256];
    int payload_length;
    int msgtype;
    int command;
    int subcmd;
    unsigned char* decryptkey;
    unsigned char* msgtype_desc;
    unsigned char* command_name;
    unsigned char* direction_name;

    payload_length = tvb_get_guint16(tvb, PIH_PAYLOADLEN, ENC_LITTLE_ENDIAN);
    msgtype = tvb_get_guint8(tvb, PIH_MSGTYPE);
    flags = tvb_get_guint8(tvb, PIH_FLAGS);
    command = tvb_get_guint8(tvb, PIH_COMMAND);
    subcmd = tvb_get_guint8(tvb, PIH_SUBCMD);

    /* Set the Protocol column to the constant string of rmcluster */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "paradoxip");

    switch (msgtype) {
    case IPRequest:
        msgtype_desc = "IP<- ";
        direction_name = "request";
        break;
    case IPResponse:
        msgtype_desc = "IP-> ";
        direction_name = "response";
        break;
    case SPTRequest:
        msgtype_desc = "Serial<- ";
        direction_name = "request";
        break;
    case SPTResponse:
        msgtype_desc = "Serial-> ";
        direction_name = "response";
        break;
    default:
        msgtype_desc = wmem_strdup_printf(wmem_packet_scope(), "<msgtype %02X>: ", msgtype);
        direction_name = "";
        break;
    }
    col_add_str(pinfo->cinfo, COL_INFO, msgtype_desc);

    if (command == Passthrough) {
        command_name = "Serial passthrough ";
        /* Don't explicitly add this to summary */
        /* col_append_str(pinfo->cinfo,COL_INFO,command_name); */
    } else if ((command >= 0xF0) && ((command - 0xF0) < (sizeof(CommandNamesF0) / sizeof(*CommandNamesF0)))) {
        command_name = CommandNamesF0[command - 0xF0];
        col_append_str(pinfo->cinfo, COL_INFO, command_name);
    } else {
        command_name = wmem_strdup_printf(wmem_packet_scope(), "<command %02X> ", command);
        col_append_str(pinfo->cinfo, COL_INFO, command_name);
    }
    /* Don't add the sub-command - not really usefull in the end */
    /* col_append_str(pinfo->cinfo,COL_INFO,wmem_strdup_printf (wmem_packet_scope(),"<sub %02X> ",subcmd)); */

    /* create display subtree for the protocol */
    protocol_ti = proto_tree_add_item(tree, proto_paradoxip, tvb, 0, -1, ENC_NA);
    paradoxip_tree = proto_item_add_subtree(protocol_ti, ett_paradoxip);
    /* And create another subtree for header fields */
    header_ti = proto_tree_add_item(paradoxip_tree, hf_header_tree, tvb, 0, 16, ENC_NA);
    header_tree = proto_item_add_subtree(header_ti, ett_header);

    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_sof, tvb, PIH_MAGIC, 1, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_length, tvb, PIH_PAYLOADLEN, 2, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_msgtype, tvb, PIH_MSGTYPE, 1, ENC_LITTLE_ENDIAN);

    if (!g_snprintf(flags_str, sizeof(flags_str), "%s%s%s%s%s%s%s%s", flags & 0x80 ? " bit8" : "", flags & 0x40 ? " keep_alive" : "", flags & 0x20 ? " live_events" : "", flags & 0x10 ? " neware" : "",
            flags & 0x08 ? " installer_mode" : "", flags & 0x04 ? " bit3" : "", flags & 0x02 ? " upload_download" : "", flags & 0x01 ? " encrypted" : ""))
        flags_str[1] = 0;
    item_ti = proto_tree_add_uint_format(header_tree, hf_paradoxip_flags, tvb, PIH_FLAGS, 1, flags, "Flags: 0x%02x (%s)", flags, flags_str + 1);
    field_tree = proto_item_add_subtree(item_ti, ett_header_flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_b8, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_ka, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_le, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_nw, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_im, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_b3, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_ud, tvb, PIH_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_paradoxip_flags_cr, tvb, PIH_FLAGS, 1, flags);

    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_command, tvb, PIH_COMMAND, 1, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_subcmd, tvb, PIH_SUBCMD, 1, ENC_LITTLE_ENDIAN); /* May have to different sub-command HF's based on Command value */
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_wt, tvb, PIH_WT, 1, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_sb, tvb, PIH_SB, 1, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_crypttype, tvb, PIH_CRYPTTYPE, 1, ENC_LITTLE_ENDIAN);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_unused, tvb, PIH_UNUSED, PIH_SEQID - PIH_UNUSED, 0);
    item_ti = proto_tree_add_item(header_tree, hf_paradoxip_seqid, tvb, PIH_SEQID, 1, ENC_LITTLE_ENDIAN);

    /* Get pointer to conversation info, create new conversation info if not allocated yet */
    conversation = find_or_create_conversation(pinfo);
    conv_info = conversation_get_proto_data(conversation, proto_paradoxip);
    if (!conv_info) {
        conv_info = wmem_new(wmem_file_scope(), conv_info_t);
        memset(conv_info, 0, sizeof(*conv_info));
        conversation_add_proto_data(conversation, proto_paradoxip, conv_info);
    }

    item_ti = proto_tree_add_uint_format(paradoxip_tree, hf_paradoxip_cmdsummary, tvb, PIH_COMMAND, 1, command, "Command: %s%s", command_name, direction_name);

    /* Nothing more to do if there is no payload data */
    if (payload_length <= 0)
        return tvb_reported_length(tvb);

    /* Decrypt encrypted payload data - seems all payload will be encrypted */
    if (flags & PIH_FLAGS_ENCRYPTED) /* Encrypted payload */
    {
        size_t cryptsize = (payload_length + 15) & 0xFFF0;
        guchar* decrypted_buffer = (guchar*)wmem_alloc(pinfo->pool, cryptsize);

        /* Determine the key used for the encryption */
        if ((command == Connect) && (msgtype == IPRequest))
            decryptkey = getip150password(&pinfo->dst);
        else if ((command == Connect) && (msgtype == IPResponse))
            decryptkey = conv_info->correctippwd ? getip150password(&pinfo->src) : NULL;
        else {
            /* todo: update to allow multiple Connect operations in one conversation, each with own session key?? */
            decryptkey = conv_info->sessionkey;
        }

        encbytes_ti = protocol_ti;
        if (show_encrypted_bytes)
            encbytes_ti = proto_tree_add_item(paradoxip_tree, hf_paradoxip_cryptmsg, tvb, PIH_PAYLOAD, -1, 0);
        if (!decryptkey) {
            expert_add_info_format(pinfo, encbytes_ti, &ei_decodewarn, "Warning: no decryption key found for this login session - cannot decrypt payload data [IP connect response not seen or wrong password]");
            return tvb_reported_length(tvb);
        }

        decrypt_pdx_aex(tvb_get_ptr(tvb, PIH_PAYLOAD, -1), decrypted_buffer, cryptsize, decryptkey, strlen(decryptkey));

        /* Now re-setup the tvb buffer to have the new data */
        next_tvb = tvb_new_child_real_data(tvb, decrypted_buffer, payload_length, payload_length);
        add_new_data_source(pinfo, next_tvb, "Decrypted payload");

        /* Verify that we have the proper password for this IP150 module */
        if ((msgtype == IPRequest) && (command == Connect)) {
            if (strncmp(decryptkey, decrypted_buffer, payload_length)) {
                expert_add_info_format(pinfo, encbytes_ti, &ei_decodewarn, "Warning: incorrect IP module password supplied - cannot decrypt payload data [IP connect request password mismatch]");
                return tvb_reported_length(tvb);
            }
            conv_info->correctippwd = 1;
        }

        /* Save session key contained in the IP150 login response.  */
        /* todo: update to allow multiple Connect operations in one conversation, each with own session key?? */
        if ((PINFO_FD_VISITED(pinfo) == FALSE) && (msgtype == IPResponse) && (command == Connect) && conv_info->correctippwd)
            conv_info->sessionkey = wmem_strndup(wmem_file_scope(), decrypted_buffer + 1, 16);
    } else {
        next_tvb = tvb_new_subset_remaining(tvb, PIH_PAYLOAD);
    }

    if (show_payload_bytes)
        item_ti = proto_tree_add_item(paradoxip_tree, hf_paradoxip_payload, next_tvb, 0, -1, 0);

    if (msgtype == IPRequest) {
        dissect_ip_request(next_tvb, pinfo, paradoxip_tree, command);
    } else if (msgtype == IPResponse) {
        dissect_ip_response(next_tvb, pinfo, paradoxip_tree, command);
    } else if (((msgtype == SPTRequest) || (msgtype == SPTResponse)) && (command == Passthrough)) {
        /* Create a new tree for the serial message data */
        serial_ti = proto_tree_add_item(tree, hf_serial_tree, next_tvb, 0, -1, ENC_NA);
        serial_tree = proto_item_add_subtree(serial_ti, ett_serialmessage);
        if (msgtype == SPTRequest)
            dissect_spt_request(next_tvb, pinfo, serial_tree);
        else
            dissect_spt_response(next_tvb, pinfo, serial_tree);
    } else {
        item_ti = proto_tree_add_item(paradoxip_tree, hf_payload_unknown, next_tvb, 0, -1, ENC_NA);
    }

    return tvb_reported_length(tvb);
}

/* Handle splittings and reassembly of packets to make sure there is exactly one message in a tvb */
static int dissect_paradoxip_packet(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    tvbuff_t* next_tvb;
    int msglen;
    guint offset = 0;
    int message_count = 0;

    /* Keep processing Paradox IP messages until we run out of bytes in the buffer */
    while (tvb_reported_length_remaining(tvb, offset) >= PIH_PAYLOAD) /* Big enough to hold length field. Take that as minimum for now */
    {
        if (tvb_get_guint8(tvb, offset + PIH_MAGIC) != 0xAA)
            return offset; /* Message should start with 0xAA - else not a valid message */
        /* todo: add any other heuristics checks here to validate message protocol */
        msglen = PIH_PAYLOAD + tvb_get_guint16(tvb, offset + PIH_PAYLOADLEN, ENC_LITTLE_ENDIAN);
        if (tvb_get_guint8(tvb, offset + PIH_FLAGS) & PIH_FLAGS_ENCRYPTED) /* Encrypted flag set - round up payload to 16 byte multiple */
            msglen = (msglen + 15) & 0xFFF0;
        if (msglen > tvb_reported_length_remaining(tvb, offset))
            break; /* Not enough data to fill another message */

        if (message_count++) {
            col_append_str(pinfo->cinfo, COL_INFO, " | ");
            col_set_fence(pinfo->cinfo, COL_INFO);
        }

        /* Set up tvb and call the message dissector code  */
        next_tvb = tvb_new_subset_length(tvb, offset, msglen);
        offset += msglen; /* skip to start of next message */
        dissect_paradoxip(next_tvb, pinfo, tree, data);
    }

    /* If no more bytes remaining we are done */
    if (!tvb_reported_length_remaining(tvb, offset))
        return offset;

    /* If we fall out to here we don't have enough data in tvb do complete a PDU (message). */
    /* Ask wireshark to give us one more data segment.                                      */
    pinfo->desegment_offset = offset;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return -1;
}

static void ApplyPreferences(void)
{
    FILE* pwdfile = NULL;
    ;
    char line[256];
    char* pos;
    char* password;
    unsigned long tempval;
    unsigned char ipaddr[4];
    void* tempmem;
    savedippwd_t* newpwdrec;

    if (tcp_current_port != tcp_default_port) {
        if (tcp_current_port)
            dissector_delete_uint("tcp.port", tcp_current_port, paradoxip_handle);
        if (tcp_default_port)
            dissector_add_uint("tcp.port", tcp_default_port, paradoxip_handle);
        tcp_current_port = tcp_default_port;
    }

    /* Clear out saved IP module passwords. Free saved paswords and reset savedd count back to zero. Keep allocated array  */
    if (savedpwds)
        while (numsavedpwd > 0)
            free(savedpwds[--numsavedpwd]);

    /* We re-read the IP150 password file regardless whether it changed or not. How do we indicate read errors? */
    if (ip150_password_filename && (*ip150_password_filename))
        pwdfile = fopen(ip150_password_filename, "r");
    if (pwdfile) {
        /* read lines from the password file */
        while (fgets(line, sizeof(line), pwdfile)) {
            /* skip anything that does not start with a digit */
            if ((line[0] < '0') || (line[0] > '9'))
                continue;
            /* Read IP address octets */
            tempval = strtoul(line, &pos, 10);
            if ((tempval > 255) || (*pos != '.'))
                continue;
            ipaddr[0] = (unsigned char)tempval;
            tempval = strtoul(pos + 1, &pos, 10);
            if ((tempval > 255) || (*pos != '.'))
                continue;
            ipaddr[1] = (unsigned char)tempval;
            tempval = strtoul(pos + 1, &pos, 10);
            if ((tempval > 255) || (*pos != '.'))
                continue;
            ipaddr[2] = (unsigned char)tempval;
            tempval = strtoul(pos + 1, &pos, 10);
            if ((tempval > 255) || ((*pos != ' ') && (*pos != '\t')))
                continue;
            ipaddr[3] = (unsigned char)tempval;
            /* skip whitespace after IP address */
            while ((*pos == ' ') || (*pos == '\t'))
                pos++;
            password = pos;
            /* scan for end of password */
            while ((*pos) && (*pos != ' ') && (*pos != '\t') && (*pos != '\r') && (*pos != '\n'))
                pos++;
            *pos = 0;
            if (!(*password))
                continue;
            /* OK, we have found a valid IP address and non-blank password. Add it to the password list */
            if (numallocpwd == numsavedpwd) {
                numallocpwd += 10;
                tempmem = realloc(savedpwds, numallocpwd * sizeof(*savedpwds));
                if (!tempmem)
                    continue;
                savedpwds = (savedippwd_t**)tempmem;
            }
            newpwdrec = (savedippwd_t*)malloc(sizeof(*newpwdrec) + strlen(password));
            if (!newpwdrec)
                continue;
            memcpy(newpwdrec->ipaddr, ipaddr, 4);
            strcpy(newpwdrec->password, password);
            savedpwds[numsavedpwd++] = newpwdrec;
        }
        fclose(pwdfile);
    }
}

void proto_reg_handoff_paradoxip(void)
{
    paradoxip_handle = create_dissector_handle(dissect_paradoxip_packet, proto_paradoxip);
    if (tcp_default_port) {
        dissector_add_uint("tcp.port", tcp_default_port, paradoxip_handle);
        tcp_current_port = tcp_default_port;
    }
}

/* Register the protocol with Wireshark. */
void proto_register_paradoxip(void)
{
    module_t* paradoxip_module;
    expert_module_t* expert_paradoxip;

    /* Register the protocol name and description */
    proto_paradoxip = proto_register_protocol("Paradox Alarm IP message", "ParadoxAlarm", "paradoxip");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_paradoxip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_paradoxip = expert_register_protocol(proto_paradoxip);
    expert_register_field_array(expert_paradoxip, ei, array_length(ei));

    /* Register a preferences module */
    paradoxip_module = prefs_register_protocol(proto_paradoxip, ApplyPreferences);
    prefs_register_uint_preference(paradoxip_module, "tcp.port", "Default TCP port", "Set the default TCP port for Paradox alarm IP messages", 10, &tcp_default_port);
    prefs_register_bool_preference(paradoxip_module, "show_encrypted", "Show encrypted payload bytes", "Add an item for encrypted payload bytes in the protocol view", &show_encrypted_bytes);
    prefs_register_bool_preference(paradoxip_module, "show_payload", "Show message payload bytes", "Add an item for decrypted (or never encrypted) payload bytes in the protocol view", &show_payload_bytes);
    prefs_register_string_preference(paradoxip_module, "ip150_password", "Default IP150 module password", "Default IP150 password to use if no matches are found in the password file", &ip150_default_password);
    prefs_register_filename_preference(paradoxip_module, "password_file", "IP150 passwords file", "File with individual IP150 module IP addresses and passwords", &ip150_password_filename, FALSE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

// todo:
// remove stack allocates buffers. use    buffer=wmem_alloc(wmem_packet_scope(), MAX_BUFFER);
// more defensive dissecting (- check packet lengths
// internal state of the dissector), use the DISSECTOR_ASSERT macro for
// handling of truncated frames... .hmmm, test. (tvb captured vs tvb reported????)
