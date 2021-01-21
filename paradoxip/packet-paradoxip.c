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

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */
#include <epan/conversation.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet-paradoxip.h"
#include "pdxcrypt.h"

/**********************************************************************************************/

/* Initialize the protocol and registered fields */
static int proto_paradoxip= -1;
static dissector_handle_t paradoxip_handle;

static const value_string MessageType_id_values[]=
{
	{1,"IP Response"},
	{2,"Serial pass-thru Response"},
	{3,"IP Request"},
	{4,"Serial pass-thru Request"},
	{0,NULL}
};
static value_string_ext MessageType_id_values_ext= VALUE_STRING_EXT_INIT(MessageType_id_values);

static const value_string Command_id_values[]=
{
	{0x00,"Passthrough"},
	{0xF0,"Connect"},
	{0xF1,"Send user label"},
	{0xF2,"Keep-alive"},
	{0xF3,"Upload-download connection"},
	{0xF4,"Upload-download disconnection"},
	{0xF5,"boot_loader"},
	{0xF6,"Web page connect"},
	{0xF7,"Web page disconnect"},
	{0xF8,"Toggle keep-alive"},
	{0xF9,"Reset"},
	{0xFA,"Set baud rate"},
	{0xFB,"Multicommand"},
	{0xFC,"single_panel"},
	{0xFD,"Unsupported Request"},
	{0xFE,"boot_ip"},
	{0xFF,"Disconnect"},
	{0,NULL}
};
static value_string_ext Command_id_values_ext= VALUE_STRING_EXT_INIT(Command_id_values);

static const value_string SubCommand_id_values[]=
{
	{0,NULL}
};
static value_string_ext SubCommand_id_values_ext= VALUE_STRING_EXT_INIT(SubCommand_id_values);

static const value_string CryptType_id_values[]=
{
	{0,"none"},
	{1,"aes_256_ecb"},
	{0xEE,"old_module"},
	{0,NULL}
};
static value_string_ext CryptType_id_values_ext= VALUE_STRING_EXT_INIT(CryptType_id_values);

static const value_string ConnectResult_id_values[]=
{
	{0,"success"},
	{1,"invalid password"},
	{2,"user_already_connected"},
	{4,"user_already_connected1"},
	{0,NULL}
};
static value_string_ext ConnectResult_id_values_ext= VALUE_STRING_EXT_INIT(ConnectResult_id_values);

static const value_string IPModuleModel_id_values[]=
{
	{0x70,"IP100"},
	{0x71,"IP150"},
	{0,NULL}
};
static value_string_ext IPModuleModel_id_values_ext= VALUE_STRING_EXT_INIT(IPModuleModel_id_values);

static const value_string SPTResponseCommand_id_values[] =
{
        {0x00,"StartCommunication"},
        {0x10,"LoginConfirmation"},
        {0x30,"SetTimeDate"},
        {0x40,"PerformAction"},
        {0x50,"ReadEEPROM"},                                                     /* But also maps to ReadStatusReponse for SP */
        {0x70,"ErrorMessage"},                                                           /* But also maps to HW_InitiateCommunicationResponse */
        {0xA0,"Broadcast"},
        {0xD0,"PerformZoneAction"},
        {0xE0,"EventMessage"},                                                           /* How closely does EVO and SP structures map? */
        {0,NULL}
};
static value_string_ext SPTResponseCommand_id_values_ext = VALUE_STRING_EXT_INIT(SPTResponseCommand_id_values);

static const value_string SPTRequestCommand_id_values[] =
{
        {0x00,"InitializeCommunication"},
        {0x30,"SetTimeDate"},
        {0x40,"PerformAction"},
        {0x50,"ReadEEPROM"},                    /* Or general read command ???  Also maps to SP PanelStatus */
        {0x51,"ReadEEPROM"},
        {0x52,"ReadEEPROM"},
        {0x53,"ReadEEPROM"},
        {0x54,"ReadEEPROM"},
        {0x55,"ReadEEPROM"},
        {0x56,"ReadEEPROM"},
        {0x57,"ReadEEPROM"},
        {0x58,"ReadEEPROM"},
        {0x59,"ReadEEPROM"},
        {0x5A,"ReadEEPROM"},
        {0x5B,"ReadEEPROM"},
        {0x5C,"ReadEEPROM"},
        {0x5D,"ReadEEPROM"},
        {0x5E,"ReadEEPROM"},
        {0x5F,"ReadEEPROM"},					/* Handle Command 5F StartCommunication as special case in dissector code */
        {0x70,"CloseConnection"},
        {0x72,"InitiateCommunication"},
        {0xA0,"Broadcast"},
        {0xA1,"Broadcast"},
        {0xA2,"Broadcast"},
        {0xA3,"Broadcast"},
        {0xA4,"Broadcast"},
        {0xA5,"Broadcast"},
        {0xA6,"Broadcast"},
        {0xA7,"Broadcast"},
        {0xA8,"Broadcast"},
        {0xA9,"Broadcast"},
        {0xAA,"Broadcast"},
        {0xAB,"Broadcast"},
        {0xAC,"Broadcast"},
        {0xAD,"Broadcast"},
        {0xAE,"Broadcast"},
        {0xAF,"Broadcast"},
        {0xD0,"PerformZoneAction"},
        {0,NULL}
};
static value_string_ext SPTRequestCommand_id_values_ext = VALUE_STRING_EXT_INIT(SPTRequestCommand_id_values);

static const value_string SPTInitProductID_id_values[] =
{
        {0,"DIGIPLEX_v13"},
        {1,"DIGIPLEX_v2"},
        {2,"DIGIPLEX_NE"},
        {3,"DIGIPLEX_EVO_48"},
        {4,"DIGIPLEX_EVO_96"},
        {5,"DIGIPLEX_EVO_192"},
        {7,"DIGIPLEX_EVO_HD"},
        {21,"SPECTRA_SP5500"},
        {22,"SPECTRA_SP6000"},
        {23,"SPECTRA_SP7000"},
        {26,"SPECTRA_SP4000"},
        {27,"SPECTRA_SP65"},
        {64,"MAGELLAN_MG5000"},
        {65,"MAGELLAN_MG5050"},
        {66,"MAGELLAN_MG5075"},
        {0,NULL}
};
static value_string_ext SPTInitProductID_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitProductID_id_values);


static const value_string SPTInitCommsTalker_id_values[] =
{
        {0,"Bootloader"},
        {1,"Controller Application"},
        {2,"Module Application"},
        {0,NULL}
};
static value_string_ext SPTInitCommsTalker_id_values_ext = VALUE_STRING_EXT_INIT(SPTInitCommsTalker_id_values);


static const value_string SPTSourceID_id_values[] =
{
        {0,"NonValid Source"},
        {1,"Winload Direct"},
        {2,"Winload IP"},
        {3,"Winload GSM"},
        {4,"Winload Dialer"},
        {5,"NeWare Direct"},
        {6,"NeWare IP"},
        {7,"NeWare GSM"},
        {8,"NeWare Dialer"},
        {9,"IP Direct=9,"},
        {10,"VDMP3 Direct"},
        {11,"VDMP3 GSM"},
        {0,NULL}
};
static value_string_ext SPTSourceID_id_values_ext = VALUE_STRING_EXT_INIT(SPTSourceID_id_values);

static const value_string ResultCode_id_values[] =
{
        {0x00,"Requested command failed"},
        {0x01,"Invalid user code"},
        {0x02,"Partition in code lockout"},
        {0x05,"Panel will disconnect"},
        {0x10,"Panel not connected"},
        {0x11,"Panel already connected"},
        {0x12,"Invalid pc password"},
        {0x13,"Winload on phone line"},
        {0x14,"Invalid module address"},
        {0x15,"Cannot write in ram"},
        {0x16,"Upgrade request fail"},
        {0x17,"Record number out of range"},
        {0x19,"Invalid record type"},
        {0x1A,"Multibus not supported"},
        {0x1B,"Incorrect number of users"},
        {0x1C,"Invalid label number"},
        {0,NULL}
};
static value_string_ext ResultCode_id_values_ext = VALUE_STRING_EXT_INIT(ResultCode_id_values);


/**********************************************************************************************/

static int hf_header_tree= -1;
static int hf_serial_tree= -1;
static int hf_payload_unknown= -1;
static int hf_paradoxip_sof= -1;
static int hf_paradoxip_length= -1;
static int hf_paradoxip_msgtype= -1;
static int hf_paradoxip_flags= -1;
static int hf_paradoxip_flags_b8= -1;
static int hf_paradoxip_flags_ka= -1;
static int hf_paradoxip_flags_le= -1;
static int hf_paradoxip_flags_nw= -1;
static int hf_paradoxip_flags_im= -1;
static int hf_paradoxip_flags_b3= -1;
static int hf_paradoxip_flags_ud= -1;
static int hf_paradoxip_flags_cr= -1;
static int hf_paradoxip_command= -1;
static int hf_paradoxip_subcmd= -1;
static int hf_paradoxip_wt= -1;
static int hf_paradoxip_sb= -1;
static int hf_paradoxip_crypttype= -1;
static int hf_paradoxip_unused= -1;
static int hf_paradoxip_seqid= -1;
static int hf_paradoxip_cryptmsg= -1;
static int hf_paradoxip_payload= -1;
static int hf_paradoxip_cmdsummary= -1;
static int hf_ip_con_req_password = -1;
static int hf_ip_con_resp_result= -1;
static int hf_ip_con_resp_sessionkey= -1;
static int hf_ip_con_resp_hwver= -1;
static int hf_ip_con_resp_fwver= -1;
static int hf_ip_con_resp_serialno= -1;
static int hf_ip_con_resp_model= -1;

static int hf_spt_req_cmd= -1;
static int hf_spt_resp_cmd= -1;
static int hf_spt_resp_status= -1;
static int hf_spt_resp_flags_re= -1;
static int hf_spt_resp_flags_ar= -1;
static int hf_spt_resp_flags_wl= -1;
static int hf_spt_resp_flags_ne= -1;

static int hf_spt_checksum= -1;
static int hf_spt_reserved= -1;
static int hf_spt_unknown= -1;
static int hf_spt_newprotocol= -1;
static int hf_spt_protocolid= -1;
static int hf_spt_protcolver= -1;
static int hf_spt_icfamilyid= -1;
static int hf_spt_icproductid= -1;
static int hf_spt_talker= -1;
static int hf_spt_appver= -1;
static int hf_spt_serialno= -1;
static int hf_spt_hwver= -1;
static int hf_spt_bootver= -1;
static int hf_spt_bootdate= -1;
static int hf_spt_cpuid= -1;
static int hf_spt_cryptoid= -1;
static int hf_spt_label= -1;

static int hf_spt_validation= -1;
static int hf_spt_sourceid= -1;
static int hf_spt_userid= -1;
static int hf_spt_fwver= -1;
static int hf_spt_productid = -1;
static int hf_spt_panelid= -1;
static int hf_spt_transceiver= -1;
static int hf_spt_trxfwver= -1;
static int hf_spt_trxfamily= -1;
static int hf_spt_trxnoise= -1;
static int hf_spt_trxstatus= -1;
static int hf_spt_trxflags_nu= -1;
static int hf_spt_trxflags_nh= -1;
static int hf_spt_trxflags_cc= -1;
static int hf_spt_trxhwrev= -1;

static int hf_spt_length= -1;
static int hf_spt_resultcode= -1;
static int hf_spt_moduleaddr= -1;
static int hf_spt_pcpasswd= -1;
static int hf_spt_modemspeed= -1;
static int hf_spt_usercode= -1;
static int hf_spt_systemoptions= -1;
static int hf_spt_carrierlen= -1;

/* Setup list of header fields */
static hf_register_info hf[]=
{
 {&hf_header_tree, {"Header fields","paradoxip.header",FT_NONE,BASE_NONE,NULL,0x0,"IP message header fields",HFILL } },
 {&hf_serial_tree, {"Paradox alarm serial message","paradoxip.serialmessage",FT_NONE,BASE_NONE,NULL,0x0,"Serial passthrough message",HFILL} },
 {&hf_paradoxip_sof, {"Start marker","paradoxip.sof",FT_UINT8,BASE_HEX,NULL,0x0,"Marks the start of an message frame - should always be 0xAA",HFILL} },
 {&hf_paradoxip_length, {"Message length","paradoxip.msglength",FT_UINT16,BASE_DEC,NULL,0x0,"Message payload length",HFILL} },
 {&hf_paradoxip_msgtype, {"Message Type","paradoxip.msgtype",FT_INT8,BASE_DEC|BASE_EXT_STRING,&MessageType_id_values_ext,0x0,NULL,HFILL} },
 {&hf_paradoxip_flags, {"Flags","paradoxip.flags",FT_UINT8,BASE_HEX,NULL,0xFF,"Message flags",HFILL} },
 {&hf_paradoxip_flags_b8, {"bit8","paradoxip.flags.bit8",FT_BOOLEAN,8,NULL,0x80,"Flags bit8 (unknown)",HFILL} },
 {&hf_paradoxip_flags_ka, {"keep_alive","paradoxip.flags.keep_alive",FT_BOOLEAN,8,NULL,0x40,"Flags keep-alive bit",HFILL} },
 {&hf_paradoxip_flags_le, {"live_events","paradoxip.flags.live_events",FT_BOOLEAN,8,NULL,0x20,"Flags live-events bit",HFILL} },
 {&hf_paradoxip_flags_nw, {"neware","paradoxip.flags.neware",FT_BOOLEAN,8,NULL,0x10,"Flags neware bit",HFILL} },
 {&hf_paradoxip_flags_im, {"installer_mode","paradoxip.flags.installer_mode",FT_BOOLEAN,8,NULL,0x08,"Flags installer-mode bit",HFILL} },
 {&hf_paradoxip_flags_b3, {"bit3","paradoxip.flags.bit3",FT_BOOLEAN,8,NULL,0x04,"Flags bit3 (unknown)",HFILL} },
 {&hf_paradoxip_flags_ud, {"upload_download","paradoxip.flags.upload_download",FT_BOOLEAN,8,NULL,0x02,"Flags upload_download bit",HFILL} },
 {&hf_paradoxip_flags_cr, {"encrypted","paradoxip.flags.encrypted",FT_BOOLEAN,8,NULL,0x01,"Flags encrypted bit",HFILL} },

 {&hf_paradoxip_command, {"Command","paradoxip.command",FT_UINT8,BASE_HEX|BASE_EXT_STRING,&Command_id_values_ext,0x0,"Command to be executed",HFILL} },
 /* How do we handle sub-command - different string values based on command... will sort out later */
 {&hf_paradoxip_subcmd, {"Sub-command","paradoxip.subcmd",FT_UINT8,BASE_HEX|BASE_EXT_STRING,&SubCommand_id_values_ext,0x0,"Sub-command - depends on Command",HFILL} },
 {&hf_paradoxip_wt, {"WT","paradoxip.wt",FT_UINT8,BASE_DEC,NULL,0x0,"Header WT (watchdog timer?) field",HFILL} },
 {&hf_paradoxip_sb, {"SB","paradoxip.sb",FT_UINT8,BASE_DEC,NULL,0x0,"Header SB field",HFILL} },
 {&hf_paradoxip_crypttype, {"Encryption Type","paradoxip.crypttype",FT_UINT8,BASE_DEC|BASE_EXT_STRING,&CryptType_id_values_ext,0x0,"Encryption type used for message payload",HFILL} },
 {&hf_paradoxip_unused, {"Unused bytes","paradoxip.unused",FT_BYTES,BASE_NONE,NULL,0x0,"Unused/undefined bytes in message header",HFILL} },
 {&hf_paradoxip_seqid, {"SequenceID","paradoxip.seqid",FT_UINT8,BASE_HEX,NULL,0x0,"Sequence ID for this message",HFILL} },
 {&hf_paradoxip_cryptmsg, {"Encrypted payload bytes","paradoxip.cryptmsg",FT_BYTES,BASE_NONE,NULL,0x0,"Encrypted payload bytes",HFILL} },
 {&hf_paradoxip_payload, {"Payload bytes","paradoxip.payload",FT_BYTES,BASE_NONE,NULL,0x0,"Message payload",HFILL} },
 {&hf_paradoxip_cmdsummary, {"Command","paradoxip.cmdsummary",FT_UINT8,BASE_HEX,NULL,0x0,"Command to execute and direction",HFILL} },

 {&hf_ip_con_req_password, {"Login password","paradoxip.ip.password",FT_STRING,BASE_NONE,NULL,0x0,"Password for logging into IP Module",HFILL} },
 {&hf_ip_con_resp_result, {"Connection result","paradoxip.ip.conresult",FT_UINT8,BASE_DEC|BASE_EXT_STRING,&ConnectResult_id_values_ext,0x0,"Connection result for IP Module connection request",HFILL} },
 {&hf_ip_con_resp_sessionkey, {"Session key","paradoxip.ip.sessionkey",FT_STRING,BASE_NONE,NULL,0x0,"Session key used to encrypt the rest of this IP session",HFILL} },
 {&hf_ip_con_resp_hwver, {"Hardware version","paradoxip.ip.hwver",FT_UINT16,BASE_HEX,NULL,0x0,"IP Module hardware version",HFILL} },
 {&hf_ip_con_resp_fwver, {"Firmware version","paradoxip.ip.fwver",FT_STRING,BASE_NONE,NULL,0x0,"IP Module firmware version",HFILL} },
 {&hf_ip_con_resp_serialno, {"Serial number","paradoxip.ip.serialno",FT_STRING,BASE_NONE,NULL,0x0,"IP Module serial number",HFILL} },
 {&hf_ip_con_resp_model, {"Model","paradoxip.ip.model",FT_UINT8,BASE_DEC|BASE_EXT_STRING,&IPModuleModel_id_values_ext,0x0,"Model number of connected IP module",HFILL} },

 {&hf_spt_req_cmd, {"Request","paradoxip.spt.req_cmd",FT_UINT8,BASE_HEX | BASE_EXT_STRING,&SPTRequestCommand_id_values_ext,0x0,"Serial passthrough response command code",HFILL} },
 {&hf_spt_resp_cmd, {"Response","paradoxip.spt.res_cmd",FT_UINT8,BASE_HEX | BASE_EXT_STRING,&SPTResponseCommand_id_values_ext,0x0,"Serial passthrough request command code",HFILL} },
 {&hf_spt_resp_status, {"Status","paradoxip.spt.status",FT_UINT8,BASE_HEX,NULL,0xFF,"Response message status flags",HFILL} },
 {&hf_spt_resp_flags_re, {"reserved","paradoxip.spt.status.reserved",FT_BOOLEAN,8,NULL,0x08,"Response message status flags reserved bit",HFILL} },
 {&hf_spt_resp_flags_ar, {"alarm_reporting_pending","paradoxip.spt.status.alarmreport",FT_BOOLEAN,8,NULL,0x04,"Response message alarm reporting pending flag",HFILL} },
 {&hf_spt_resp_flags_wl, {"Winload_connected","paradoxip.spt.status.winload",FT_BOOLEAN,8,NULL,0x02,"Response message Winload connected flag",HFILL} },
 {&hf_spt_resp_flags_ne, {"NeWare_connected","paradoxip.spt.status.neware",FT_BOOLEAN,8,NULL,0x01,"Response message NeWare connected flag",HFILL} },

 {&hf_spt_checksum, {"Checksum","paradoxip.spt.checksum",FT_UINT8,BASE_HEX,NULL,0x00,"Checksum for the serial message",HFILL} },
 {&hf_spt_reserved, {"Reserved/padding","paradoxip.spt.reserved",FT_BYTES,BASE_NONE,NULL,0x0,"Reserved / padding bytes",HFILL} },
 {&hf_spt_unknown, {"Unknown","paradoxip.spt.unknown",FT_BYTES,BASE_NONE,NULL,0x0,"Unknown bytes",HFILL} },
 {&hf_spt_newprotocol, {"new_protocol","paradoxip.spt.new_protocol",FT_UINT8,BASE_HEX,NULL,0x00,"Checksum for the serial message",HFILL} },
 {&hf_spt_protocolid, {"Protocol ID","paradoxip.spt.protocolid",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_protcolver, {"Protocol version","paradoxip.spt.protover",FT_STRING,BASE_NONE,NULL,0x0,"Protocol version",HFILL} },
 /* Family and product IDs match standard values from Infield/Hextopuf. Harvest from infield ini file?? ** ONLY WHEN USED IN  InitiateCommunication*/
 {&hf_spt_icfamilyid, {"Family ID","paradoxip.spt.icfamilyid",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_icproductid, {"Product ID","paradoxip.spt.icproductid",FT_UINT8,BASE_HEX | BASE_EXT_STRING,&SPTInitProductID_id_values_ext,0x00,NULL,HFILL} },
 {&hf_spt_talker, {"Talker","paradoxip.spt.talker",FT_UINT8,BASE_HEX | BASE_EXT_STRING,&SPTInitCommsTalker_id_values_ext,0x00,NULL,HFILL} },
 {&hf_spt_appver, {"Application version","paradoxip.spt.appver",FT_STRING,BASE_NONE,NULL,0x0,"Application version",HFILL} },
 {&hf_spt_serialno, {"Serial number","paradoxip.spt.serialno",FT_STRING,BASE_NONE,NULL,0x0,"Serial number",HFILL} },
 {&hf_spt_hwver, {"Hardware version","paradoxip.spt.hwver",FT_STRING,BASE_NONE,NULL,0x0,"Hardware version.revision",HFILL} },
 {&hf_spt_bootver, {"Bootloader version","paradoxip.spt.bootver",FT_STRING,BASE_NONE,NULL,0x0,"Bootloader version",HFILL} },
 {&hf_spt_bootdate, {"Bootloader date","paradoxip.spt.bootdate",FT_STRING,BASE_NONE,NULL,0x0,"Bootloader build data",HFILL} },
 {&hf_spt_cpuid, {"Processor ID","paradoxip.spt.cpuid",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 /* EncryptioID is the same as for PUF files. */
 {&hf_spt_cryptoid, {"Encryption ID","paradoxip.spt.cryptoid",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_label, {"Label","paradoxip.spt.label",FT_STRING,BASE_NONE,NULL,0x0,NULL,HFILL} },
 
 {&hf_spt_validation, {"validation","paradoxip.spt.validation",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_sourceid, {"Source ID","paradoxip.spt.sourceid",FT_UINT8,BASE_HEX| BASE_EXT_STRING,&SPTSourceID_id_values_ext,0x00,NULL,HFILL} },
 {&hf_spt_userid, {"User ID","paradoxip.spt.userid",FT_UINT16,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_fwver, {"Firmware version","paradoxip.spt.fwver",FT_STRING,BASE_NONE,NULL,0x0,"Firmware version",HFILL} },
 {&hf_spt_productid, {"Product ID","paradoxip.spt.productid",FT_UINT8,BASE_HEX | BASE_EXT_STRING,&SPTInitProductID_id_values_ext,0x00,NULL,HFILL} },
 {&hf_spt_panelid, {"Panel ID","paradoxip.spt.panelid",FT_UINT16,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_transceiver, {"Transceiver","paradoxip.spt.transceiver",FT_NONE,BASE_NONE,NULL,0x0,"Transceiver details",HFILL} },
 {&hf_spt_trxfwver, {"Firmware version","paradoxip.spt.trxfwver",FT_STRING,BASE_NONE,NULL,0x0,"Transceiver firmware version",HFILL} },
 {&hf_spt_trxfamily, {"Family","paradoxip.spt.trxfamily",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_trxnoise, {"Noise floor level","paradoxip.spt.trxnoise",FT_UINT8,BASE_DEC,NULL,0x00,NULL,HFILL} },
 {&hf_spt_trxstatus, {"Status","paradoxip.spt.trxstatus",FT_UINT8,BASE_HEX,NULL,0xFF,"Transceiver status flags",HFILL} },
 {&hf_spt_trxflags_nu, {"not used","paradoxip.spt.trxstatus.notused",FT_BOOLEAN,8,NULL,0xFC,NULL,HFILL} },
 {&hf_spt_trxflags_nh, {"noise floor high","paradoxip.spt.trxstatus.noisehigh",FT_BOOLEAN,8,NULL,0x02,NULL,HFILL} },
 {&hf_spt_trxflags_cc, {"constant carrier","paradoxip.spt.trxstatus.constcarrier",FT_BOOLEAN,8,NULL,0x01,NULL,HFILL} },
 {&hf_spt_trxhwrev, {"Hardware revision","paradoxip.spt.trxhwrev",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 
 {&hf_spt_length, {"Length","paradoxip.spt.length",FT_UINT8,BASE_HEX,NULL,0x00,"Serial packet total length",HFILL} },
 {&hf_spt_resultcode, {"Result code","paradoxip.spt.result",FT_UINT8,BASE_HEX| BASE_EXT_STRING,&ResultCode_id_values_ext,0x00,"Result code for the previous request",HFILL} },

 {&hf_spt_moduleaddr, {"Module address","paradoxip.spt.moduleaddr",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_pcpasswd, {"PC password","paradoxip.spt.pcpassword",FT_UINT16,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_modemspeed, {"Modem speed","paradoxip.spt.modemspeed",FT_UINT8,BASE_HEX,NULL,0x00,NULL,HFILL} },
 {&hf_spt_usercode, {"User code","paradoxip.spt.usercode",FT_BYTES,BASE_NONE,NULL,0x00,NULL,HFILL} },
 {&hf_spt_systemoptions, {"System options","paradoxip.spt.systemoptions",FT_BYTES,BASE_NONE,NULL,0x00,NULL,HFILL} },
 {&hf_spt_carrierlen, {"carrier_len","paradoxip.spt.carrier_len",FT_UINT8,BASE_DEC,NULL,0x00,NULL,HFILL} },


 {&hf_payload_unknown, {"Unknown","paradoxip.payloadunknown",FT_BYTES,BASE_NONE,NULL,0x0,"Unknown byte values in message payload",HFILL} }
};

/* Initialize the subtree pointers */
static gint ett_paradoxip= -1;
static gint ett_header= -1;
static gint ett_header_flags= -1;
static gint ett_serialmessage= -1;
static gint ett_spt_responsestatus= -1;
static gint ett_spt_trxdetails= -1;
static gint ett_spt_trxstatus= -1;

/* Setup protocol subtree array */
static gint *ett[]=
{
 &ett_paradoxip,
 &ett_header,
 &ett_header_flags,
 &ett_serialmessage,
 &ett_spt_responsestatus,
 &ett_spt_trxdetails,
 &ett_spt_trxstatus
};

static expert_field ei_decodeerror = EI_INIT;
static expert_field ei_decodewarn = EI_INIT;

/* Setup protocol expert items */
static ei_register_info ei[]=
{
 { &ei_decodeerror, { "packet-paradoxip.expert", PI_UNDECODED, PI_ERROR, "Paradox Alarm IP protocol", EXPFILL }},
 { &ei_decodewarn, { "packet-paradoxip.expert", PI_UNDECODED, PI_WARN, "Paradox Alarm IP protocol", EXPFILL }},
};

/**********************************************************************************************/

typedef struct _savedippwd_t
{
 unsigned char		ipaddr[4];
 unsigned char		password[1];
} savedippwd_t;

typedef struct _conv_info_t
{
 char				correctippwd;
 unsigned char		*sessionkey;
} conv_info_t;

/* Global preferences */
#define PARADOXIP_TCP_PORT 10000
static guint		tcp_default_port= PARADOXIP_TCP_PORT;
static guint		tcp_current_port= 0;
static char			*ip150_default_password= "paradox";
static char			*ip150_password_filename= "";
static gboolean		show_encrypted_bytes= FALSE;
static gboolean		show_payload_bytes= TRUE;
static int			numsavedpwd= 0;
static int			numallocpwd= 0;
static savedippwd_t	**savedpwds= NULL;

/* offsets for message header elements */
#define	PIH_MAGIC		0
#define	PIH_PAYLOADLEN	1
#define	PIH_MSGTYPE		3
#define	PIH_FLAGS		4
#define	PIH_COMMAND		5
#define	PIH_SUBCMD		6
#define	PIH_WT			7
#define	PIH_SB			8
#define	PIH_CRYPTTYPE	9
#define	PIH_UNUSED		10
#define	PIH_SEQID		15			/* Is this location of SeqID byte correct? When is this used? */
#define	PIH_PAYLOAD		16

/* Values for message header flags */
#define	PIH_FLAGS_ENCRYPTED		0x01				/* 'Encrypted' bit in header flags field */

static unsigned char *(MessageTypeName[])=	{"", "IP Resp: ","SerialResp: ","IP Req: ","SerialReq: "};

enum MessageTypeEnum
{
 IPResponse=1,
 SPTResponse=2,
 IPRequest=3,
 SPTRequest=4
};

static unsigned char *(CommandNamesF0[])=	{"Connect ","SendUserLabel ","KeepAlive ","UpDownConnect ","UpDownDisconnect ","BootLoader ","WebPageConnect ","WebPageDisconnect ","ToggleKeepAlive ","Reset ","SetBaudRate ","MultiCommand ","SinglePanel ","UnsupportedRequest ","BootIP ","Disconnect "};

enum CommandsEnum
{
 Passthrough=0,
 Connect= 0xF0,
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

enum SPTResponseEnum
{
 StartCommunicationResp= 0x00,
 LoginConfirmationResp= 0x10,
 SetTimeDateResp= 0x30,
 PerformActionResp= 0x40,
 ReadEEPROMResp= 0x50,
 ErrorMessageResp= 0x70,
 BroadcastResp= 0xA0,
 PerformZoneActionResp= 0xD0,
 EventMessageResp= 0xE0
};

enum SPTRequestEnum
{
 InitializeCommunicationReq= 0x00,
 SetTimeDateReq= 0x30,
 PerformActionReq= 0x40,
 ReadEEPROMReq50= 0x50,
 ReadEEPROMReq51,
 ReadEEPROMReq52,
 ReadEEPROMReq53,
 ReadEEPROMReq54,
 ReadEEPROMReq55,
 ReadEEPROMReq56,
 ReadEEPROMReq57,
 ReadEEPROMReq58,
 ReadEEPROMReq59,
 ReadEEPROMReq5A,
 ReadEEPROMReq5B,
 ReadEEPROMReq5C,
 ReadEEPROMReq5D,
 ReadEEPROMReq5E,
 ReadEEPROMReq5F,
 StartCommunicationReq= 0x5F,
 CloseConnectionReq= 0x70,
 InitiateCommunicationReq= 0x72,
 BroadcastReqA0= 0xA0,
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
 PerformZoneActionReq= 0xD0
};

/* Get the IP module password associated with a given address or return default if no matching address */
unsigned char *getip150password (address *ip150addr)
{
 int			c;
 int			wildcard_idx= -1;
 unsigned char	wildcard_addr[4]= {0,0,0,0};
 
 if (savedpwds&&(ip150addr->type==AT_IPv4))
 {
  for (c=0; c<numsavedpwd; c++)
  {
   if (!memcmp(savedpwds[c]->ipaddr,ip150addr->data,4))
    return savedpwds[c]->password;
   if (!memcmp(savedpwds[c]->ipaddr,wildcard_addr,4))
    wildcard_idx= c;
  }
 
  if (wildcard_idx>=0)
   return savedpwds[wildcard_idx]->password;
 }	 
 return ip150_default_password;
}

int validate_serial_checksum (tvbuff_t *tvb)
{
 guint 			len= tvb_reported_length(tvb);
 const guint8	*p= tvb_get_ptr(tvb,0,len);
 guint8			sum= 0;
 
 if (len<2)
  return 1;

 while (--len)
  sum+= *(p++);

 return *p==sum;	
}

void dissect_spt_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_item *item_ti;
    guint8      command_code;
	guint		msgsize= tvb_reported_length(tvb);

    command_code= tvb_get_guint8(tvb,0);
	
	if ((command_code==StartCommunicationReq) && (msgsize!=8))
	{
	 /* This command code with message size 8 maps to ReadEEPROM */	
     col_append_str(pinfo->cinfo, COL_INFO, "StartCommunication");
     item_ti = proto_tree_add_uint_format(tree, hf_spt_req_cmd, tvb, 0, 1, command_code, "Response: StartCommunication (0x5F)");

     item_ti = proto_tree_add_item(tree, hf_spt_validation, tvb, 1, 1, ENC_LITTLE_ENDIAN);
     item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 2, 31, ENC_NA);
     item_ti = proto_tree_add_item(tree, hf_spt_sourceid, tvb, 33, 1, ENC_LITTLE_ENDIAN);
     item_ti = proto_tree_add_item(tree, hf_spt_userid, tvb, 34, 2, ENC_LITTLE_ENDIAN);
	}
    else
	{
     col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(command_code, &SPTRequestCommand_id_values_ext, "<unknown>%02X"));
     item_ti = proto_tree_add_item(tree, hf_spt_req_cmd, tvb, 0, 1, ENC_UTF_8 | ENC_NA);

 	 switch (command_code)
 	 {
      case InitializeCommunicationReq:
				item_ti = proto_tree_add_item(tree, hf_spt_moduleaddr, tvb, 1, 1, ENC_LITTLE_ENDIAN);
				item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 2,2, ENC_NA);
				item_ti= proto_tree_add_item(tree,hf_spt_productid,tvb,4,1,ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_string(tree,hf_spt_fwver,tvb,5,3,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,5),tvb_get_guint8(tvb,6),tvb_get_guint8(tvb,7))); 
				item_ti= proto_tree_add_item(tree,hf_spt_panelid,tvb,8,2,ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_item(tree,hf_spt_pcpasswd,tvb,10,2,ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_item(tree,hf_spt_modemspeed,tvb,12,1,ENC_LITTLE_ENDIAN);
				item_ti = proto_tree_add_item(tree, hf_spt_sourceid, tvb, 13, 1, ENC_LITTLE_ENDIAN);
				item_ti = proto_tree_add_item(tree, hf_spt_usercode, tvb, 14, 3, ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_string(tree,hf_spt_serialno,tvb,17,4,wmem_strdup_printf(wmem_packet_scope(),"%08X",tvb_get_guint32(tvb,17,ENC_BIG_ENDIAN)));
				item_ti = proto_tree_add_item(tree, hf_spt_systemoptions, tvb, 21, 9, ENC_NA);
				item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 30,4, ENC_NA);
				item_ti = proto_tree_add_item(tree, hf_spt_sourceid, tvb, 34, 1, ENC_LITTLE_ENDIAN);
				item_ti = proto_tree_add_item(tree, hf_spt_carrierlen, tvb, 35, 1, ENC_LITTLE_ENDIAN);
				break;
	  
      case SetTimeDateReq:
      case PerformActionReq:
      case ReadEEPROMReq50:
      case ReadEEPROMReq51:
      case ReadEEPROMReq52:
      case ReadEEPROMReq53:
      case ReadEEPROMReq54:
      case ReadEEPROMReq55:
      case ReadEEPROMReq56:
      case ReadEEPROMReq57:
      case ReadEEPROMReq58:
      case ReadEEPROMReq59:
      case ReadEEPROMReq5A:
      case ReadEEPROMReq5B:
      case ReadEEPROMReq5C:
      case ReadEEPROMReq5D:
      case ReadEEPROMReq5E:
      case ReadEEPROMReq5F:
      case CloseConnectionReq:	/* Size differs between EVO and SP */
				item_ti = proto_tree_add_item(tree, hf_spt_length, tvb, 1, 1, ENC_LITTLE_ENDIAN);
				if (tvb_get_guint8(tvb,1)!=msgsize)
				 expert_add_info_format(pinfo,item_ti,&ei_decodewarn,"Length field does not match actual message size");
				item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 2, msgsize-3, ENC_NA);
				break;
	  
      case InitiateCommunicationReq:
				/* PAI has command as upper nibble, and lower nibble as reserved (2). We treat it as command 0x72 */
                item_ti = proto_tree_add_item(tree, hf_spt_reserved, tvb, 1, 35, ENC_NA);
                break;
				
      case BroadcastReqA0:
      case BroadcastReqA1:
      case BroadcastReqA2:
      case BroadcastReqA3:
      case BroadcastReqA4:
      case BroadcastReqA5:
      case BroadcastReqA6:
      case BroadcastReqA7:
      case BroadcastReqA8:
      case BroadcastReqA9:
      case BroadcastReqAA:
      case BroadcastReqAB:
      case BroadcastReqAC:
      case BroadcastReqAD:
      case BroadcastReqAE:
      case BroadcastReqAF:
      case PerformZoneActionReq:
 		
  	  default:
  		item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 1, msgsize-2, ENC_NA);
  	 	break;
  	 }
	}

    item_ti = proto_tree_add_item(tree, hf_spt_checksum, tvb, msgsize-1, 1, ENC_UTF_8 | ENC_NA);
    if (!validate_serial_checksum (tvb))
     expert_add_info_format(pinfo,item_ti,&ei_decodewarn,"Warning: Incorrect checksum for this message");
}

void dissect_spt_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_item *item_ti;
    proto_tree *field_tree;
    proto_tree *trx_tree;
    guint8      command_code;
    guint8      flags;
	guint		msgsize= tvb_reported_length(tvb);
	char		flags_str[256];

    command_code= tvb_get_guint8(tvb, 0);
	
	if ((command_code==0x10) && (msgsize!=6))
	{
     col_append_str(pinfo->cinfo, COL_INFO, "InitializeCommunication");
     item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_cmd, tvb, 0, 1, command_code & 0xF0,wmem_strdup_printf(wmem_packet_scope(),"Response: InitializeCommunication (0x%02X)",command_code));

	 /* todo: dissect SP_InitializeCommunicationResponse message */
  	 item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 1, msgsize-2, ENC_NA);
	}
	else if (((command_code&0x70)==0x70) && (msgsize==37))
	{
     col_append_str(pinfo->cinfo, COL_INFO, "InitiateCommunication");
     item_ti = proto_tree_add_uint_format(tree, hf_spt_resp_cmd, tvb, 0, 1, command_code & 0xF0,wmem_strdup_printf(wmem_packet_scope(),"Response: InitiateCommunication (0x%02X)",command_code));
     /* PAI has lower nibble of command as "message_centre" - we will just treat is as part of the command. */     
	 /* todo: dissect InitiateCommunicationResponse message */
	 item_ti= proto_tree_add_item(tree,hf_spt_newprotocol,tvb,1,1,ENC_LITTLE_ENDIAN);
	 item_ti= proto_tree_add_item(tree,hf_spt_protocolid,tvb,2,1,ENC_LITTLE_ENDIAN);
  	 item_ti= proto_tree_add_string(tree,hf_spt_protcolver,tvb,3,3,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,3),tvb_get_guint8(tvb,4),tvb_get_guint8(tvb,5))); 

	 
	 item_ti= proto_tree_add_item(tree,hf_spt_icfamilyid,tvb,6,1,ENC_LITTLE_ENDIAN);
	 item_ti= proto_tree_add_item(tree,hf_spt_icproductid,tvb,7,1,ENC_LITTLE_ENDIAN);
	 item_ti= proto_tree_add_item(tree,hf_spt_talker,tvb,8,1,ENC_LITTLE_ENDIAN);
  	 item_ti= proto_tree_add_string(tree,hf_spt_appver,tvb,9,3,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,9),tvb_get_guint8(tvb,10),tvb_get_guint8(tvb,11))); 
 	 item_ti= proto_tree_add_string(tree,hf_spt_serialno,tvb,12,4,wmem_strdup_printf(wmem_packet_scope(),"%08X",tvb_get_guint32(tvb,12,ENC_BIG_ENDIAN)));
	 item_ti= proto_tree_add_string(tree,hf_spt_hwver,tvb,16,2,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X",tvb_get_guint8(tvb,16),tvb_get_guint8(tvb,17))); 
  	 item_ti= proto_tree_add_string(tree,hf_spt_bootver,tvb,18,3,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,18),tvb_get_guint8(tvb,19),tvb_get_guint8(tvb,20))); 
  	 item_ti= proto_tree_add_string(tree,hf_spt_bootdate,tvb,21,3,wmem_strdup_printf(wmem_packet_scope(),"%02X/%02X/%02X",tvb_get_guint8(tvb,23),tvb_get_guint8(tvb,22),tvb_get_guint8(tvb,21))); 
	 item_ti= proto_tree_add_item(tree,hf_spt_cpuid,tvb,24,1,ENC_LITTLE_ENDIAN);
	 item_ti= proto_tree_add_item(tree,hf_spt_cryptoid,tvb,25,1,ENC_LITTLE_ENDIAN);
     item_ti= proto_tree_add_item(tree,hf_spt_unknown,tvb,26,2, ENC_NA);
     item_ti= proto_tree_add_item(tree,hf_spt_label,tvb,28,8,ENC_LITTLE_ENDIAN);

	///     col_append_str(pinfo->cinfo, COL_INFO," Result:");
	///     col_append_str(pinfo->cinfo,COL_INFO, val_to_str_ext(tvb_get_guint8(tvb, 0), &ConnectResult_id_values_ext, "<unknown>%02X"));
	///		col_append_str(pinfo->cinfo,COL_INFO," Session:");
	///		col_append_str(pinfo->cinfo,COL_INFO,tvb_get_string_enc(wmem_packet_scope(),tvb,1,16,ENC_UTF_8|ENC_NA));
	///

	}
	else
	{
     col_append_str(pinfo->cinfo,COL_INFO, val_to_str_ext(command_code & 0xF0, &SPTResponseCommand_id_values_ext, "<unknown>%02X"));
     item_ti = proto_tree_add_uint (tree, hf_spt_resp_cmd, tvb, 0, 1, command_code & 0xF0);
     flags= command_code&0x0F;
     if (!snprintf (flags_str,sizeof(flags_str),"%s%s%s%s",flags&0x08?" reserved":"",flags&0x04?" report_pending":"",flags&0x02?" winload":"",flags&0x01?" neware":""))
      flags_str[1]= 0;
     item_ti = proto_tree_add_uint_format(tree,hf_spt_resp_status,tvb,0,1,flags,"Status flags: 0x%02x (%s)",flags,flags_str+1);
     field_tree = proto_item_add_subtree(item_ti, ett_spt_responsestatus);
     proto_tree_add_boolean(field_tree,hf_spt_resp_flags_re,tvb,0,1,flags);
     proto_tree_add_boolean(field_tree,hf_spt_resp_flags_ar,tvb,0,1,flags);
     proto_tree_add_boolean(field_tree,hf_spt_resp_flags_wl,tvb,0,1,flags);
     proto_tree_add_boolean(field_tree,hf_spt_resp_flags_ne,tvb,0,1,flags);

	 /* todo: dissect general response message */
	 switch (command_code&0xF0)
	 {
      case StartCommunicationResp:
                item_ti= proto_tree_add_item(tree, hf_spt_reserved, tvb, 1, 3, ENC_NA);
				item_ti= proto_tree_add_item(tree,hf_spt_productid,tvb,4,1,ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_string(tree,hf_spt_fwver,tvb,5,3,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,5),tvb_get_guint8(tvb,6),tvb_get_guint8(tvb,7))); 
				item_ti= proto_tree_add_item(tree,hf_spt_panelid,tvb,8,2,ENC_LITTLE_ENDIAN);
                                item_ti = proto_tree_add_item(tree, hf_spt_unknown, tvb, 10, 5, ENC_NA);
                                item_ti= proto_tree_add_item(tree, hf_spt_transceiver, tvb, 15, 7, ENC_NA);
				trx_tree= proto_item_add_subtree(item_ti, ett_spt_trxdetails);
				item_ti= proto_tree_add_string(trx_tree,hf_spt_trxfwver,tvb,15,4,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X.%d",tvb_get_guint8(tvb,17),tvb_get_guint8(tvb,18),tvb_get_guint8(tvb,15))); 
				item_ti= proto_tree_add_item(trx_tree,hf_spt_trxfamily,tvb,16,1,ENC_LITTLE_ENDIAN);
				item_ti= proto_tree_add_item(trx_tree,hf_spt_trxnoise,tvb,19,1,ENC_LITTLE_ENDIAN);

        			flags= tvb_get_guint8(tvb,20);
			        if (!snprintf (flags_str,sizeof(flags_str),"%s%s%s",flags&0xFC?" not_used":"",flags&0x02?" high_noise":"",flags&0x01?" constant_carrier":""))
                     flags_str[1]= 0;
			        item_ti = proto_tree_add_uint_format(trx_tree,hf_spt_trxstatus,tvb,20,1,flags,"Status flags: 0x%02x (%s)",flags,flags_str+1);
			        field_tree = proto_item_add_subtree(item_ti, ett_spt_trxstatus);
			        proto_tree_add_boolean(field_tree,hf_spt_trxflags_nu,tvb,20,1,flags);
			        proto_tree_add_boolean(field_tree,hf_spt_trxflags_nh,tvb,20,1,flags);
			        proto_tree_add_boolean(field_tree,hf_spt_trxflags_cc,tvb,20,1,flags);
				item_ti= proto_tree_add_item(trx_tree,hf_spt_trxhwrev,tvb,21,1,ENC_LITTLE_ENDIAN);
                                item_ti= proto_tree_add_item(tree, hf_spt_unknown, tvb, 22, 14, ENC_NA);
                break;
	  
      case LoginConfirmationResp:
      case SetTimeDateResp:
      case PerformActionResp:
      case ReadEEPROMResp:
  		item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 1, msgsize-2, ENC_NA);
  	 	break;
      case ErrorMessageResp:
				/* Length field might not be valid for SP 37 byte message?? */
				item_ti = proto_tree_add_item(tree, hf_spt_length, tvb, 1, 1, ENC_LITTLE_ENDIAN);
				if (tvb_get_guint8(tvb,1)!=msgsize)
				 expert_add_info_format(pinfo,item_ti,&ei_decodewarn,"Length field does not match actual message size");
				item_ti = proto_tree_add_item(tree, hf_spt_resultcode, tvb, 2, 1, ENC_LITTLE_ENDIAN);
				if (msgsize>4)
				 item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 4, msgsize-4, ENC_NA);
				break;
      case BroadcastResp:
      case PerformZoneActionResp:
      case EventMessageResp:
      default: 
  		item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 1, msgsize-2, ENC_NA);
  	 	break;
	 }
    }
    item_ti = proto_tree_add_item(tree, hf_spt_checksum, tvb, msgsize-1, 1, ENC_LITTLE_ENDIAN);
	if (!validate_serial_checksum (tvb))
     expert_add_info_format(pinfo,item_ti,&ei_decodewarn,"Warning: Incorrect checksum for this message");
}

void dissect_ip_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int command)
{
    proto_item* item_ti;

    switch (command)
    {
    case Connect:
                item_ti = proto_tree_add_item(tree, hf_ip_con_req_password, tvb, 0,-1, ENC_UTF_8 | ENC_NA);
				col_append_str(pinfo->cinfo,COL_INFO," Password:");
				col_append_str(pinfo->cinfo,COL_INFO,tvb_get_string_enc(wmem_packet_scope(),tvb,0,tvb_reported_length(tvb),ENC_UTF_8|ENC_NA));
                break;
	default:	item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 0,-1, ENC_NA);
                break;
    }
}

void dissect_ip_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int command)
{
 proto_item 	*item_ti;
 
 switch (command)
 {
  case Connect:
			item_ti= proto_tree_add_item(tree,hf_ip_con_resp_result,tvb,0,1,ENC_LITTLE_ENDIAN);
			item_ti= proto_tree_add_item(tree,hf_ip_con_resp_sessionkey,tvb,1,16,ENC_UTF_8|ENC_NA); 
                        item_ti= proto_tree_add_item(tree,hf_ip_con_resp_hwver,tvb,17,2,ENC_LITTLE_ENDIAN);
			item_ti= proto_tree_add_string(tree,hf_ip_con_resp_fwver,tvb,19,2,wmem_strdup_printf(wmem_packet_scope(),"%X.%02X",tvb_get_guint8(tvb,19),tvb_get_guint8(tvb,20))); 
			item_ti= proto_tree_add_string(tree,hf_ip_con_resp_serialno,tvb,21,4,wmem_strdup_printf(wmem_packet_scope(),"%08X",tvb_get_guint32(tvb,21,ENC_BIG_ENDIAN)));
			/* Following item not present in tested IP150 data... maybe later models? */
			/* item_ti= proto_tree_add_item(tree,hf_ip_con_resp_model,tvb,25,1,ENC_LITTLE_ENDIAN); */
			
                        col_append_str(pinfo->cinfo, COL_INFO," Result:");
                        col_append_str(pinfo->cinfo,COL_INFO, val_to_str_ext(tvb_get_guint8(tvb, 0), &ConnectResult_id_values_ext, "<unknown>%02X"));
			col_append_str(pinfo->cinfo,COL_INFO," Session:");
			col_append_str(pinfo->cinfo,COL_INFO,tvb_get_string_enc(wmem_packet_scope(),tvb,1,16,ENC_UTF_8|ENC_NA));
			
                        break;
	default:			item_ti = proto_tree_add_item(tree, hf_payload_unknown, tvb, 0,-1, ENC_NA);
                        break;
 }
}

/* Code to actually dissect the packets */
static int dissect_paradoxip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
 proto_item		*protocol_ti;
 proto_item		*serial_ti;
 proto_item             *header_ti;
 proto_item      	*item_ti;
 proto_tree		*encbytes_ti;
 proto_tree		*paradoxip_tree;
 proto_tree             *header_tree;
 proto_tree		*serial_tree;
 proto_tree		*field_tree;
 tvbuff_t 		*next_tvb;
 conversation_t          *conversation;
 conv_info_t	        *conv_info;
 
 int			flags;
 char			flags_str[256];
 int			payload_length;
 int			msgtype;
 int			command;
 int			subcmd;
 unsigned char  	*decryptkey;
 unsigned char      *msgtype_desc;
 unsigned char		*command_name;
 unsigned char		*direction_name;
 
 
 payload_length= tvb_get_guint16(tvb,PIH_PAYLOADLEN,ENC_LITTLE_ENDIAN);
 msgtype= tvb_get_guint8(tvb,PIH_MSGTYPE);
 flags= tvb_get_guint8(tvb,PIH_FLAGS);
 command= tvb_get_guint8(tvb,PIH_COMMAND);
 subcmd= tvb_get_guint8(tvb,PIH_SUBCMD);

 /* Set the Protocol column to the constant string of rmcluster */
 col_set_str(pinfo->cinfo,COL_PROTOCOL,"paradoxip");

 switch (msgtype)
 {
 case IPRequest: msgtype_desc = "IP<- ";
				 direction_name= "request";
                 break;
 case IPResponse: msgtype_desc = "IP-> ";
				 direction_name= "response";
				 break;
 case SPTRequest: msgtype_desc = "Serial<- ";
				  direction_name= "request";
				  break;
 case SPTResponse: msgtype_desc = "Serial-> ";
				 direction_name= "response";
				 break;
 default:  msgtype_desc = wmem_strdup_printf(wmem_packet_scope(), "<msgtype %02X>: ", msgtype);
				 direction_name= "";
				 break;
 }
 col_add_str(pinfo->cinfo,COL_INFO,msgtype_desc);

 if (command == Passthrough)
 {
     command_name = "Serial passthrough ";
  /* Don't explicitly add this to summary */
  /* col_append_str(pinfo->cinfo,COL_INFO,command_name); */
 }
 else if ((command >= 0xF0) && ((command - 0xF0) < (sizeof(CommandNamesF0) / sizeof(*CommandNamesF0))))
 {
  command_name= CommandNamesF0[command - 0xF0];
  col_append_str(pinfo->cinfo, COL_INFO,command_name);
 }
 else
 {
  command_name= wmem_strdup_printf(wmem_packet_scope(), "<command %02X> ", command);
  col_append_str(pinfo->cinfo, COL_INFO,command_name);
 }
 /* Don't add the sub-command - not really usefull in the end */
 /* col_append_str(pinfo->cinfo,COL_INFO,wmem_strdup_printf (wmem_packet_scope(),"<sub %02X> ",subcmd)); */

 /* create display subtree for the protocol */
 protocol_ti = proto_tree_add_item(tree, proto_paradoxip, tvb, 0, -1, ENC_NA);
 paradoxip_tree = proto_item_add_subtree(protocol_ti, ett_paradoxip);
 /* And create another subtree for header fields */
 header_ti = proto_tree_add_item(paradoxip_tree, hf_header_tree, tvb, 0,16, ENC_NA);
 header_tree = proto_item_add_subtree(header_ti, ett_header);

 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_sof,tvb,PIH_MAGIC,1,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_length,tvb,PIH_PAYLOADLEN,2,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_msgtype,tvb,PIH_MSGTYPE,1,ENC_LITTLE_ENDIAN);
 
 if (!snprintf (flags_str,sizeof(flags_str),"%s%s%s%s%s%s%s%s",flags&0x80?" bit8":"",flags&0x40?" keep_alive":"",flags&0x20?" live_events":"",flags&0x10?" neware":"",
			flags&0x08?" installer_mode":"",flags&0x04?" bit3":"",flags&0x02?" upload_download":"",flags&0x01?" encrypted":""))
  flags_str[1]= 0;
 item_ti = proto_tree_add_uint_format(header_tree,hf_paradoxip_flags,tvb,PIH_FLAGS,1,flags,"Flags: 0x%02x (%s)",flags,flags_str+1);
 field_tree = proto_item_add_subtree(item_ti, ett_header_flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_b8,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_ka,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_le,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_nw,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_im,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_b3,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_ud,tvb,PIH_FLAGS,1,flags);
 proto_tree_add_boolean(field_tree,hf_paradoxip_flags_cr,tvb,PIH_FLAGS,1,flags);

 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_command,tvb,PIH_COMMAND,1,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_subcmd,tvb,PIH_SUBCMD,1,ENC_LITTLE_ENDIAN);  /* May have to different sub-command HF's based on Command value */
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_wt,tvb,PIH_WT,1,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_sb,tvb,PIH_SB,1,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_crypttype,tvb,PIH_CRYPTTYPE,1,ENC_LITTLE_ENDIAN);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_unused,tvb,PIH_UNUSED,PIH_SEQID-PIH_UNUSED,0);
 item_ti = proto_tree_add_item(header_tree,hf_paradoxip_seqid,tvb,PIH_SEQID,1,ENC_LITTLE_ENDIAN);

 /* Get pointer to conversation info, create new conversation info if not allocated yet */
 conversation= find_or_create_conversation(pinfo);
 conv_info= conversation_get_proto_data(conversation,proto_paradoxip);
 if (!conv_info)
 {
  conv_info= wmem_new(wmem_file_scope(),conv_info_t);
  memset (conv_info,0,sizeof(*conv_info));
  conversation_add_proto_data(conversation,proto_paradoxip,conv_info);
 }

 item_ti = proto_tree_add_uint_format(paradoxip_tree, hf_paradoxip_cmdsummary, tvb, PIH_COMMAND, 1, command, "Command: %s%s", command_name, direction_name);

 /* Nothing more to do if there is no payload data */
 if (payload_length <= 0)
     return tvb_reported_length(tvb);

 /* Decrypt encrypted payload data - seems all payload will be encrypted */
 if (flags&PIH_FLAGS_ENCRYPTED)							/* Encrypted payload */
 {
  size_t			cryptsize= (payload_length+15)&0xFFF0;
  guchar 			*decrypted_buffer= (guchar*)wmem_alloc(pinfo->pool,cryptsize);

  /* Determine the key used for the encryption */
  if ((command==Connect)&&(msgtype==IPRequest))
   decryptkey= getip150password(&pinfo->dst);
  else if ((command==Connect)&&(msgtype==IPResponse))
   decryptkey= conv_info->correctippwd?getip150password(&pinfo->src):NULL;
  else
  {
   /* todo: update to allow multiple Connect operations in one conversation, each with own session key?? */
   decryptkey= conv_info->sessionkey;
  }
  
  encbytes_ti= protocol_ti;
  if (show_encrypted_bytes)
   encbytes_ti = proto_tree_add_item(paradoxip_tree,hf_paradoxip_cryptmsg,tvb,PIH_PAYLOAD,-1,0);			
  if (!decryptkey)
  {
   expert_add_info_format(pinfo,encbytes_ti,&ei_decodewarn,"Warning: no decryption key found for this login session - cannot decrypt payload data [IP connect response not seen or wrong password]");
   return tvb_reported_length(tvb);
  }
  
  decrypt_pdx_aex (tvb_get_ptr(tvb,PIH_PAYLOAD,-1),decrypted_buffer,cryptsize,decryptkey,strlen(decryptkey));

  /* Now re-setup the tvb buffer to have the new data */
  next_tvb= tvb_new_child_real_data(tvb,decrypted_buffer,payload_length,payload_length);
  add_new_data_source(pinfo,next_tvb,"Decryped payload");
  
  /* Verify that we have the proper password for this IP150 module */
  if ((msgtype==IPRequest)&&(command==Connect))
  {
   if (strncmp(decryptkey,decrypted_buffer,payload_length))
   {
    expert_add_info_format(pinfo,encbytes_ti,&ei_decodewarn,"Warning: incorrect IP module password supplied - cannot decrypt payload data [IP connect request password mismatch]");
    return tvb_reported_length(tvb);
   }
   conv_info->correctippwd= 1;
  }
   
  /* Save session key contained in the IP150 login response.  */
  /* todo: update to allow multiple Connect operations in one conversation, each with own session key?? */
  if ((PINFO_FD_VISITED(pinfo)==FALSE)&&(msgtype==IPResponse)&&(command==Connect)&&conv_info->correctippwd)
   conv_info->sessionkey= wmem_strndup(wmem_file_scope(),decrypted_buffer+1,16);
 }
 else
 {
  next_tvb= tvb_new_subset_remaining(tvb,PIH_PAYLOAD);
 }

 if (show_payload_bytes)
  item_ti = proto_tree_add_item(paradoxip_tree,hf_paradoxip_payload,next_tvb,0,-1,0);			
 
 if (msgtype == IPRequest)
 {
     dissect_ip_request(next_tvb, pinfo, paradoxip_tree, command);
 }
 else if (msgtype == IPResponse)
 {
     dissect_ip_response(next_tvb,pinfo, paradoxip_tree,command);
 }
 else if (((msgtype == SPTRequest)||(msgtype == SPTResponse)) && (command == Passthrough))
     {
         /* Create a new tree for the serial message data */
         serial_ti = proto_tree_add_item(tree, hf_serial_tree, next_tvb, 0, -1, ENC_NA);
         serial_tree = proto_item_add_subtree(serial_ti, ett_serialmessage);
         if (msgtype == SPTRequest)
             dissect_spt_request(next_tvb, pinfo, serial_tree);
         else
             dissect_spt_response(next_tvb, pinfo, serial_tree);
     }
     else
 {
  item_ti = proto_tree_add_item(paradoxip_tree, hf_payload_unknown, next_tvb, 0, -1, ENC_NA);
 }
 
 return tvb_reported_length(tvb);
}

/* Handle splittings and reassembly of packets to make sure there is exactly one message in a tvb */
static int dissect_paradoxip_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
 tvbuff_t	*next_tvb;
 int		msglen;
 guint		offset= 0;
 int		message_count= 0;

 /* Keep processing Paradox IP messages until we run out of bytes in the buffer */
 while (tvb_reported_length_remaining(tvb,offset)>=PIH_PAYLOAD)	/* Big enough to hold length field. Take that as minimum for now */
 {
  if (tvb_get_guint8(tvb,offset+PIH_MAGIC)!=0xAA)
   return offset;										/* Message should start with 0xAA - else not a valid message */
  /* todo: add any other heuristics checks here to validate message protocol */
  msglen= PIH_PAYLOAD + tvb_get_guint16(tvb,offset+PIH_PAYLOADLEN,ENC_LITTLE_ENDIAN);
  if (tvb_get_guint8(tvb,offset+PIH_FLAGS)&PIH_FLAGS_ENCRYPTED)	/* Encrypted flag set - round up payload to 16 byte multiple */
   msglen= (msglen+15)&0xFFF0;
  if (msglen>tvb_reported_length_remaining(tvb,offset))
   break;												/* Not enough data to fill another message */

  if (message_count++)
  {
   col_append_str(pinfo->cinfo,COL_INFO," | ");
   col_set_fence(pinfo->cinfo,COL_INFO);
  }
   
  /* Set up tvb and call the message dissector code  */
  next_tvb= tvb_new_subset_length(tvb,offset,msglen);
  offset+= msglen;	/* skip to start of next message */
  dissect_paradoxip (next_tvb,pinfo,tree,data);
 }
  
 /* If no more bytes remaining we are done */
 if (!tvb_reported_length_remaining(tvb,offset))
  return offset;

 /* If we fall out to here we don't have enough data in tvb do complete a PDU (message). */
 /* Ask wireshark to give us one more data segment.                                      */ 
 pinfo->desegment_offset = offset;
 pinfo->desegment_len= DESEGMENT_ONE_MORE_SEGMENT;
 return -1;
}

static void ApplyPreferences (void)
{
 FILE			*pwdfile= NULL;;
 char			line[256];
 char			*pos;
 char			*password;
 unsigned long	tempval;
 unsigned char	ipaddr[4];
 void			*tempmem;
 savedippwd_t	*newpwdrec;
 
 if (tcp_current_port!=tcp_default_port)
 {
  if (tcp_current_port)
   dissector_delete_uint("tcp.port",tcp_current_port,paradoxip_handle);
  if (tcp_default_port)
   dissector_add_uint("tcp.port",tcp_default_port,paradoxip_handle);
  tcp_current_port= tcp_default_port;
 }

 /* Clear out saved IP module passwords. Free saved paswords and reset savedd count back to zero. Keep allocated array  */
 if (savedpwds)
  while (numsavedpwd>0)
   free (savedpwds[--numsavedpwd]);

 /* We re-read the IP150 password file regardless whether it changed or not. How do we indicate read errors? */
 if (ip150_password_filename&&(*ip150_password_filename))
  pwdfile= fopen(ip150_password_filename,"r");
 if (pwdfile)
 {
  /* read lines from the password file */
  while (fgets(line,sizeof(line),pwdfile))
  {
   /* skip anything that does not start with a digit */
   if ((line[0]<'0')||(line[0]>'9'))
	continue;
   /* Read IP address octets */
   tempval= strtoul(line,&pos,10);
   if ((tempval>255)||(*pos!='.'))
	continue;
   ipaddr[0]= (unsigned char) tempval;
   tempval= strtoul(pos+1,&pos,10);
   if ((tempval>255)||(*pos!='.'))
	continue;
   ipaddr[1]= (unsigned char)tempval;
   tempval= strtoul(pos+1,&pos,10);
   if ((tempval>255)||(*pos!='.'))
	continue;
   ipaddr[2]= (unsigned char)tempval;
   tempval= strtoul(pos+1,&pos,10);
   if ((tempval>255)||((*pos!=' ')&&(*pos!='\t')))
	continue;
   ipaddr[3]= (unsigned char)tempval;
   /* skip whitespace after IP address */
   while ((*pos==' ')||(*pos=='\t'))
	pos++;
   password= pos;
   /* scan for end of password */
   while ((*pos)&&(*pos!=' ')&&(*pos!='\t')&&(*pos!='\r')&&(*pos!='\n'))
	pos++;
   *pos= 0;
   if (!(*password))
	continue;
   /* OK, we have found a valid IP address and non-blank password. Add it to the password list */
   if (numallocpwd==numsavedpwd)
   {
	numallocpwd+= 10;
	tempmem= realloc(savedpwds,numallocpwd*sizeof(*savedpwds));
	if (!tempmem)
	 continue;
    savedpwds= (savedippwd_t**) tempmem;
   }
   newpwdrec= (savedippwd_t*) malloc(sizeof(*newpwdrec)+strlen(password));
   if (!newpwdrec)
	continue;
   memcpy (newpwdrec->ipaddr,ipaddr,4);
   strcpy (newpwdrec->password,password);
   savedpwds[numsavedpwd++]= newpwdrec;
  }
  fclose(pwdfile);
 }
}

void proto_reg_handoff_paradoxip(void)
{
 paradoxip_handle= create_dissector_handle(dissect_paradoxip_packet,proto_paradoxip);
 if (tcp_default_port)
 {
  dissector_add_uint("tcp.port",tcp_default_port,paradoxip_handle);
  tcp_current_port= tcp_default_port;
 }
}

/* Register the protocol with Wireshark. */
void proto_register_paradoxip(void)
{
 module_t			*paradoxip_module;
 expert_module_t	*expert_paradoxip;

 /* Register the protocol name and description */
 proto_paradoxip = proto_register_protocol("Paradox Alarm IP message","ParadoxAlarm", "paradoxip");

 /* Required function calls to register the header fields and subtrees */
 proto_register_field_array(proto_paradoxip,hf,array_length(hf));
 proto_register_subtree_array(ett,array_length(ett));

 /* Required function calls to register expert items */
 expert_paradoxip= expert_register_protocol(proto_paradoxip);
 expert_register_field_array(expert_paradoxip,ei,array_length(ei));

 /* Register a preferences module */
 paradoxip_module= prefs_register_protocol(proto_paradoxip,ApplyPreferences);
 prefs_register_uint_preference(paradoxip_module,"tcp.port","Default TCP port","Set the default TCP port for Paradox alarm IP messages",10, &tcp_default_port);
 prefs_register_bool_preference(paradoxip_module,"show_encrypted","Show encrypted payload bytes","Add an item for encrypted payload bytes in the protocol view",&show_encrypted_bytes);
 prefs_register_bool_preference(paradoxip_module,"show_payload","Show message payload bytes","Add an item for decrypted (or never encrypted) payload bytes in the protocol view",&show_payload_bytes);
 prefs_register_string_preference(paradoxip_module,"ip150_password","Default IP150 module password","Default IP150 password to use if no matches are found in the password file",&ip150_default_password);
 prefs_register_filename_preference(paradoxip_module,"password_file","IP150 passwords file","File with individual IP150 module IP addresses and passwords",&ip150_password_filename,FALSE);
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
