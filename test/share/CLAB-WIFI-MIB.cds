�--****************************************************************************
--
-- Copyright (c) 2012-2014 Broadcom Corporation
--
-- This program is the proprietary software of Broadcom Corporation and/or
-- its licensors, and may only be used, duplicated, modified or distributed
-- pursuant to the terms and conditions of a separate, written license
-- agreement executed between you and Broadcom (an "Authorized License").
-- Except as set forth in an Authorized License, Broadcom grants no license
-- (express or implied), right to use, or waiver of any kind with respect to
-- the Software, and Broadcom expressly reserves all rights in and to the
-- Software and all intellectual property rights therein.  IF YOU HAVE NO
-- AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY,
-- AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE
-- SOFTWARE.  
--
-- Except as expressly set forth in the Authorized License,
--
-- 1.     This program, including its structure, sequence and organization,
-- constitutes the valuable trade secrets of Broadcom, and you shall use all
-- reasonable efforts to protect the confidentiality thereof, and to use this
-- information only in connection with your use of Broadcom integrated circuit
-- products.
--
-- 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED
-- "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS
-- OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
-- RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND ALL
-- IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR
-- A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
-- ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. YOU ASSUME
-- THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
--
-- 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM
-- OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
-- INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY
-- RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM
-- HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN
-- EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1,
-- WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY
-- FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.
--
--****************************************************************************
--    Filename: CLAB-WIFI-MIB.mib
--    Creation Date: March 11, 2014
--
--**************************************************************************
--    Description:
--
--		Cable Lab WIFI MIB for runtime (not factory) management of 
--      802.11 (Wi-Fi) settings.
--		
--**************************************************************************
--    Revision History:
--
--**************************************************************************
   �"This data type represents a packet error rate in
                 units of 10^-5 or a resolution of 0.000000001
                 precision."                                                                                     �"This MIB module contains the management objects
             for the Wi-Fi interface.

             Copyright 1999-2014 Cable Television Laboratories, Inc.
             All rights reserved." �"Broadband Network Services
             Cable Television Laboratories, Inc.
             858 Coal Creek Circle,
             Louisville, CO 80027, USA
             Phone: +1 303-661-9100
             Email: mibs@cablelabs.com" "201403110000Z" "201201030000Z" "201009270000Z" "201007290000Z" �"Revised Version includes ECN
             WiFi-MGMT-N-14.xxyyzz
             and published as part of WR-SP-WiFi-MGMT-I04-YYMMDD" �"Revised Version includes ECN
             WiFi-MGMT-N-11.0006-5
             and published as part of WR-SP-WiFi-MGMT-I03-120216" �"Revised Version includes ECN
             WiFi-MGMT-N-11.0002-4
             and published as part of WR-SP-WiFi-MGMT-I02-101006" �"Initial version, published as part of the CableLabs
             Wi-Fi Provisioning Framework Specification
             WR-SP-WiFi-MGMT-I01-100729
             Copyright 2010 Cable Television Laboratories, Inc.
             All rights reserved."       -- March 11, 2014
           3"This object represents the Wi-Fi GW notification."                     ;"This attribute represents the Event Message of the event."                       "The identifier of the event"                       c"Date and Time when the event was generated. (not the time when
        the event was dispatched)."                               D"This object is defined in TR-181 Device.WiFi.RadioNumberOfEntries." &"TR-181 Device Data Model for TR-069."                     C"This object is defined in TR-181 Device.WiFi.SSIDNumberOfEntries." &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.AccessPointNumberOfEntries." &"TR-181 Device Data Model for TR-069."                     G"This object is defined in TR-181 Device.WiFi.EndPointNumberOfEntries." &"TR-181 Device Data Model for TR-069."                     4"This object is defined in TR-181 Device.WiFi.Radio" &"TR-181 Device Data Model for TR-069."                     +"The Conceptual row of clabWIFIRadioTable."                       �"The key for a unique instance of this object.
        This value corresponds to the Interface Index
        (i.e., ifIndex in SMIv2). "                       ?"This object is defined in TR-181 Device.WiFi.Radio.{i}.Enable" &"TR-181 Device Data Model for TR-069."                     @"This object is defined in TR-181 Device.WiFi.Radio.{i}.Status." &"TR-181 Device Data Model for TR-069."                     ?"This object is defined in TR-181 Device.WiFi.Radio.{i}.Alias." &"TR-181 Device Data Model for TR-069."                     >"This object is defined in TR-181 Device.WiFi.Radio.{i}.Name." &"TR-181 Device Data Model for TR-069."                     D"This object is defined in TR-181 Device.WiFi.Radio.{i}.LastChange." &"TR-181 Device Data Model for TR-069."                     E"This object is defined in TR-181 Device.WiFi.Radio.{i}.LowerLayers." &"TR-181 Device Data Model for TR-069."                     A"This object is defined in TR-181 Device.WiFi.Radio.{i}.Upstream" &"TR-181 Device Data Model for TR-069."                     D"This object is defined in TR-181 Device.WiFi.Radio.{i}.MaxBitRate." &"TR-181 Device Data Model for TR-069."                     L"This object is defined in TR-181 Device.WiFi.RadioSupportedFrequencyBands." &"TR-181 Device Data Model for TR-069."                     O"This object is defined in TR-181 Device.WiFi.Radio.{i}.OperatingFrequencyBand" &"TR-181 Device Data Model for TR-069."                     K"This object is defined in TR-181 Device.WiFi.Radio.{i}.SupportedStandards" &"TR-181 Device Data Model for TR-069."                     N"This object is modified from TR-181 Device.WiFi.Radio.{i}.OperatingStandards" &"TR-181 Device Data Model for TR-069."                     I"This object is defined in TR-181 Device.WiFi.Radio.{i}.PossibleChannels" &"TR-181 Device Data Model for TR-069."                     F"This object is defined in TR-181 Device.WiFi.Radio.{i}.ChannelsInUse" &"TR-181 Device Data Model for TR-069."                     �"This object is defined in TR-181 Device.WiFi.Radio.{i}.Channel.
         For 80MHz, 160MHz and 80+80MHz RF channels of 802.11ac, this
         object indicates the Primary Channel of the RF channel." &"TR-181 Device Data Model for TR-069."                     M"This object is defined in TR-181 Device.WiFi.Radio.{i}.AutoChannelSupported" &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.Radio.{i}.AutoChannelEnable" &"TR-181 Device Data Model for TR-069."                     Q"This object is defined in TR-181 Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod" &"TR-181 Device Data Model for TR-069."                     U"This object is modified from TR-181 Device.WiFi.Radio.{i}.OperatingChannelBandwidth" &"TR-181 Device Data Model for TR-069."                     I"This object is defined in TR-181 Device.WiFi.Radio.{i}.ExtensionChannel" &"TR-181 Device Data Model for TR-069."                     K"This object is defined in TR-181 Device.WiFi.Radio.{i}.RadioGuardInterval" &"TR-181 Device Data Model for TR-069."                     B"This object is defined in TR-181 Device.WiFi.Radio.{i}.RadioMCS " &"TR-181 Device Data Model for TR-069."                     O"This object is defined in TR-181 Device.WiFi.Radio.{i}.TransmitPowerSupported" &"TR-181 Device Data Model for TR-069."                     F"This object is defined in TR-181 Device.WiFi.Radio.{i}.TransmitPower" &"TR-181 Device Data Model for TR-069."                     L"This object is defined in TR-181 Device.WiFi.Radio.{i}.IEEE80211hSupported" &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.Radio.{i}.IEEE80211hEnabled" &"TR-181 Device Data Model for TR-069."                     I"This object is defined in TR-181 Device.WiFi.Radio.{i}.RegulatoryDomain" &"TR-181 Device Data Model for TR-069."                     �"This object is defined for the Noncontiguous 80+80Mhz channels
         only. It indicates the center of the second 80Mhz subchannel." "IEEE 802.11ac standard."                    "This object is the RSSI signal level at which CS/CCA detects a
         busy condition. This attribute enables APs to increase minimum
         sensitivity to avoid detecting busy condition from
         multiple/weak Wi-Fi sources in dense Wi-Fi environments."                       Q"This object indicates the Carrier Sense ranges supported by
         the radio."                       �"This object indicates the fraction of the time AP senses a busy
         channel or transmits frames. This object provides visibility
         into channel capacity."                       8"This object allows configuring the RTS/CTS parameters."                       �"This object allows configuring the frame aggregation level
         depending on how dense the network is. For example, if the
         network is not congested, then a large number of frames can
         be aggregated and sent."                       9"This object indicates the throughput expressed in Mbps."                       Q"This object indicates the traffic quality (e.g., HTTP, TCP)
         of an STA."                       ?"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats." &"TR-181 Device Data Model for TR-069."                     0"The Conceptual row of clabWIFIRadioStatsTable." "TR-181 Issue 2"                     I"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.BytesSent." &"TR-181 Device Data Model for TR-069."                     M"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.BytesReceived." &"TR-181 Device Data Model for TR-069."                     K"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.PacketsSent." &"TR-181 Device Data Model for TR-069."                     O"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.PacketsReceived." &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.ErrorsSent." &"TR-181 Device Data Model for TR-069."                     N"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.ErrorsReceived." &"TR-181 Device Data Model for TR-069."                     R"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent." &"TR-181 Device Data Model for TR-069."                     V"This object is defined in TR-181 Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived." &"TR-181 Device Data Model for TR-069."                     7"This object is defined in TR-181 Device.WiFi.SSID{i}." &"TR-181 Device Data Model for TR-069."                     *"The Conceptual row of clabWIFISSIDTable."                       �"The key for a unique instance of this object.
        This value corresponds to the Interface Index
        (i.e., ifIndex in SMIv2). "                       >"This object is defined in TR-181 Device.WiFi.SSID{i}.Enable." &"TR-181 Device Data Model for TR-069."                     >"This object is defined in TR-181 Device.WiFi.SSID{i}.Status." &"TR-181 Device Data Model for TR-069."                     ="This object is defined in TR-181 Device.WiFi.SSID{i}.Alias." &"TR-181 Device Data Model for TR-069."                     <"This object is defined in TR-181 Device.WiFi.SSID{i}.Name." &"TR-181 Device Data Model for TR-069."                     B"This object is defined in TR-181 Device.WiFi.SSID{i}.LastChange." &"TR-181 Device Data Model for TR-069."                     C"This object is defined in TR-181 Device.WiFi.SSID{i}.LowerLayers." &"TR-181 Device Data Model for TR-069."                     ="This object is defined in TR-181 Device.WiFi.SSID{i}.BSSID." &"TR-181 Device Data Model for TR-069."                     B"This object is defined in TR-181 Device.WiFi.SSID{i}.MACAddress." &"TR-181 Device Data Model for TR-069."                     <"This object is defined in TR-181 Device.WiFi.SSID{i}.SSID." &"TR-181 Device Data Model for TR-069."                     "The status of this instance"                       ="This object is defined in TR-181 Device.WiFi.SSID{i}.Stats." &"TR-181 Device Data Model for TR-069."                     /"The Conceptual row of clabWIFISSIDStatsTable." "TR-181 Issue2"                     G"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.BytesSent." &"TR-181 Device Data Model for TR-069."                     K"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.BytesReceived." &"TR-181 Device Data Model for TR-069."                     I"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.PacketsSent." &"TR-181 Device Data Model for TR-069."                     M"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.PacketsReceived." &"TR-181 Device Data Model for TR-069."                     H"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.ErrorsSent." &"TR-181 Device Data Model for TR-069."                     L"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.ErrorsReceived." &"TR-181 Device Data Model for TR-069."                     P"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.UnicastPacketsSent." &"TR-181 Device Data Model for TR-069."                     T"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.UnicastPacketsReceived." &"TR-181 Device Data Model for TR-069."                     P"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.DiscardPacketsSent." &"TR-181 Device Data Model for TR-069."                     T"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.DiscardPacketsReceived." &"TR-181 Device Data Model for TR-069."                     R"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.MulticastPacketsSent." &"TR-181 Device Data Model for TR-069."                     V"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.MulticastPacketsReceived." &"TR-181 Device Data Model for TR-069."                     R"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.BroadcastPacketsSent." &"TR-181 Device Data Model for TR-069."                     V"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.BroadcastPacketsReceived." &"TR-181 Device Data Model for TR-069."                     Y"This object is defined in TR-181 Device.WiFi.SSID{i}.Stats.UnknownProtoPacketsReceived." &"TR-181 Device Data Model for TR-069."                     >"This object is defined in TR-181 Device.WiFi.AccessPoint{i}." &"TR-181 Device Data Model for TR-069."                     1"The Conceptual row of clabWIFIAccessPointTable."                       /"The key for a unique instance of this object."                       E"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Enable." &"TR-181 Device Data Model for TR-069."                     E"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Status." &"TR-181 Device Data Model for TR-069."                     D"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Alias." &"TR-181 Device Data Model for TR-069."                     H"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Reference." &"TR-181 Device Data Model for TR-069."                     S"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.AdvertisementEnabled." &"TR-181 Device Data Model for TR-069."                     I"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.RetryLimit." &"TR-181 Device Data Model for TR-069."                     L"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WMMCapability." &"TR-181 Device Data Model for TR-069."                     N"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.UAPSDCapability." &"TR-181 Device Data Model for TR-069."                     H"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WMMEnable." &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.UAPSDEnable." &"TR-181 Device Data Model for TR-069."                     ^"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.AssociatedDeviceNumberOfEntries." &"TR-181 Device Data Model for TR-069."                     "The status of this instance."                       H"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.." &"TR-181 Device Data Model for TR-069."                     9"The Conceptual row of clabWIFIAccessPointSecurityTable." "802.11-2007"                     V"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.ModesSupported." &"TR-181 Device Data Model for TR-069."                     S"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.ModeEnabled." &"TR-181 Device Data Model for TR-069."                     N"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.WEPKey." &"TR-181 Device Data Model for TR-069."                     T"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.PreSharedKey." &"TR-181 Device Data Model for TR-069."                     U"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.KeyPassphrase." &"TR-181 Device Data Model for TR-069."                     X"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.RekeyingInterval." &"TR-181 Device Data Model for TR-069."                     ^"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.RadiusServerIPAddrType." &"TR-181 Device Data Model for TR-069."                     Z"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.RadiusServerIPAddr." &"TR-181 Device Data Model for TR-069."                     X"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.RadiusServerPort." &"TR-181 Device Data Model for TR-069."                     T"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.Security.RadiusSecret." &"TR-181 Device Data Model for TR-069."                     "The status of this instance."                       2"The WEP key 2 expressed as a hexadecimal string."                       2"The WEP key 3 expressed as a hexadecimal string."                       2"The WEP key 4 expressed as a hexadecimal string."                       ."This attribute defines the selected WEP key."                      _"This attribute defines a human readable password to derive
        the WEP keys, following well-known key generation algorithm for
        this purpose.
        When this attribute is a zero-length string, WEP keys are used
        directly. Otherwise, the values of the WEP keys cannot be
        changed directly and an error on write is returned."                       ?"This attribute defines the encryption algorithm used for WPA."                       B"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WPS." &"TR-181 Device Data Model for TR-069."                     4"The Conceptual row of clabWIFIAccessPointWPSTable." 	"WPSv1.0"                     I"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WPS.Enable." &"TR-181 Device Data Model for TR-069."                     Y"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WPS.ConfigMethodsSupported." &"TR-181 Device Data Model for TR-069."                     W"This object is defined in TR-181 Device.WiFi.AccessPoint{i}.WPS.ConfigMethodsEnabled." &"TR-181 Device Data Model for TR-069."                     "The status of this instance."                       C"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}." &"TR-181 Device Data Model for TR-069."                     6"The Conceptual row of clabWIFIAssociatedDeviceTable."                       |"The key for a unique instance of this object. There is one
        instance for each unique Associated device MAC Address."                       N"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.MACAddress." &"TR-181 Device Data Model for TR-069."                     W"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.AuthenticationState." &"TR-181 Device Data Model for TR-069."                     X"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.LastDataDownlinkRate." &"TR-181 Device Data Model for TR-069."                     \"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.DeviceLastDataUplinkRate." &"TR-181 Device Data Model for TR-069."                     R"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.SignalStrength." &"TR-181 Device Data Model for TR-069."                     S"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.Retransmissions." &"TR-181 Device Data Model for TR-069."                     J"This object is defined in TR-181 Device.WiFi.AssociatedDevice{i}.Active." &"TR-181 Device Data Model for TR-069."                     b"This object indicates the number of packets to be retransmitted
         to have an upper limit."                       ^"This object indicates the total number of stations associated at
         any point in time."                       \"This object specifies the maximum number of STAs associated at
         any point in time."                       Y"This object contains statistics for each speed rate of
        an 802.11 LAN interface."                       3"The Conceptual row of clabWIFIDataRateStatsTable."                       z"This key represents the data speed for the statistics
        collected. the value is reported in integer units of Mbps."                       �"The FramesSent Parameter indicates the total number of frames
        transmitted out of the interface (not marked as duplicated).
The value of this counter MAY be reset to zero when the CPE is rebooted."                       �"The FramesRetransmissionsSent parameter indicates the total
        number of frames retransmitted out of the interface (marked
        as duplicated).
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                       �"The FramesReceived parameter indicates the total number of
        frames received on this interface (not marked as duplicated).
        The value of this counter MAY be reset to zero when the CPE is
        rebooted."                       �"The FramesDuplicatedReceived indicates the total number of
        duplicated frames received on this interface.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                      9"This object contains periodic statistics for an 802.11 SSID
        on a CPE device. Note that these statistics refer to the link
        layer, not to the physical layer. This object does not include
        the total byte and packet statistics, which are, for
        historical reasons, in the parent object."                       3"The Conceptual row of clabWIFIPeriodicStatsTable."                      G"This key indicates the Interval where the measurements were
        Accumulated.
        The interval of measurements is synchronized with the wall clock.
        The total number of intervals is based on a 24 hour period.
        At an interval of 15 minutes 96 intervals (1..96)  are defined,
        at 30 minutes, 48 intervals (1..48) and 24 intervals (1..24)
        for 1 hour measurement interval.
        Devices with  no capabilities to report measurements per interval
        will report the value 0 for the interval attribute of the unique
        statistics  instance."                       x"The Id key represents a unique identifier for a client
        Mac address in a given statistics measurement interval."                       Y"The DeviceMACAddress represents the MAC address of an
        associated client device."                      �"FrameSent is the total number of frames transmitted out of
        the interface.
        For conventional 802.11 MAC (a,b,g) this counter corresponds
        to the total of MSDUs (MAC Service Data Unit) being transmitted.
        For High Throughput transmissions this corresponds to the
        A-MSDU (Aggregation MSDU)
        The value of this counter MAY be reset to zero when the
        CPE is rebooted."                       �"DataFramesSentAck is the total number of MSDU frames marked
        as duplicates and non duplicates acknowledged.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                      B"DataFramesSentNoAck is the total number of MSDU frames
        retransmitted out of the interface (i.e., marked as duplicate
        and non-duplicate) and not acknowledged but not including
        those defined in dataFramesLost.
        The value of this counter MAY be reset to zero when the
        CPE is rebooted."                      "DataFramesLost is the total number of MSDU frames retransmitted
        out of the interface that where not acknowledged and discarded
        for reaching max number of retransmissions.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                      �"FramesReceived is the total number of frames received by the
        interface.
        For conventional 802.11 MAC (a,b,g) this counter corresponds to the
        total of MSDUs (MAC Service Data Unit) being transmitted.
        For High Throughput transmissions (n) this corresponds to A-MSDUs
        (Aggregation MSDU) and MSDUs.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                       �"DataFramesReceived is the total number of MSDU frames
        received and  marked as non-duplicates.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                       �"DataFramesDuplicateReceived is the total number of duplicated
        frames received on this interface.
        The value of this counter MAY be reset to zero when the
        CPE is rebooted."                       8"ProbesReceived is the total number of probes received."                       8"ProbesRejected is the total number of probes rejected."                       {"The Received Signal Strength indicator is the energy observed
        at the antenna receiver for a current transmission."                       u"The signal to Noise Ratio (SNR) parameter represents the strength
        of the signal compared to received noise."                       P"Disassociations represents the total number of client
        disassociations."                       W"AuthenticationFailures indicates the total number of
        authentication failures."                       _"The LastTimeAssociation parameter represents the last
        time the client was associated."                       �"LastTimeDisassociation parameter represents the last time
        the client disassociate from the interface.
The all zeros value indicates the client is currently associated. "                       z"The SSIDPolicy object defines the configuration of policies,
        behaviors and event thresholds controlled per SSID."                       0"The Conceptual row of clabWIFISSIDPolicyTable."                      f"The BlockAfterAttempts parameter indicates the maximum number
        of attempts a client is allowed to attempt registration before
        being denied access. Exceeding this value generates one event.
        Events from same client should not reoccur more than once an
        hour.
        The value zero indicates no connection attempts restrictions."                       �"The AllocatedBandwidth parameter indicates the maximum
        bandwidth reserved for a particular interface.
The value zero indicates no limit."                      O"The AuthenticationFailures parameter indicates the number of
        Authenticationfailures a station simultaneously produces to
        generate the event.
        Events from same client should not reoccur more than once an
        hour.
        The value 0 indicates no threshold and events of this type are
        not generated."                      B"The NonAuthenticatedTraffic parameter represents the number
        of non-authenticated messages received from a station to generate
        an event. Events from same client should not reoccur more
        than once an hour.
        The value 0 indicates no threshold and events of this type are
        not generated."                      1"The AssociationFailures indicates the number of simultaneous
        association failures from a station to generate an event.
        Events from same client should not reoccur more than once an
        hour.
        The value 0 indicates no threshold and events of this type are
        not generated."                       �"The StatsInterval parameter indicates the interval value to
        collect per-interval statistics.

        The value 0 indicates no interval and values reported are
        snapshots at the time of the request. "                       �"The SNR parameter indicates the threshold to report SNR.
        The value -100 indicates no threshold, and events of this
        type are not generated."                       �"The ANPI parameter indicates the threshold to report the
        Average Noise plus Interference. The value -100 indicates no
        threshold, and events of this type are not generated."                      "The LowReceivedPowerThreshold parameter indicates the power
        level threshold to generate an event whenever the station
        received power is below the threshold. The value -100 indicates
        no threshold is set, and events of this type are not generated."                      "The LowPowerDeniedAccessThreshold parameter indicates the
        power level threshold to deny client association whenever the
        station received power is below the threshold. The value -100
        indicates no threshold, and events of this type are not
        generated."                      ="The LowerPowerDissasociationThreshold parameter indicates
        the threshold to report Disassociation due to low power.
        The Wi-Fi GW should refuse associations when the power level
        is below this RSSI level. The value -100 indicates no
        threshold, and events of this type are not generated."                       "The status of this instance."                       Q"The BeaconMcsLevelInUse parameter specifies the beacon MCS to
         be used."                       Z"The BeaconMcsLevelsSupported parameter specifies all the beacon MCSs
         supported."                      "The ClientSessions object represents the current
        and closed sessions (association connections).
        When the maximum number of instances is reached, the oldest
        closed session instance is replaced by a newly created client
        association."                       4"The Conceptual row of clabWIFIClientSessionsTable."                       5"The Id key identifies a single client  MAC Address."                       b"The DeviceMACAddress parameter indicates the MAC address
        of an associated client device."                       J"The Start parameter indicates the time when the session
        started."                       �"The Stop parameter indicates the time when the session ended.
        If the session us current the value reported is all zeros."                      N"The TerminationCode parameter indicates the Reason Code or the
        Status Code that lead to ending the association of the station.
        Reason code and Status code overlaps. The context of the type of
        termination is provided by the TerminationMeaning attribute.
        The value zero indicates the session is active."                       �"The TerminationMeaning parameter indicates the meaning of the
        Reason Code or Status Code for the ended session.
        The zero-length string is used when the instance corresponds
        to an active session."                       �"The ClientStats object contains accumulative statistics
        for each client station.
        A station is reported only after is associated for the
        first time. "                       1"The Conceptual row of clabWIFIClientStatsTable."                      "The Interval parameter indicate the measurements were
        accumulated.
        The interval of measurements is synchronized with the
        wall clock
        The total number of intervals is based on a 24 hour period.
        At an interval of 15 minutes 96 intervals (1..96)  are defined,
        at 30 minutes, 48 intervals (1..48) and 24 intervals (1..24)
        for 1 hour measurement interval.
        Devices with  no capable to report measurements per interval
        will report the value 0 for the interval attribute."                       5"The Id key identifies a single client  MAC Address."                       b"The DeviceMACAddress parameter indicates the MAC address of
        an associated client device."                      �"The FramesSent parameter indicates the total number of frames
        transmitted out of the interface.
        For conventional 802.11 MAC (a,b,g) this counter corresponds
        to the total of MSDUs (MAC Service Data Unit) being transmitted.
        For High Throughput transmissions this corresponds to the
        A-MSDU (Aggregation MSDU)
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                       �"The DataFramesSentAck parameter indicates the total number of
        MSDU frames marked as duplicates and non duplicates acknowledged.
        The value of this counter MAY be reset to zero when the CPE is
        rebooted."                      W"The DataFramesSentNoAck parameter indicates the total number of
        MSDU frames retransmitted out of the interface
        (i.e., marked as duplicate and non-duplicate) and not acknowledged
        but not including those defined in dataFramesLost.
        The value of this counter MAY be reset to zero when the CPE is
        rebooted."                      2"The DataFramesLost parameter indicates the total number of
        MSDU frames retransmitted out of the interface that where not
        acknowledged and discarded for reaching max number of
        retransmissions.
        The value of this counter MAY be reset to zero when the CPE is
        rebooted."                      �"The FramesReceived parameter indicates the total number of
        frames received by the interface.
        For conventional 802.11 MAC (a,b,g) this counter corresponds
        to the total of MSDUs (MAC Service Data Unit) being transmitted.
        For High Throughput transmissions (n) this corresponds to
        A-MSDUs (Aggregation MSDU) and MSDUs.
        The value of this counter MAY be reset to zero when the
        CPE is rebooted."                       �"The DataFramesReceived parameter indicates the total number
        of MSDU frames received and  marked as non-duplicates.
        The value of this counter MAY be reset to zero when the CPE
        is rebooted."                       �"The DataFramesDuplicateReceived parameter indicates the total
        number of duplicated frames received on this interface.
        The value of this counter MAY be reset to zero when the
        CPE is rebooted."                       U"The ProbesReceived parameter indicates the Total number of
        probes received."                       U"The ProbesRejected parameter indicates the total number of
        probes rejected."                       �"The Received Signal Strength Indicator, RSSI, parameter is the
        energy observed at the antenna receiver for a current
        transmission."                       �"The signal to Noise Ratio (SNR) parameter indicates the signal
        strength received from a client compared to the noise received."                       ]"The Disassociations parameter indicates the total number of
        client disassociations."                       e"The AuthenticationFailures parameter indicates the total
        number of authentication failures."                       ^"The LastTimeAssociation parameter indicates the Last time
        the client was associated."                       �"The  LastTimeDisassociation parameter indicates the last time
        the client disassociate from the interface.
        The all zeros value indicates the client is currently
        associated. "                      %"This object is the extension of Radius Client operation
        for the Access Point 802.1x Authenticator for WPA Enterprise.
        An instance is relevant when the attribute
        AccessPointSecurity.ModeEnabled is 'WPA-Enterprise' or
        'WPA2-Enterprise' or 'WPA-WPA2-Enterprise'."                       2"The Conceptual row of clabWIFIRadiusClientTable."                      K"The NAS-Identifier parameter corresponds to the Radius
        attribute NAS-Identifier used in Access request messages.
        The device always sends the Radius parameter NAS-IP-Address
        and will send the NAS-Identifier parameter when this
        attribute is set to other than the zero-length string.
        The NAS-Identifier attribute can be used as a hint to
        indicate the authentication server the SSID domain where
        the WiFi endpoint tries to authenticate, i.e.,
        when more than one SSID domains are using the same
        Radius server instance."                       ~"The LocationPolicy  corresponds to the string value of the
        Radius Basic-Location-Policy-Rules attribute per RFC 5580"                       x"The OperatorName parameter corresponds to the string value of the
        Radius Operator-Name attribute per RFC 5580."                       �"The LocationInformation parameter corresponds to the string
        value of the Radius Location-Information  attribute per
        RFC 5580."                       x"The Location Data parameter corresponds to the string value of
        the Radius LocationData attribute per RFC 5580."                       h"The UsageReports parameter indicates whether the client send
        usage data 'true' or not 'false'."                       �"The IntervalInterimReport parameter indicates whether the client
        send Interim reports at time intervals 'true' or not 'false'."                       �"A 'true' value for the APTransitionReport parameter indicates the
        client sends Interim reports when the stations transitions to a
        different Access point."                       y"A 'true' value for Gigaword Report indicates the client sends
        Interim reports when the 32-bit counters rollover"                       "The status of this instance."                          0"This attribute when set to 'true' flushes the WiFi settings in
        non-volatile memory and reinitialize the WiFi system with the
        new set of values without reboot.

        This attribute reports a value 'false' when WiFi attributes have
        been changed but the changes are not active (i.e.,. not flushed
        in non-volatile and not part of the active configuration).

        Systems that support immediate commit upon any attribute change
        will report this attribute as 'true' always, and silently
        accepts sets to 'true'."                       O"This table defines neighbor information known through channel
         scans."                       5"The conceptual row of clabWIFIApNeighborStatsTable."                       ;"The attribute indicates the current SSID of the neighbor."                       X"The attribute indicates the current channel being used by the
         neighboring AP."                       b"The attribute indicates the current bandwidth in which the
         neighboring AP is operating."                       �"The attribute indicates the signal strength at which packets
         from the neighboring AP are received at the measuring AP, in
         terms of dBm."                               #"The compliance statement for the."                   +"Objects implemented in the clabWIFIGroup."                 >"Notifications implemented in the clabWIFINotificationsGroup."                            