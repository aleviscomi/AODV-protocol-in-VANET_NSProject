//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package networkprojectvanet.mitm.arp_poisoning_attack;

import inet.networklayer.contract.IArp;

//
// TODO auto-generated module
//
simple ArpPoisoning like IArp
{
    parameters:
        @class(inet::ArpPoisoning);
        
        double arpPoisoningTimer @unit(s) = default(5s);
        double arpPoisoningStart @unit(s) = default(10s);
        string victim1 = default("");
        string victim2 = default("");
        
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule;
        double retryTimeout @unit(s) = default(1s);   // number seconds ARP waits between retries to resolve an IPv4 address
        int retryCount = default(3);                  // number of times ARP will attempt to resolve an IPv4 address
        double cacheTimeout @unit(s) = default(120s); // number seconds unused entries in the cache will time out
        string proxyArpInterfaces = default("*");     // list of interfaces that proxy ARP is enabled (all interfaces by default)
        @display("i=block/layer");
        @signal[arpRequestSent](type=inet::Packet);
        @signal[arpReplySent](type=inet::Packet);
        @signal[arpResolutionInitiated](type=inet::IArp::Notification);
        @signal[arpResolutionCompleted](type=inet::IArp::Notification);
        @signal[arpResolutionFailed](type=inet::IArp::Notification);
        @statistic[arpRequestSent](title="ARP request sent"; source=arpRequestSent; record=count,"sum(packetBytes)","vector(packetBytes)");
        @statistic[arpReplySent](title="ARP replies sent"; source=arpReplySent; record=count,"sum(packetBytes)","vector(packetBytes)");
        @statistic[arpResolutionInitiated](title="ARP initiated resolutions"; record=count);
        @statistic[arpResolutionCompleted](title="ARP completed resolutions"; record=count);
        @statistic[arpResolutionFailed](title="ARP failed resolutions"; record=count);
    gates:
        input netwIn @labels(ArpPacket+Ieee802Ctrl); // incoming ARP requests and replies
        output netwOut @labels(ArpPacket+Ieee802Ctrl,Ipv4Header+Ieee802Ctrl);  // outgoing ARP requests/replies, and datagrams with resolved next hop
        input ifIn @labels(ArpPacket,Ieee802Ctrl);
        output ifOut @labels(ArpPacket,Ieee802Ctrl);
}
