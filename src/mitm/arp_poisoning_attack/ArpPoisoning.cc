/*
 * Copyright (C) 2004 Andras Varga
 * Copyright (C) 2008 Alfonso Ariza Quintana (global arp)
 * Copyright (C) 2014 OpenSim Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/dissector/ProtocolDissector.h"
#include "inet/common/packet/dissector/ProtocolDissectorRegistry.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "ArpPoisoning.h"
#include "inet/networklayer/arp/ipv4/ArpPacket_m.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/common/L3AddressResolver.h"

namespace inet {

simsignal_t ArpPoisoning::arpRequestSentSignal = registerSignal("arpRequestSent");
simsignal_t ArpPoisoning::arpReplySentSignal = registerSignal("arpReplySent");

static std::ostream& operator<<(std::ostream& out, const ArpPoisoning::ArpCacheEntry& e)
{
    if (e.pending)
        out << "pending (" << e.numRetries << " retries)";
    else
        out << "MAC:" << e.macAddress << "  age:" << floor(simTime() - e.lastUpdate) << "s";
    return out;
}

Define_Module(ArpPoisoning);

ArpPoisoning::ArpPoisoning()
{
}

/********** Arp Poisoning Methods *************/

void ArpPoisoning::sendFakeArpReply(Ipv4Address victim1, Ipv4Address victim2, MacAddress macVictim1, MacAddress myMACAddress) {
    // "Swap hardware and protocol fields", etc.
    const auto& arpReply = makeShared<ArpPacket>();

    arpReply->setDestIpAddress(victim1);
    arpReply->setDestMacAddress(macVictim1);
    arpReply->setSrcIpAddress(victim2);
    arpReply->setSrcMacAddress(myMACAddress);

    arpReply->setOpcode(ARP_REPLY);
    Packet *outPk = new Packet("arpREPLY");
    outPk->insertAtFront(arpReply);
    outPk->addTag<MacAddressReq>()->setDestAddress(macVictim1);
    outPk->addTag<InterfaceReq>()->setInterfaceId(ift->getInterface(1)->getInterfaceId());
    outPk->addTag<PacketProtocolTag>()->setProtocol(&Protocol::arp);

    // send out
    EV_INFO << "Sending " << outPk << " to network protocol.\n";
    emit(arpReplySentSignal, outPk);
    send(outPk, "ifOut");
    numRepliesSent++;
}

void ArpPoisoning::handleArpPoisoningTimerMsg() {
    EV_INFO << "It is Arp Poisoning time" << endl;

    L3Address result1;
    L3AddressResolver().tryResolve(victim1str, result1);
    Ipv4Address victim1 = result1.toIpv4();

    L3Address result2;
    L3AddressResolver().tryResolve(victim2str, result2);
    Ipv4Address victim2 = result2.toIpv4();


    MacAddress myMACAddress = ift->getInterface(1)->getMacAddress();
    Ipv4Address myIPAddress = ift->getInterface(1)->getIpv4Address();

    ArpCache::const_iterator it = arpCache.find(victim1);
    if (it == arpCache.end()) {
        // no cache entry: launch ARP request
        ArpCacheEntry *entry = new ArpCacheEntry();
        entry->owner = this;
        auto where = arpCache.insert(arpCache.begin(), std::make_pair(victim1, entry));
        entry->myIter = where;    // note: "inserting a new element into a map does not invalidate iterators that point to existing elements"
        entry->ie = ift->getInterface(1);

        EV << "Starting ARP resolution for " << victim1 << "\n";
        initiateArpResolution(entry);
        scheduleAt(simTime() + 0.3, arpPoisoningTimerMsg);
        return;
    }

    ArpCache::const_iterator it2 = arpCache.find(victim2);
    if (it2 == arpCache.end()) {
        // no cache entry: launch ARP request
        ArpCacheEntry *entry = new ArpCacheEntry();
        entry->owner = this;
        auto where = arpCache.insert(arpCache.begin(), std::make_pair(victim2, entry));
        entry->myIter = where;    // note: "inserting a new element into a map does not invalidate iterators that point to existing elements"
        entry->ie = ift->getInterface(1);

        EV << "Starting ARP resolution for " << victim2 << "\n";
        initiateArpResolution(entry);
        scheduleAt(simTime() + 0.3, arpPoisoningTimerMsg);
        return;
    }

    ArpCacheEntry *entryVictim1 = it->second;
    MacAddress macVictim1 = entryVictim1->macAddress;
    ArpCacheEntry *entryVictim2 = it2->second;
    MacAddress macVictim2 = entryVictim2->macAddress;

    sendFakeArpReply(victim1, victim2, macVictim1, myMACAddress);
    sendFakeArpReply(victim2, victim1, macVictim2, myMACAddress);

    scheduleAt(simTime() + arpPoisoningTimer, arpPoisoningTimerMsg);
}

/**********************************************/

void ArpPoisoning::initialize(int stage)
{
    OperationalBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        retryTimeout = par("retryTimeout");
        retryCount = par("retryCount");
        cacheTimeout = par("cacheTimeout");
        proxyArpInterfaces = par("proxyArpInterfaces").stdstringValue();

        proxyArpInterfacesMatcher.setPattern(proxyArpInterfaces.c_str(), false, true, false);

        // init statistics
        numRequestsSent = numRepliesSent = 0;
        numResolutions = numFailedResolutions = 0;
        WATCH(numRequestsSent);
        WATCH(numRepliesSent);
        WATCH(numResolutions);
        WATCH(numFailedResolutions);

        WATCH_PTRMAP(arpCache);

        arpPoisoningTimerMsg = new cMessage("arpPoisoningTimerMsg");
        arpPoisoningTimer = par("arpPoisoningTimer");
        arpPoisoningStart = par("arpPoisoningStart");
        victim1str = par("victim1");
        victim2str = par("victim2");
        scheduleAt(simTime() + arpPoisoningStart, arpPoisoningTimerMsg);
    }
    else if (stage == INITSTAGE_NETWORK_LAYER) {
        ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        rt = getModuleFromPar<IIpv4RoutingTable>(par("routingTableModule"), this);
        registerService(Protocol::arp, gate("netwIn"), gate("ifIn"));
        registerProtocol(Protocol::arp, gate("ifOut"), gate("netwOut"));
    }
}

void ArpPoisoning::finish()
{
}

ArpPoisoning::~ArpPoisoning()
{
    for (auto & elem : arpCache)
        delete elem.second;
}

void ArpPoisoning::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == arpPoisoningTimerMsg) {
            handleArpPoisoningTimerMsg();
            return;
        }
        requestTimedOut(msg);
    }
    else {
        Packet *packet = check_and_cast<Packet *>(msg);
        processArpPacket(packet);
    }
}

void ArpPoisoning::handleStartOperation(LifecycleOperation *operation)
{
    ASSERT(arpCache.empty());
}

void ArpPoisoning::handleStopOperation(LifecycleOperation *operation)
{
    flush();
}

void ArpPoisoning::handleCrashOperation(LifecycleOperation *operation)
{
    flush();
}

void ArpPoisoning::flush()
{
    while (!arpCache.empty()) {
        auto i = arpCache.begin();
        ArpCacheEntry *entry = i->second;
        cancelAndDelete(entry->timer);
        entry->timer = nullptr;
        delete entry;
        arpCache.erase(i);
    }
}

void ArpPoisoning::refreshDisplay() const
{
    OperationalBase::refreshDisplay();

    std::stringstream os;

    os << "size:" << arpCache.size() << " sent:" << numRequestsSent << "\n"
       << "repl:" << numRepliesSent << " fail:" << numFailedResolutions;

    getDisplayString().setTagArg("t", 0, os.str().c_str());
}

void ArpPoisoning::initiateArpResolution(ArpCacheEntry *entry)
{
    Ipv4Address nextHopAddr = entry->myIter->first;
    entry->pending = true;
    entry->numRetries = 0;
    entry->lastUpdate = SIMTIME_ZERO;
    entry->macAddress = MacAddress::UNSPECIFIED_ADDRESS;
    sendArpRequest(entry->ie, nextHopAddr);

    // start timer
    cMessage *msg = entry->timer = new cMessage("ARP timeout");
    msg->setContextPointer(entry);
    scheduleAt(simTime() + retryTimeout, msg);

    numResolutions++;
    Notification signal(nextHopAddr, MacAddress::UNSPECIFIED_ADDRESS, entry->ie);
    emit(arpResolutionInitiatedSignal, &signal);
}

void ArpPoisoning::sendArpRequest(const InterfaceEntry *ie, Ipv4Address ipAddress)
{
    // find our own IPv4 address and MAC address on the given interface
    MacAddress myMACAddress = ie->getMacAddress();
    Ipv4Address myIPAddress = ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress();

    // both must be set
    ASSERT(!myMACAddress.isUnspecified());
    ASSERT(!myIPAddress.isUnspecified());

    // fill out everything in ARP Request packet except dest MAC address
    Packet *packet = new Packet("arpREQ");
    const auto& arp = makeShared<ArpPacket>();
    arp->setOpcode(ARP_REQUEST);
    arp->setSrcMacAddress(myMACAddress);
    arp->setSrcIpAddress(myIPAddress);
    arp->setDestIpAddress(ipAddress);
    packet->insertAtFront(arp);

    packet->addTag<MacAddressReq>()->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::arp);
    // send out
    EV_INFO << "Sending " << packet << " to network protocol.\n";
    emit(arpRequestSentSignal, packet);
    send(packet, "ifOut");
    numRequestsSent++;
}

void ArpPoisoning::requestTimedOut(cMessage *selfmsg)
{
    ArpCacheEntry *entry = (ArpCacheEntry *)selfmsg->getContextPointer();
    entry->numRetries++;
    if (entry->numRetries < retryCount) {
        // retry
        Ipv4Address nextHopAddr = entry->myIter->first;
        EV_INFO << "ARP request for " << nextHopAddr << " timed out, resending\n";
        sendArpRequest(entry->ie, nextHopAddr);
        scheduleAt(simTime() + retryTimeout, selfmsg);
        return;
    }

    delete selfmsg;

    // max retry count reached: ARP failure.
    // throw out entry from cache
    EV << "ARP timeout, max retry count " << retryCount << " for " << entry->myIter->first << " reached.\n";
    Notification signal(entry->myIter->first, MacAddress::UNSPECIFIED_ADDRESS, entry->ie);
    emit(arpResolutionFailedSignal, &signal);
    arpCache.erase(entry->myIter);
    delete entry;
    numFailedResolutions++;
}

bool ArpPoisoning::addressRecognized(Ipv4Address destAddr, InterfaceEntry *ie)
{
    if (rt->isLocalAddress(destAddr))
        return true;
    else {
        // if proxy ARP is enables in interface ie
        if (proxyArpInterfacesMatcher.matches(ie->getInterfaceName())) {
            // if we can route this packet, and the output port is
            // different from this one, then say yes
            InterfaceEntry *rtie = rt->getInterfaceForDestAddr(destAddr);
            return rtie != nullptr && rtie != ie;
        }
        else
            return false;
    }
}

void ArpPoisoning::dumpArpPacket(const ArpPacket *arp)
{
    EV_DETAIL << (arp->getOpcode() == ARP_REQUEST ? "ARP_REQ" : arp->getOpcode() == ARP_REPLY ? "ARP_REPLY" : "unknown type")
              << "  src=" << arp->getSrcIpAddress() << " / " << arp->getSrcMacAddress()
              << "  dest=" << arp->getDestIpAddress() << " / " << arp->getDestMacAddress() << "\n";
}

void ArpPoisoning::processArpPacket(Packet *packet)
{
    EV_INFO << "Received " << packet << " from network protocol.\n";
    const auto& arp = packet->peekAtFront<ArpPacket>();
    dumpArpPacket(arp.get());

    // extract input port
    InterfaceEntry *ie = ift->getInterfaceById(packet->getTag<InterfaceInd>()->getInterfaceId());

    //
    // Recipe a'la RFC 826:
    //
    // ?Do I have the hardware type in ar$hrd?
    // Yes: (almost definitely)
    //   [optionally check the hardware length ar$hln]
    //   ?Do I speak the protocol in ar$pro?
    //   Yes:
    //     [optionally check the protocol length ar$pln]
    //     Merge_flag := false
    //     If the pair <protocol type, sender protocol address> is
    //         already in my translation table, update the sender
    //         hardware address field of the entry with the new
    //         information in the packet and set Merge_flag to true.
    //     ?Am I the target protocol address?
    //     Yes:
    //       If Merge_flag is false, add the triplet <protocol type,
    //           sender protocol address, sender hardware address> to
    //           the translation table.
    //       ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
    //       Yes:
    //         Swap hardware and protocol fields, putting the local
    //             hardware and protocol addresses in the sender fields.
    //         Set the ar$op field to ares_op$REPLY
    //         Send the packet to the (new) target hardware address on
    //             the same hardware on which the request was received.
    //

    MacAddress srcMacAddress = arp->getSrcMacAddress();
    Ipv4Address srcIpAddress = arp->getSrcIpAddress();

    if (srcMacAddress.isUnspecified())
        throw cRuntimeError("wrong ARP packet: source MAC address is empty");
    if (srcIpAddress.isUnspecified())
        throw cRuntimeError("wrong ARP packet: source IPv4 address is empty");

    bool mergeFlag = false;
    // "If ... sender protocol address is already in my translation table"
    auto it = arpCache.find(srcIpAddress);
    if (it != arpCache.end()) {
        // "update the sender hardware address field"
        ArpCacheEntry *entry = it->second;
        updateArpCache(entry, srcMacAddress);
        mergeFlag = true;
    }

    // "?Am I the target protocol address?"
    // if Proxy ARP is enabled, we also have to reply if we're a router to the dest IPv4 address
    if (addressRecognized(arp->getDestIpAddress(), ie)) {
        // "If Merge_flag is false, add the triplet protocol type, sender
        // protocol address, sender hardware address to the translation table"
        if (!mergeFlag) {
            ArpCacheEntry *entry;
            if (it != arpCache.end()) {
                entry = it->second;
            }
            else {
                entry = new ArpCacheEntry();
                auto where = arpCache.insert(arpCache.begin(), std::make_pair(srcIpAddress, entry));
                entry->myIter = where;
                entry->ie = ie;

                entry->pending = false;
                entry->timer = nullptr;
                entry->numRetries = 0;
            }
            updateArpCache(entry, srcMacAddress);
        }

        // "?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)"
        switch (arp->getOpcode()) {
            case ARP_REQUEST: {
                EV_DETAIL << "Packet was ARP REQUEST, sending REPLY\n";
                MacAddress myMACAddress = resolveMacAddressForArpReply(ie, arp.get());
                if (myMACAddress.isUnspecified()) {
                    delete packet;
                    return;
                }

                Ipv4Address myIPAddress = ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress();

                // "Swap hardware and protocol fields", etc.
                const auto& arpReply = makeShared<ArpPacket>();
                Ipv4Address origDestAddress = arp->getDestIpAddress();
                arpReply->setDestIpAddress(srcIpAddress);
                arpReply->setDestMacAddress(srcMacAddress);
                arpReply->setSrcIpAddress(origDestAddress);
                arpReply->setSrcMacAddress(myMACAddress);
                arpReply->setOpcode(ARP_REPLY);
                Packet *outPk = new Packet("arpREPLY");
                outPk->insertAtFront(arpReply);
                outPk->addTag<MacAddressReq>()->setDestAddress(srcMacAddress);
                outPk->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
                outPk->addTag<PacketProtocolTag>()->setProtocol(&Protocol::arp);

                // send out
                EV_INFO << "Sending " << outPk << " to network protocol.\n";
                emit(arpReplySentSignal, outPk);
                send(outPk, "ifOut");
                numRepliesSent++;
                break;
            }

            case ARP_REPLY: {
                EV_DETAIL << "Discarding packet\n";
                break;
            }

            case ARP_RARP_REQUEST:
                throw cRuntimeError("RARP request received: RARP is not supported");

            case ARP_RARP_REPLY:
                throw cRuntimeError("RARP reply received: RARP is not supported");

            default:
                throw cRuntimeError("Unsupported opcode %d in received ARP packet", arp->getOpcode());
        }
    }
    else {
        // address not recognized
        EV_INFO << "IPv4 address " << arp->getDestIpAddress() << " not recognized, dropping ARP packet\n";
    }
    delete packet;
}

MacAddress ArpPoisoning::resolveMacAddressForArpReply(const InterfaceEntry *ie, const ArpPacket *arp)
{
    return ie->getMacAddress();
}

void ArpPoisoning::updateArpCache(ArpCacheEntry *entry, const MacAddress& macAddress)
{
    EV_DETAIL << "Updating ARP cache entry: " << entry->myIter->first << " <--> " << macAddress << "\n";

    // update entry
    if (entry->pending) {
        entry->pending = false;
        delete cancelEvent(entry->timer);
        entry->timer = nullptr;
        entry->numRetries = 0;
    }
    entry->macAddress = macAddress;
    entry->lastUpdate = simTime();
    Notification signal(entry->myIter->first, macAddress, entry->ie);
    emit(arpResolutionCompletedSignal, &signal);
}

MacAddress ArpPoisoning::resolveL3Address(const L3Address& address, const InterfaceEntry *ie)
{
    Enter_Method("resolveMACAddress(%s,%s)", address.str().c_str(), ie->getInterfaceName());

    Ipv4Address addr = address.toIpv4();
    ArpCache::const_iterator it = arpCache.find(addr);
    if (it == arpCache.end()) {
        // no cache entry: launch ARP request
        ArpCacheEntry *entry = new ArpCacheEntry();
        entry->owner = this;
        auto where = arpCache.insert(arpCache.begin(), std::make_pair(addr, entry));
        entry->myIter = where;    // note: "inserting a new element into a map does not invalidate iterators that point to existing elements"
        entry->ie = ie;

        EV << "Starting ARP resolution for " << addr << "\n";
        initiateArpResolution(entry);
        return MacAddress::UNSPECIFIED_ADDRESS;
    }
    else if (it->second->pending) {
        // an ARP request is already pending for this address
        EV << "ARP resolution for " << addr << " is already pending\n";
        return MacAddress::UNSPECIFIED_ADDRESS;
    }
    else if (it->second->lastUpdate + cacheTimeout >= simTime()) {
        return it->second->macAddress;
    }
    else {
        EV << "ARP cache entry for " << addr << " expired, starting new ARP resolution\n";
        ArpCacheEntry *entry = it->second;
        entry->ie = ie;    // routing table may have changed
        initiateArpResolution(entry);
    }
    return MacAddress::UNSPECIFIED_ADDRESS;
}

L3Address ArpPoisoning::getL3AddressFor(const MacAddress& macAddr) const
{
    Enter_Method_Silent();

    if (macAddr.isUnspecified())
        return Ipv4Address::UNSPECIFIED_ADDRESS;

    simtime_t now = simTime();
    for (const auto & elem : arpCache)
        if (elem.second->macAddress == macAddr && elem.second->lastUpdate + cacheTimeout >= now)
            return elem.first;


    return Ipv4Address::UNSPECIFIED_ADDRESS;
}

// Also known as ARP Announcement
void ArpPoisoning::sendArpGratuitous(const InterfaceEntry *ie, MacAddress srcAddr, Ipv4Address ipAddr, ArpOpcode opCode)
{
    Enter_Method_Silent();

    // both must be set
    ASSERT(!srcAddr.isUnspecified());
    ASSERT(!ipAddr.isUnspecified());

    // fill out everything in ARP Request packet except dest MAC address
    Packet *packet = new Packet("arpGrt");
    const auto& arp = makeShared<ArpPacket>();
    arp->setOpcode(opCode);
    arp->setSrcMacAddress(srcAddr);
    arp->setSrcIpAddress(ipAddr);
    arp->setDestIpAddress(ipAddr);
    arp->setDestMacAddress(MacAddress::BROADCAST_ADDRESS);
    packet->insertAtFront(arp);

    auto macAddrReq = packet->addTag<MacAddressReq>();
    macAddrReq->setSrcAddress(srcAddr);
    macAddrReq->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::arp);

    ArpCacheEntry *entry = new ArpCacheEntry();
    auto where = arpCache.insert(arpCache.begin(), std::make_pair(ipAddr, entry));
    entry->myIter = where;
    entry->ie = ie;

    entry->pending = false;
    entry->timer = nullptr;
    entry->numRetries = 0;

//    updateARPCache(entry, srcAddr); //FIXME

    // send out
    send(packet, "ifOut");
}

// A client should send out 'ARP Probe' to probe the newly received IPv4 address.
// Refer to RFC 5227, IPv4 Address Conflict Detection
void ArpPoisoning::sendArpProbe(const InterfaceEntry *ie, MacAddress srcAddr, Ipv4Address probedAddr)
{
    Enter_Method_Silent();

    // both must be set
    ASSERT(!srcAddr.isUnspecified());
    ASSERT(!probedAddr.isUnspecified());

    Packet *packet = new Packet("arpProbe");
    const auto& arp = makeShared<ArpPacket>();
    arp->setOpcode(ARP_REQUEST);
    arp->setSrcMacAddress(srcAddr);
    arp->setSrcIpAddress(Ipv4Address::UNSPECIFIED_ADDRESS);
    arp->setDestIpAddress(probedAddr);
    arp->setDestMacAddress(MacAddress::UNSPECIFIED_ADDRESS);
    packet->insertAtFront(arp);

    auto macAddrReq = packet->addTag<MacAddressReq>();
    macAddrReq->setSrcAddress(srcAddr);
    macAddrReq->setDestAddress(MacAddress::BROADCAST_ADDRESS);
    packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::arp);

    // send out
    send(packet, "ifOut");
}

} // namespace inet

