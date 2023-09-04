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

#include "inet/networklayer/common/L3Tools.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "SecureAodvFlooding.h"

using namespace inet;
using namespace aodv;

Define_Module(SecureAodvFlooding);

const int KIND_DELAYEDSEND = 100;

SecureAodvFlooding::SecureAodvFlooding() {

}

SecureAodvFlooding::~SecureAodvFlooding() {

}

void SecureAodvFlooding::initialize(int stage) {
    if (stage == INITSTAGE_ROUTING_PROTOCOLS)
        addressType = getSelfIPAddress().getAddressType();  // needed for handleStartOperation()

    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        lastBroadcastTime = SIMTIME_ZERO;
        rebootTime = SIMTIME_ZERO;
        rreqId = sequenceNum = 0;
        rreqCount = rerrCount = 0;
        host = getContainingNode(this);
        routingTable = getModuleFromPar<IRoutingTable>(par("routingTableModule"), this);
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        networkProtocol = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);

        aodvUDPPort = par("udpPort");
        askGratuitousRREP = par("askGratuitousRREP");
        useHelloMessages = par("useHelloMessages");
        destinationOnlyFlag = par("destinationOnlyFlag");
        activeRouteTimeout = par("activeRouteTimeout");
        helloInterval = par("helloInterval");
        allowedHelloLoss = par("allowedHelloLoss");
        netDiameter = par("netDiameter");
        nodeTraversalTime = par("nodeTraversalTime");
        rerrRatelimit = par("rerrRatelimit");
        rreqRetries = par("rreqRetries");
        rreqRatelimit = par("rreqRatelimit");
        timeoutBuffer = par("timeoutBuffer");
        ttlStart = par("ttlStart");
        ttlIncrement = par("ttlIncrement");
        ttlThreshold = par("ttlThreshold");
        localAddTTL = par("localAddTTL");
        jitterPar = &par("jitter");
        periodicJitter = &par("periodicJitter");

        myRouteTimeout = par("myRouteTimeout");
        deletePeriod = par("deletePeriod");
        blacklistTimeout = par("blacklistTimeout");
        netTraversalTime = par("netTraversalTime");
        nextHopWait = par("nextHopWait");
        pathDiscoveryTime = par("pathDiscoveryTime");
        expungeTimer = new cMessage("ExpungeTimer");
        counterTimer = new cMessage("CounterTimer");
        rrepAckTimer = new cMessage("RrepAckTimer");
        blacklistTimer = new cMessage("BlackListTimer");

        antiFloodingTimeout = par("antiFloodingTimeout");
        antiFloodingLimit = par("antiFloodingLimit");
        isDynamic = par("isDynamic");
        rreqRateTimer = new cMessage("rreqRateTimer");

        if(isDynamic && getParentModule()->getIndex() == 1) {
            scheduleAt(17, rreqRateTimer);
        }

        if (useHelloMessages)
            helloMsgTimer = new cMessage("HelloMsgTimer");
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        networkProtocol->registerHook(0, this);
        host->subscribe(linkBrokenSignal, this);
        usingIpv6 = (routingTable->getRouterIdAsGeneric().getType() == L3Address::IPv6);
    }
}

void SecureAodvFlooding::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (auto waitForRrep = dynamic_cast<WaitForRrep *>(msg))
            handleWaitForRREP(waitForRrep);
        else if (msg == helloMsgTimer)
            sendHelloMessagesIfNeeded();
        else if (msg == expungeTimer)
            expungeRoutes();
        else if (msg == counterTimer) {
            rreqCount = rerrCount = 0;
            scheduleAt(simTime() + 1, counterTimer);
        }
        else if (msg == rrepAckTimer)
            handleRREPACKTimer();
        else if (msg == blacklistTimer)
            handleBlackListTimer();
        else if (msg == rreqRateTimer) {
            std::cout << "TEMPO: " << simTime() << " | car[" << getParentModule()->getIndex() << "] | rreq rate: " << rreqCountMitigation << endl;
            if(rreqCountMitigation > 15 && antiFloodingLimit > 3)
                antiFloodingLimit--;
            if(rreqCountMitigation < 10 && antiFloodingLimit < 6)
                antiFloodingLimit++;
            rreqCountMitigation = 0;
            scheduleAt(simTime() + 1, rreqRateTimer);
        }
        else if (msg->getFullPath().find("clearAntiFloodingTable of ") != string::npos){
            string addr = msg->getFullPath();
            addr = addr.substr(addr.find("of ")+3);
            EV_WARN << "Clearing..." << endl << addr << " with n° packets: " << antiFloodingMap[addr] << endl;
            antiFloodingMap[addr]--;
            EV_WARN << "Updated to: " << antiFloodingMap[addr] << endl;
        }
        else if (msg->getKind() == KIND_DELAYEDSEND) {
            auto timer = check_and_cast<PacketHolderMessage*>(msg);
            socket.send(timer->dropOwnedPacket());
            delete timer;
        }
        else
            throw cRuntimeError("Unknown self message");
    }
    else
        socket.processMessage(msg);
}


void SecureAodvFlooding::handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) {
    EV_INFO << "AODV Route Request arrived with source addr: " << sourceAddr << " originator addr: " << rreq->getOriginatorAddr()
                << " destination addr: " << rreq->getDestAddr() << endl;

    // A node ignores all RREQs received from any node in its blacklist flooding set.

    // Check if I'm one-hop neighbor
    if(rreq->getOriginatorAddr() == sourceAddr) {
        string sourceAddrStr = sourceAddr.str();

        // Check if value is <0 (means that IP is in blacklist)
        if(antiFloodingMap[sourceAddrStr] < 0) {
            EV_WARN << sourceAddrStr << " is an attacker. He is in blacklist. Discarding packet..." << endl;
            return;
        }
        // Check if this IP passed limit
        else if(antiFloodingMap[sourceAddrStr] + 1 >= antiFloodingLimit) {
            //std::cout << "simtime: " << simTime() << "; originator: " << rreq->getOriginatorAddr() << "; source: " << sourceAddr << "; me: " << getSelfIPAddress() << "; dest: " << rreq->getDestAddr() << endl;
            EV_WARN << sourceAddrStr << " is attempting a flooding attack. Put in blacklist. Discarding packet..." << endl;
            antiFloodingMap[sourceAddrStr] = -1;
            return;
        }
        else {
            EV_WARN << "RREQ from: " << sourceAddrStr << " with n° packets " << antiFloodingMap[sourceAddrStr] << endl;
            antiFloodingMap[sourceAddrStr]++;
            EV_WARN << "Updated to: " << antiFloodingMap[sourceAddrStr] << endl;

            string x = "clearAntiFloodingTable of " + sourceAddrStr;
            const char *s = x.c_str();
            cMessage *clear = new cMessage(s);
            scheduleAt(simTime()+antiFloodingTimeout, clear);
        }
    }

    if(isDynamic) {
        rreqCountMitigation++;
    }



    // A node ignores all RREQs received from any node in its blacklist set.

    auto blackListIt = blacklist.find(sourceAddr);
    if (blackListIt != blacklist.end()) {
        EV_INFO << "The sender node " << sourceAddr << " is in our blacklist. Ignoring the Route Request" << endl;
        return;
    }

    // When a node receives a RREQ, it first creates or updates a route to
    // the previous hop without a valid sequence number (see section 6.2).

    IRoute *previousHopRoute = routingTable->findBestMatchingRoute(sourceAddr);

    if (!previousHopRoute || previousHopRoute->getSource() != this) {
        // create without valid sequence number
        previousHopRoute = createRoute(sourceAddr, sourceAddr, 1, false, rreq->getOriginatorSeqNum(), true, simTime() + activeRouteTimeout);
    }
    else
        updateRoutingTable(previousHopRoute, sourceAddr, 1, false, rreq->getOriginatorSeqNum(), true, simTime() + activeRouteTimeout);

    // then checks to determine whether it has received a RREQ with the same
    // Originator IP Address and RREQ ID within at least the last PATH_DISCOVERY_TIME.
    // If such a RREQ has been received, the node silently discards the newly received RREQ.

    RreqIdentifier rreqIdentifier(rreq->getOriginatorAddr(), rreq->getRreqId());
    auto checkRREQArrivalTime = rreqsArrivalTime.find(rreqIdentifier);
    if (checkRREQArrivalTime != rreqsArrivalTime.end() && simTime() - checkRREQArrivalTime->second <= pathDiscoveryTime) {
        EV_WARN << "The same packet has arrived within PATH_DISCOVERY_TIME= " << pathDiscoveryTime << ". Discarding it" << endl;
        return;
    }

    // update or create
    rreqsArrivalTime[rreqIdentifier] = simTime();

    // First, it first increments the hop count value in the RREQ by one, to
    // account for the new hop through the intermediate node.

    rreq->setHopCount(rreq->getHopCount() + 1);

    // Then the node searches for a reverse route to the Originator IP Address (see
    // section 6.2), using longest-prefix matching.

    IRoute *reverseRoute = routingTable->findBestMatchingRoute(rreq->getOriginatorAddr());

    // If need be, the route is created, or updated using the Originator Sequence Number from the
    // RREQ in its routing table.
    //
    // When the reverse route is created or updated, the following actions on
    // the route are also carried out:
    //
    //   1. the Originator Sequence Number from the RREQ is compared to the
    //      corresponding destination sequence number in the route table entry
    //      and copied if greater than the existing value there
    //
    //   2. the valid sequence number field is set to true;
    //
    //   3. the next hop in the routing table becomes the node from which the
    //      RREQ was received (it is obtained from the source IP address in
    //      the IP header and is often not equal to the Originator IP Address
    //      field in the RREQ message);
    //
    //   4. the hop count is copied from the Hop Count in the RREQ message;
    //
    //   Whenever a RREQ message is received, the Lifetime of the reverse
    //   route entry for the Originator IP address is set to be the maximum of
    //   (ExistingLifetime, MinimalLifetime), where
    //
    //   MinimalLifetime = (current time + 2*NET_TRAVERSAL_TIME - 2*HopCount*NODE_TRAVERSAL_TIME).

    unsigned int hopCount = rreq->getHopCount();
    simtime_t minimalLifeTime = simTime() + 2 * netTraversalTime - 2 * hopCount * nodeTraversalTime;
    simtime_t newLifeTime = std::max(simTime(), minimalLifeTime);
    int rreqSeqNum = rreq->getOriginatorSeqNum();
    if (!reverseRoute || reverseRoute->getSource() != this) {    // create
        // This reverse route will be needed if the node receives a RREP back to the
        // node that originated the RREQ (identified by the Originator IP Address).
        reverseRoute = createRoute(rreq->getOriginatorAddr(), sourceAddr, hopCount, true, rreqSeqNum, true, newLifeTime);
    }
    else {
        AodvRouteData *routeData = check_and_cast<AodvRouteData *>(reverseRoute->getProtocolData());
        int routeSeqNum = routeData->getDestSeqNum();
        int newSeqNum = std::max(routeSeqNum, rreqSeqNum);
        int newHopCount = rreq->getHopCount();    // Note: already incremented by 1.
        int routeHopCount = reverseRoute->getMetric();
        // The route is only updated if the new sequence number is either
        //
        //   (i)       higher than the destination sequence number in the route
        //             table, or
        //
        //   (ii)      the sequence numbers are equal, but the hop count (of the
        //             new information) plus one, is smaller than the existing hop
        //             count in the routing table, or
        //
        //   (iii)     the sequence number is unknown.

        if (rreqSeqNum > routeSeqNum ||
            (rreqSeqNum == routeSeqNum && newHopCount < routeHopCount) ||
            rreq->getUnknownSeqNumFlag())
        {
            updateRoutingTable(reverseRoute, sourceAddr, hopCount, true, newSeqNum, true, newLifeTime);
        }
    }

    // A node generates a RREP if either:
    //
    // (i)       it is itself the destination, or
    //
    // (ii)      it has an active route to the destination, the destination
    //           sequence number in the node's existing route table entry
    //           for the destination is valid and greater than or equal to
    //           the Destination Sequence Number of the RREQ (comparison
    //           using signed 32-bit arithmetic), and the "destination only"
    //           ('D') flag is NOT set.

    // After a node receives a RREQ and responds with a RREP, it discards
    // the RREQ.  If the RREQ has the 'G' flag set, and the intermediate
    // node returns a RREP to the originating node, it MUST also unicast a
    // gratuitous RREP to the destination node.

    IRoute *destRoute = routingTable->findBestMatchingRoute(rreq->getDestAddr());
    AodvRouteData *destRouteData = destRoute ? dynamic_cast<AodvRouteData *>(destRoute->getProtocolData()) : nullptr;

    // check (i)
    if (rreq->getDestAddr() == getSelfIPAddress()) {
        EV_INFO << "I am the destination node for which the route was requested" << endl;

        // create RREP
        auto rrep = createRREP(rreq, destRoute, reverseRoute, sourceAddr);

        // send to the originator
        sendRREP(rrep, rreq->getOriginatorAddr(), 255);

        return;    // discard RREQ, in this case, we do not forward it.
    }

    // check (ii)
    if (destRouteData && destRouteData->isActive() && destRouteData->hasValidDestNum() &&
        destRouteData->getDestSeqNum() >= rreq->getDestSeqNum())
    {
        EV_INFO << "I am an intermediate node who has information about a route to " << rreq->getDestAddr() << endl;

        if (destRoute->getNextHopAsGeneric() == sourceAddr) {
            EV_WARN << "This RREP would make a loop. Dropping it" << endl;
            return;
        }

        // we respond to the RREQ, if the D (destination only) flag is not set
        if(!rreq->getDestOnlyFlag())
        {
            // create RREP
            auto rrep = createRREP(rreq, destRoute, reverseRoute, sourceAddr);

            // send to the originator
            sendRREP(rrep, rreq->getOriginatorAddr(), 255);

            if (rreq->getGratuitousRREPFlag()) {
                // The gratuitous RREP is then sent to the next hop along the path to
                // the destination node, just as if the destination node had already
                // issued a RREQ for the originating node and this RREP was produced in
                // response to that (fictitious) RREQ.

                IRoute *originatorRoute = routingTable->findBestMatchingRoute(rreq->getOriginatorAddr());
                auto grrep = createGratuitousRREP(rreq, originatorRoute);
                sendGRREP(grrep, rreq->getDestAddr(), 100);
            }

            return;    // discard RREQ, in this case, we also do not forward it.
        }
        else
            EV_INFO << "The originator indicated that only the destination may respond to this RREQ (D flag is set). Forwarding ..." << endl;
    }

    // If a node does not generate a RREP (following the processing rules in
    // section 6.6), and if the incoming IP header has TTL larger than 1,
    // the node updates and broadcasts the RREQ to address 255.255.255.255
    // on each of its configured interfaces (see section 6.14).  To update
    // the RREQ, the TTL or hop limit field in the outgoing IP header is
    // decreased by one, and the Hop Count field in the RREQ message is
    // incremented by one, to account for the new hop through the
    // intermediate node. (!) Lastly, the Destination Sequence number for the
    // requested destination is set to the maximum of the corresponding
    // value received in the RREQ message, and the destination sequence
    // value currently maintained by the node for the requested destination.
    // However, the forwarding node MUST NOT modify its maintained value for
    // the destination sequence number, even if the value received in the
    // incoming RREQ is larger than the value currently maintained by the
    // forwarding node.

    if (timeToLive > 0 && (simTime() > rebootTime + deletePeriod || rebootTime == 0)) {
        if (destRouteData)
            rreq->setDestSeqNum(std::max(destRouteData->getDestSeqNum(), rreq->getDestSeqNum()));
        rreq->setUnknownSeqNumFlag(false);

        auto outgoingRREQ = dynamicPtrCast<Rreq>(rreq->dupShared());
        forwardRREQ(outgoingRREQ, timeToLive);
    }
    else
        EV_WARN << "Can't forward the RREQ because of its small (< 1) TTL: " << timeToLive << " or the AODV reboot has not completed yet (" << rebootTime << ")" << endl;
}
