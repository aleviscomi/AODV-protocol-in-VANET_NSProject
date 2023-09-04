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

#include "SecureAodvBlackhole.h"

#include "inet/networklayer/common/L3Tools.h"

using namespace inet;
using namespace aodv;

Define_Module(SecureAodvBlackhole);

SecureAodvBlackhole::SecureAodvBlackhole() {

}

SecureAodvBlackhole::~SecureAodvBlackhole() {

}

void SecureAodvBlackhole::handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive)
{
    EV_INFO << "AODV Route Request arrived with source addr: " << sourceAddr << " originator addr: " << rreq->getOriginatorAddr()
                << " destination addr: " << rreq->getDestAddr() << endl;

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

    EV_INFO << "I am the destination node for which the route was requested" << endl;

    // create SRREP
    auto srrep = createFakeSRREP(rreq, destRoute, reverseRoute, sourceAddr);

    // send to the originator
    sendSRREP(srrep, rreq->getOriginatorAddr(), 255);

}

const Ptr<SecureRrep> SecureAodvBlackhole::createFakeSRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr)
{
    auto srrep = makeShared<SecureRrep>(); // TODO: "AODV-RREP");
    srrep->setPacketType(SRREP);
    srrep->setChunkLength(usingIpv6 ? B(44) : B(20));

    srrep->setDestAddr(rreq->getDestAddr());
    srrep->setOriginatorAddr(rreq->getOriginatorAddr());

    srrep->setDestSeqNum(999999);
    //srrep->setCipheredDSN(null);
    srrep->setHopCount(0);
    srrep->setLifeTime(myRouteTimeout.trunc(SIMTIME_MS));

    return srrep;
}

SecureAodvBlackhole::Result SecureAodvBlackhole::ensureRouteForDatagram(Packet *datagram) {
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& destAddr = networkHeader->getDestinationAddress();
    const L3Address& sourceAddr = networkHeader->getSourceAddress();

    if (destAddr.isBroadcast() || routingTable->isLocalAddress(destAddr) || destAddr.isMulticast())
        return ACCEPT;
    else {
        EV_INFO << "Finding route for source " << sourceAddr << " with destination " << destAddr << endl;
        IRoute *route = routingTable->findBestMatchingRoute(destAddr);
        AodvRouteData *routeData = route ? dynamic_cast<AodvRouteData *>(route->getProtocolData()) : nullptr;
        bool isActive = routeData && routeData->isActive();
        if (isActive && !route->getNextHopAsGeneric().isUnspecified()) {
            EV_INFO << "Active route found: " << route << endl;

            // Each time a route is used to forward a data packet, its Active Route
            // Lifetime field of the source, destination and the next hop on the
            // path to the destination is updated to be no less than the current
            // time plus ACTIVE_ROUTE_TIMEOUT.

            updateValidRouteLifeTime(destAddr, simTime() + activeRouteTimeout);
            updateValidRouteLifeTime(route->getNextHopAsGeneric(), simTime() + activeRouteTimeout);

            return ACCEPT;
        }
        else {
            bool isInactive = routeData && !routeData->isActive();
            EV_INFO << (isInactive ? "Inactive" : "Missing") << " route for destination " << destAddr << endl;
            return DROP;
        }
    }
}
