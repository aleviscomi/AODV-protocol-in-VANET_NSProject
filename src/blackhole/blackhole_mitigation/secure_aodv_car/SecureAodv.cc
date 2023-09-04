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

#include "../secure_aodv_car/SecureAodv.h"

#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.cc"
#include "inet/common/ModuleAccess.h"


#include <string>
#include <random>
#include <algorithm>
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/oids.h"
#include "cryptopp/asn.h"
#include "cryptopp/queue.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/eccrypto.h"

using namespace std;
using namespace CryptoPP;

using namespace inet;
using namespace aodv;

Define_Module(SecureAodv);

SecureAodv::SecureAodv() {

}

SecureAodv::~SecureAodv() {

}

void SecureAodv::genRSAKey() {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privkey;
    privkey.GenerateRandomWithKeySize(rng, 2048);

    RSA::PublicKey pubkey(privkey);

    string addrPrivKey = "/home/veins/workspace.omnetpp/NetworkProjectVanet/simulations/keys/privateRSAKeys/" + to_string(host->getId());
    string addrPubKey = "/home/veins/workspace.omnetpp/NetworkProjectVanet/simulations/keys/publicRSAKeys/" + to_string(host->getId());


    Base64Encoder privkeysink(new FileSink(addrPrivKey.c_str()));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();


    Base64Encoder pubkeysink(new FileSink(addrPubKey.c_str()));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();
}

string SecureAodv::signRSA(string dsn) {
    AutoSeededRandomPool rng;
    string addrPrivKey = "/home/veins/workspace.omnetpp/NetworkProjectVanet/simulations/keys/privateRSAKeys/" + to_string(host->getId());

    //Read private key
    CryptoPP::ByteQueue bytes;
    FileSource file(addrPrivKey.c_str(), true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();

    RSA::PrivateKey privateKey;
    privateKey.Load(bytes);

    //Sign message
    RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
    byte* signature = new byte[privkey.SignatureLength()];
    size_t length = privkey.SignMessage(
        rng,
        (byte const*) dsn.c_str(),
        dsn.length(),
        signature);

    string signatureStr(reinterpret_cast<const char *>(signature), length);
    string messageBase64;
    StringSource ss(signatureStr, true, new Base64Encoder(new StringSink(messageBase64)));

    return messageBase64;
}

bool SecureAodv::verifyRSA(const Ptr<const SecureRrep>& srrep) {
    CryptoPP::ByteQueue bytes;
    L3Address srcAddr = srrep->getDestAddr();
    string idPubKey = to_string(L3AddressResolver().findHostWithAddress(srcAddr)->getId());

    string addrPubKey = "/home/veins/workspace.omnetpp/NetworkProjectVanet/simulations/keys/publicRSAKeys/" + idPubKey;

    FileSource file(addrPubKey.c_str(), true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PublicKey publicKey;
    publicKey.Load(bytes);

    string signature;
    StringSource ss(srrep->getCipheredDSN(), true, new Base64Decoder(new StringSink(signature)));

    RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
    string dsn = std::to_string(srrep->getDestSeqNum());

    return verifier.VerifyMessage((const byte*) dsn.c_str(), dsn.length(), (const byte*) signature.c_str(), signature.length());
}

void SecureAodv::initialize(int stage) {
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
        if (useHelloMessages)
            helloMsgTimer = new cMessage("HelloMsgTimer");

        genRSAKey();
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        networkProtocol->registerHook(0, this);
        host->subscribe(linkBrokenSignal, this);
        usingIpv6 = (routingTable->getRouterIdAsGeneric().getType() == L3Address::IPv6);
    }
}

void SecureAodv::checkIpVersionAndPacketTypeCompatibility(AodvControlPacketType packetType) {
    switch (packetType) {
        case RREQ:
        case RREP:
        case SRREP:
        case RERR:
        case RREPACK:
            if (usingIpv6)
                throw cRuntimeError("AODV Control Packet arrived with non-IPv6 packet type %d, but AODV configured for IPv6 routing", packetType);
            break;

        case RREQ_IPv6:
        case RREP_IPv6:
        case RERR_IPv6:
        case RREPACK_IPv6:
            if (!usingIpv6)
                throw cRuntimeError("AODV Control Packet arrived with IPv6 packet type %d, but AODV configured for non-IPv6 routing", packetType);
            break;

        default:
            throw cRuntimeError("AODV Control Packet arrived with undefined packet type: %d", packetType);
    }
}

void SecureAodv::processPacket(Packet *packet) {
    L3Address sourceAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    // KLUDGE: I added this -1 after TTL decrement has been moved in Ipv4
    unsigned int arrivalPacketTTL = packet->getTag<HopLimitInd>()->getHopLimit() - 1;
    const auto& aodvPacket = packet->popAtFront<AodvControlPacket>();
    //TODO aodvPacket->copyTags(*udpPacket);

    auto packetType = aodvPacket->getPacketType();
    switch (packetType) {
        case RREQ:
        case RREQ_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleRREQ(CHK(dynamicPtrCast<Rreq>(aodvPacket->dupShared())), sourceAddr, arrivalPacketTTL);
            delete packet;
            return;

        case RREP:
        case RREP_IPv6:
            EV_WARN << "This is an AODV Route Reply, but we are using a Secure AODV Protocol!!!" << endl;
            delete packet;
            return;

        case SRREP:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleSRREP(CHK(dynamicPtrCast<SecureRrep>(aodvPacket->dupShared())), sourceAddr);
            delete packet;
            return;

        case RERR:
        case RERR_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleRERR(CHK(dynamicPtrCast<const Rerr>(aodvPacket)), sourceAddr);
            delete packet;
            return;

        case RREPACK:
        case RREPACK_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleRREPACK(CHK(dynamicPtrCast<const RrepAck>(aodvPacket)), sourceAddr);
            delete packet;
            return;

        default:
            throw cRuntimeError("AODV Control Packet arrived with undefined packet type: %d", packetType);
    }
}

void SecureAodv::handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) {
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
    AodvRouteData *destRouteData = destRoute ? dynamic_cast<AodvRouteData *>(destRoute->getProtocolData()) : nullptr;

    // check (i)
    if (rreq->getDestAddr() == getSelfIPAddress()) {
        EV_INFO << "I am the destination node for which the route was requested" << endl;

        // create SRREP
        auto srrep = createSRREP(rreq, destRoute, reverseRoute, sourceAddr);

        // send to the originator
        sendSRREP(srrep, rreq->getOriginatorAddr(), 255);

        return;    // discard RREQ, in this case, we do not forward it.
    }

    // check (ii)
    if (destRouteData && destRouteData->isActive() && destRouteData->hasValidDestNum() &&
        destRouteData->getDestSeqNum() >= rreq->getDestSeqNum())
    {
        EV_INFO << "I am an intermediate node who has information about a route to " << rreq->getDestAddr() << endl;

        if (destRoute->getNextHopAsGeneric() == sourceAddr) {
            EV_WARN << "This SRREP would make a loop. Dropping it" << endl;
            return;
        }

        // we respond to the RREQ, if the D (destination only) flag is not set
        if(!rreq->getDestOnlyFlag())
        {
            // create RREP
            auto srrep = createSRREP(rreq, destRoute, reverseRoute, sourceAddr);

            // send to the originator
            sendSRREP(srrep, rreq->getOriginatorAddr(), 255);

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

const Ptr<SecureRrep> SecureAodv::createSRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr) {
    auto srrep = makeShared<SecureRrep>(); // TODO: "AODV-SRREP");
    srrep->setPacketType(SRREP);
    srrep->setChunkLength(usingIpv6 ? B(44) : B(20));

    // When generating a RREP message, a node copies the Destination IP
    // Address and the Originator Sequence Number from the RREQ message into
    // the corresponding fields in the RREP message.

    srrep->setDestAddr(rreq->getDestAddr());

    // OriginatorAddr = The IP address of the node which originated the RREQ
    // for which the route is supplied.
    srrep->setOriginatorAddr(rreq->getOriginatorAddr());

    // Processing is slightly different, depending on whether the node is
    // itself the requested destination (see section 6.6.1), or instead
    // if it is an intermediate node with an fresh enough route to the destination
    // (see section 6.6.2).

    if (rreq->getDestAddr() == getSelfIPAddress()) {    // node is itself the requested destination
        // 6.6.1. Route Reply Generation by the Destination

        // If the generating node is the destination itself, it MUST increment
        // its own sequence number by one if the sequence number in the RREQ
        // packet is equal to that incremented value.

        if (!rreq->getUnknownSeqNumFlag() && sequenceNum + 1 == rreq->getDestSeqNum())
            sequenceNum++;

        // The destination node places its (perhaps newly incremented)
        // sequence number into the Destination Sequence Number field of
        // the RREP,
        srrep->setDestSeqNum(sequenceNum);

        // and enters the value zero in the Hop Count field
        // of the RREP.
        srrep->setHopCount(0);

        // The destination node copies the value MY_ROUTE_TIMEOUT
        // into the Lifetime field of the RREP.
        srrep->setLifeTime(myRouteTimeout.trunc(SIMTIME_MS));

        srrep->setCipheredDSN(signRSA(to_string(sequenceNum)).c_str());
    }
    else {    // intermediate node
        // 6.6.2. Route Reply Generation by an Intermediate Node

        // it copies its known sequence number for the destination into
        // the Destination Sequence Number field in the RREP message.
        AodvRouteData *destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
        AodvRouteData *originatorRouteData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());
        srrep->setDestSeqNum(destRouteData->getDestSeqNum());

        // The intermediate node updates the forward route entry by placing the
        // last hop node (from which it received the RREQ, as indicated by the
        // source IP address field in the IP header) into the precursor list for
        // the forward route entry -- i.e., the entry for the Destination IP
        // Address.
        destRouteData->addPrecursor(lastHopAddr);

        // The intermediate node also updates its route table entry
        // for the node originating the RREQ by placing the next hop towards the
        // destination in the precursor list for the reverse route entry --
        // i.e., the entry for the Originator IP Address field of the RREQ
        // message data.

        originatorRouteData->addPrecursor(destRoute->getNextHopAsGeneric());

        // The intermediate node places its distance in hops from the
        // destination (indicated by the hop count in the routing table)
        // Hop Count field in the RREP.

        srrep->setHopCount(destRoute->getMetric());

        // The Lifetime field of the RREP is calculated by subtracting the
        // current time from the expiration time in its route table entry.

        srrep->setLifeTime((destRouteData->getLifeTime() - simTime()).trunc(SIMTIME_MS));

        srrep->setCipheredDSN(signatures[L3AddressResolver().findHostWithAddress(rreq->getDestAddr())->getId()].c_str());
    }

    return srrep;
}

void SecureAodv::handleSRREP(const Ptr<SecureRrep>& srrep, const L3Address& sourceAddr) {
    // 6.7. Receiving and Forwarding Route Replies

    EV_INFO << "AODV Secure Route Reply arrived with source addr: " << sourceAddr << " originator addr: " << srrep->getOriginatorAddr()
            << " destination addr: " << srrep->getDestAddr() << endl;

    if (srrep->getOriginatorAddr().isUnspecified()) {
        EV_INFO << "This Secure Route Reply is a Hello Message" << endl;
        //handleHelloMessage(srrep);
        return;
    }

    // Controllo la firma
    if(!verifyRSA(srrep)) {
        EV_WARN << "This SRREP hasn't a valid DSN signature!!! Discarding it." << endl;
        return;
    }
    EV_INFO << "This SRREP has a valid DSN signature!!!" << endl;

    // When a node receives a RREP message, it searches (using longest-
    // prefix matching) for a route to the previous hop.

    // If needed, a route is created for the previous hop,
    // but without a valid sequence number (see section 6.2)

    IRoute *previousHopRoute = routingTable->findBestMatchingRoute(sourceAddr);

    if (!previousHopRoute || previousHopRoute->getSource() != this) {
        // create without valid sequence number
        previousHopRoute = createRoute(sourceAddr, sourceAddr, 1, false, srrep->getDestSeqNum(), true, simTime() + activeRouteTimeout);
    }
    else
        updateRoutingTable(previousHopRoute, sourceAddr, 1, false, srrep->getDestSeqNum(), true, simTime() + activeRouteTimeout);

    // Next, the node then increments the hop count value in the RREP by one,
    // to account for the new hop through the intermediate node
    unsigned int newHopCount = srrep->getHopCount() + 1;
    srrep->setHopCount(newHopCount);

    // Then the forward route for this destination is created if it does not
    // already exist.

    IRoute *destRoute = routingTable->findBestMatchingRoute(srrep->getDestAddr());
    AodvRouteData *destRouteData = nullptr;
    simtime_t lifeTime = srrep->getLifeTime();
    unsigned int destSeqNum = srrep->getDestSeqNum();

    if (destRoute && destRoute->getSource() == this) {    // already exists
        destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
        // Upon comparison, the existing entry is updated only in the following circumstances:

        // (i) the sequence number in the routing table is marked as
        //     invalid in route table entry.

        if (!destRouteData->hasValidDestNum()) {
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);

            // If the route table entry to the destination is created or updated,
            // then the following actions occur:
            //
            // -  the route is marked as active,
            //
            // -  the destination sequence number is marked as valid,
            //
            // -  the next hop in the route entry is assigned to be the node from
            //    which the RREP is received, which is indicated by the source IP
            //    address field in the IP header,
            //
            // -  the hop count is set to the value of the New Hop Count,
            //
            // -  the expiry time is set to the current time plus the value of the
            //    Lifetime in the RREP message,
            //
            // -  and the destination sequence number is the Destination Sequence
            //    Number in the RREP message.
        }
        // (ii) the Destination Sequence Number in the RREP is greater than
        //      the node's copy of the destination sequence number and the
        //      known value is valid, or
        else if (destSeqNum > destRouteData->getDestSeqNum()) {
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
        }
        else {
            // (iii) the sequence numbers are the same, but the route is
            //       marked as inactive, or
            if (destSeqNum == destRouteData->getDestSeqNum() && !destRouteData->isActive()) {
                updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            }
            // (iv) the sequence numbers are the same, and the New Hop Count is
            //      smaller than the hop count in route table entry.
            else if (destSeqNum == destRouteData->getDestSeqNum() && newHopCount < (unsigned int)destRoute->getMetric()) {
                updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            }
        }
    }
    else {    // create forward route for the destination: this path will be used by the originator to send data packets
        destRoute = createRoute(srrep->getDestAddr(), sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
        destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
    }

    // If the current node is not the node indicated by the Originator IP
    // Address in the RREP message AND a forward route has been created or
    // updated as described above, the node consults its route table entry
    // for the originating node to determine the next hop for the RREP
    // packet, and then forwards the RREP towards the originator using the
    // information in that route table entry.

    IRoute *originatorRoute = routingTable->findBestMatchingRoute(srrep->getOriginatorAddr());
    if (getSelfIPAddress() != srrep->getOriginatorAddr()) {
        // If a node forwards a RREP over a link that is likely to have errors or
        // be unidirectional, the node SHOULD set the 'A' flag to require that the
        // recipient of the RREP acknowledge receipt of the RREP by sending a RREP-ACK
        // message back (see section 6.8).

        if (originatorRoute && originatorRoute->getSource() == this) {
            AodvRouteData *originatorRouteData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());

            // Also, at each node the (reverse) route used to forward a
            // RREP has its lifetime changed to be the maximum of (existing-
            // lifetime, (current time + ACTIVE_ROUTE_TIMEOUT).

            simtime_t existingLifeTime = originatorRouteData->getLifeTime();
            originatorRouteData->setLifeTime(std::max(simTime() + activeRouteTimeout, existingLifeTime));

            if (simTime() > rebootTime + deletePeriod || rebootTime == 0) {
                // If a node forwards a RREP over a link that is likely to have errors
                // or be unidirectional, the node SHOULD set the 'A' flag to require that
                // the recipient of the RREP acknowledge receipt of the RREP by sending a
                // RREP-ACK message back (see section 6.8).

                if (srrep->getAckRequiredFlag()) {
                    auto rrepACK = createRREPACK();
                    sendRREPACK(rrepACK, sourceAddr);
                    srrep->setAckRequiredFlag(false);
                }

                // When any node transmits a RREP, the precursor list for the
                // corresponding destination node is updated by adding to it
                // the next hop node to which the RREP is forwarded.

                destRouteData->addPrecursor(originatorRoute->getNextHopAsGeneric());

                // Finally, the precursor list for the next hop towards the
                // destination is updated to contain the next hop towards the
                // source (originator).

                IRoute *nextHopToDestRoute = routingTable->findBestMatchingRoute(destRoute->getNextHopAsGeneric());
                if (nextHopToDestRoute && nextHopToDestRoute->getSource() == this) {
                    AodvRouteData *nextHopToDestRouteData = check_and_cast<AodvRouteData *>(nextHopToDestRoute->getProtocolData());
                    nextHopToDestRouteData->addPrecursor(originatorRoute->getNextHopAsGeneric());
                }
                auto outgoingSRREP = dynamicPtrCast<SecureRrep>(srrep->dupShared());
                forwardSRREP(outgoingSRREP, originatorRoute->getNextHopAsGeneric(), 100);
            }
        }
        else
            EV_ERROR << "Reverse route doesn't exist. Dropping the SRREP message" << endl;
    }
    else {
        if (hasOngoingRouteDiscovery(srrep->getDestAddr())) {
            EV_INFO << "The Secure Route Reply has arrived for our Route Request to node " << srrep->getDestAddr() << endl;
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            completeRouteDiscovery(srrep->getDestAddr());
        }
    }
}

void SecureAodv::sendSRREP(const Ptr<SecureRrep>& srrep, const L3Address& destAddr, unsigned int timeToLive) {
    EV_INFO << "Sending Secure Route Reply to " << destAddr << endl;

    // When any node transmits a RREP, the precursor list for the
    // corresponding destination node is updated by adding to it
    // the next hop node to which the RREP is forwarded.

    IRoute *destRoute = routingTable->findBestMatchingRoute(destAddr);
    const L3Address& nextHop = destRoute->getNextHopAsGeneric();
    AodvRouteData *destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
    destRouteData->addPrecursor(nextHop);

    // The node we received the Route Request for is our neighbor,
    // it is probably an unidirectional link
    if (destRoute->getMetric() == 1) {
        // It is possible that a RREP transmission may fail, especially if the
        // RREQ transmission triggering the RREP occurs over a unidirectional
        // link.

        srrep->setAckRequiredFlag(true);

        // when a node detects that its transmission of a RREP message has failed,
        // it remembers the next-hop of the failed RREP in a "blacklist" set.

        failedNextHop = nextHop;

        if (rrepAckTimer->isScheduled())
            cancelEvent(rrepAckTimer);

        scheduleAt(simTime() + nextHopWait, rrepAckTimer);
    }
    sendAODVPacket(srrep, nextHop, timeToLive, 0);
}

void SecureAodv::forwardSRREP(const Ptr<SecureRrep>& srrep, const L3Address& destAddr, unsigned int timeToLive) {
    EV_INFO << "Forwarding the Secure Route Reply to the node " << srrep->getOriginatorAddr() << " which originated the Route Request" << endl;

    // RFC 5148:
    // When a node forwards a message, it SHOULD be jittered by delaying it
    // by a random duration.  This delay SHOULD be generated uniformly in an
    // interval between zero and MAXJITTER.
    sendAODVPacket(srrep, destAddr, 100, *jitterPar);
}
