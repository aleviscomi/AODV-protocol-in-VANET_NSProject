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

#ifndef __VANETPROJECT_SECUREAODVBLACKHOLE_H_
#define __VANETPROJECT_SECUREAODVBLACKHOLE_H_

#include "/home/veins/workspace.omnetpp/NetworkProjectVanet/src/blackhole/blackhole_mitigation/secure_aodv_car/SecureAodv.h"

using namespace inet;
using namespace aodv;

/**
 * TODO - Generated class
 */
class SecureAodvBlackhole : public SecureAodv
{
    public:
    SecureAodvBlackhole();
        virtual ~SecureAodvBlackhole();
    protected:
        void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) override;
        Result ensureRouteForDatagram(Packet *datagram) override;
        const Ptr<SecureRrep> createFakeSRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr);
};

#endif
