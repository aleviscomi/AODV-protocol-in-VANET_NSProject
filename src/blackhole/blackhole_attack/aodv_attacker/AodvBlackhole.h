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

#ifndef __VANETPROJECT_AODVBLACKHOLE_H_
#define __VANETPROJECT_AODVBLACKHOLE_H_

#include "inet/routing/aodv/Aodv.h"

using namespace inet;
using namespace aodv;

class AodvBlackhole : public Aodv
{
    public:
        AodvBlackhole();
        virtual ~AodvBlackhole();
    protected:
        void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) override;
        Result ensureRouteForDatagram(Packet *datagram) override;
        const Ptr<Rrep> createFakeRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr);
};

#endif // ifndef __INET_AODVBLACKHOLE_H

