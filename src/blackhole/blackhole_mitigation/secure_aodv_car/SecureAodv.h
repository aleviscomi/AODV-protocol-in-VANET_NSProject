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

#ifndef __VANETPROJECT_SECUREAODV_H_
#define __VANETPROJECT_SECUREAODV_H_

#include <string>
#include "inet/routing/aodv/Aodv.h"

using namespace std;
using namespace inet;
using namespace aodv;

class SecureAodv : public Aodv
{
    public:
        map<int, string> signatures;

        SecureAodv();
        virtual ~SecureAodv();
    protected:
        void initialize(int stage) override;

        void checkIpVersionAndPacketTypeCompatibility(AodvControlPacketType packetType) override;
        void processPacket(Packet *packet) override;
        void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) override;

        const Ptr<SecureRrep> createSRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr);
        void handleSRREP(const Ptr<SecureRrep>& srrep, const L3Address& sourceAddr);
        void sendSRREP(const Ptr<SecureRrep>& srrep, const L3Address& destAddr, unsigned int timeToLive);
        void forwardSRREP(const Ptr<SecureRrep>& rrep, const L3Address& destAddr, unsigned int timeToLive);

        void genRSAKey();
        string signRSA(string dsn);
        bool verifyRSA(const Ptr<const SecureRrep>& srrep);
};

#endif
