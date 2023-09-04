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

#ifndef __VANETPROJECT_SECUREAODVFLOODING_H_
#define __VANETPROJECT_SECUREAODVFLOODING_H_

#include "inet/routing/aodv/Aodv.h"
#include <map>

using namespace inet;
using namespace std;
using namespace aodv;

class SecureAodvFlooding : public Aodv
{
    protected:
        map<string, int> antiFloodingMap;
        double antiFloodingTimeout = 0;
        double antiFloodingLimit = 0;
        int rreqCountMitigation = 0;
        bool isDynamic = false;
        cMessage *clearAntiFloodingMap = nullptr;
        cMessage *rreqRateTimer = nullptr;
    public:
        SecureAodvFlooding();
        virtual ~SecureAodvFlooding();
    protected:
        void initialize(int stage) override;
        void handleMessageWhenUp(cMessage *msg) override;
        void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive) override;
};

#endif // ifndef __VANETPROJECT_SECUREAODVFLOODING_H_

