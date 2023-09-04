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

package networkprojectvanet.simulations.aodv_blackhole;

import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.physicallayer.unitdisk.UnitDiskRadioMedium;
import inet.node.inet.INetworkNode;
import networkprojectvanet.veins_inet.AodvCar;
import networkprojectvanet.blackhole.blackhole_attack.aodv_attacker.AttackerAodvCar;
import networkprojectvanet.veins_inet.VeinsInetManager;
import inet.environment.common.PhysicalEnvironment;
import org.car2x.veins.visualizer.roads.RoadsCanvasVisualizer;
import org.car2x.veins.visualizer.roads.RoadsOsgVisualizer;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;

network Scenario
{
    parameters:
        @display("bgb=4000,3200");
        string normalCarType = default("AodvCar");
        string attackerCarType = default("AttackerAodvCar");
    
    submodules:
        visualizer: IntegratedCanvasVisualizer {
            @display("p=38,200");
        }
        radioMedium: UnitDiskRadioMedium {//Ieee80211ScalarRadioMedium;
            @display("p=38,600");
        }
        manager: VeinsInetManager {
            @display("p=38,1000");
        }
        normal_car[0]: <normalCarType> like INetworkNode;
        attacker_car[0]: <attackerCarType> like INetworkNode;
        //physicalEnvironment: PhysicalEnvironment;
        roadsCanvasVisualizer: RoadsCanvasVisualizer {
            @display("p=38,1400");
        }
}
