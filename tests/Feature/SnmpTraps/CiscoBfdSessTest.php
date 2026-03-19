<?php

/**
 * CiscoBfdSessTest.php
 *
 * Tests CiscoBfdSessDown and CiscoBfdSessUp traps from Cisco devices.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * @link       https://www.librenms.org
 *
 * @copyright  2026 MTex
 * @author     MTex <git AT mtex.pt>
 */

namespace LibreNMS\Tests\Feature\SnmpTraps;

use App\Models\Device;
use App\Models\Port;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use LibreNMS\Enum\Severity;
use LibreNMS\Tests\Traits\RequiresDatabase;

final class CiscoBfdSessTest extends SnmpTrapTestCase
{
    use RequiresDatabase;
    use DatabaseTransactions;

    public function testCiscoBfdSessDownTrap(): void
    {
        $device = Device::factory()->create();
        $port = Port::factory()->make([
            'ifAdminStatus' => 'up',
            'ifOperStatus' => 'up',
            'ifDescr' => 'GigabitEthernet0/1',
        ]);
        $device->ports()->save($port);

        $warning = "Snmptrap ciscoBfdSessDown: Could not find port at ifIndex $port->ifIndex for device: $device->hostname";
        \Log::shouldReceive('warning')->never()->with($warning);

        $this->assertTrapLogsMessage("$device->hostname
UDP: [$device->ip]:64610->[127.0.0.1]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 17:58:59.10
SNMPv2-MIB::snmpTrapOID.0 CISCO-IETF-BFD-MIB::ciscoBfdSessDown
IF-MIB::ifIndex.$port->ifIndex $port->ifIndex
CISCO-IETF-BFD-MIB::ciscoBfdSessDiag.$port->ifIndex controlDetectionTimeExpired",
            "Cisco BFD Down Trap: $port->ifDescr. Reason: controlDetectionTimeExpired",
            'Could not handle CiscoBfdSessDown trap',
            [Severity::Error, 'interface', $port->port_id],
            $device,
        );
    }

    public function testCiscoBfdSessUpTrap(): void
    {
        $device = Device::factory()->create();
        $port = Port::factory()->make([
            'ifAdminStatus' => 'up',
            'ifOperStatus' => 'up',
            'ifDescr' => 'GigabitEthernet0/1',
        ]);
        $device->ports()->save($port);

        $warning = "Snmptrap ciscoBfdSessUp: Could not find port at ifIndex $port->ifIndex for device: $device->hostname";
        \Log::shouldReceive('warning')->never()->with($warning);

        $this->assertTrapLogsMessage("$device->hostname
UDP: [$device->ip]:64610->[127.0.0.1]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 17:58:59.10
SNMPv2-MIB::snmpTrapOID.0 CISCO-IETF-BFD-MIB::ciscoBfdSessUp
IF-MIB::ifIndex.$port->ifIndex $port->ifIndex
CISCO-IETF-BFD-MIB::ciscoBfdSessDiag.$port->ifIndex noDiagnostic",
            "Cisco BFD Up Trap: $port->ifDescr. Reason: noDiagnostic",
            'Could not handle CiscoBfdSessUp trap',
            [Severity::Ok, 'interface', $port->port_id],
            $device,
        );
    }

    public function testCiscoBfdSessDownTrapWithoutMatchingPort(): void
    {
        $device = Device::factory()->create();
        $ifIndex = 9999;

        \Log::shouldReceive('warning')->once()->with(
            "Snmptrap ciscoBfdSessDown: Could not find port at ifIndex $ifIndex for device: $device->hostname"
        );

        $this->assertTrapLogsMessage("$device->hostname
UDP: [$device->ip]:64610->[127.0.0.1]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 17:58:59.10
SNMPv2-MIB::snmpTrapOID.0 CISCO-IETF-BFD-MIB::ciscoBfdSessDown
IF-MIB::ifIndex.$ifIndex $ifIndex
CISCO-IETF-BFD-MIB::ciscoBfdSessDiag.$ifIndex controlDetectionTimeExpired",
            "BFD Session Down (ifIndex: $ifIndex). Motivo: controlDetectionTimeExpired",
            'Could not handle CiscoBfdSessDown trap without matching port',
            [Severity::Error],
            $device,
        );
    }

    public function testCiscoBfdSessUpTrapWithoutMatchingPort(): void
    {
        $device = Device::factory()->create();
        $ifIndex = 9999;

        \Log::shouldReceive('warning')->once()->with(
            "Snmptrap ciscoBfdSessUp: Could not find port at ifIndex $ifIndex for device: $device->hostname"
        );

        $this->assertTrapLogsMessage("$device->hostname
UDP: [$device->ip]:64610->[127.0.0.1]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 17:58:59.10
SNMPv2-MIB::snmpTrapOID.0 CISCO-IETF-BFD-MIB::ciscoBfdSessUp
IF-MIB::ifIndex.$ifIndex $ifIndex
CISCO-IETF-BFD-MIB::ciscoBfdSessDiag.$ifIndex noDiagnostic",
            "BFD Session Up (ifIndex: $ifIndex). Motivo: noDiagnostic",
            'Could not handle CiscoBfdSessUp trap without matching port',
            [Severity::Ok],
            $device,
        );
    }
}
