<?php

/**
 * CiscoBfdSessDown.php
 *
 * Handler for BFD session down traps (Cisco).
 * This handler processes the ciscoBfdSessDown event
 *
 * -
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
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

namespace LibreNMS\Snmptrap\Handlers;

use App\Models\Device;
use LibreNMS\Enum\Severity;
use LibreNMS\Interfaces\SnmptrapHandler;
use LibreNMS\Snmptrap\Trap;
use Log;

class CiscoBfdSessDown implements SnmptrapHandler
{
    /**
     * Handle snmptrap ciscoBfdSessDown.
     *
     * @param  Device  $device
     * @param  Trap  $trap
     * @return void
     */
    public function handle(Device $device, Trap $trap)
    {
        // 1. Search for the exact OID containing 'IF-MIB::ifIndex'
        $ifIndex = $trap->getOidData($trap->findOid('IF-MIB::ifIndex'));

        // 2. Search for the exact OID of the diagnosis
        $diag = $trap->getOidData($trap->findOid('CISCO-IETF-BFD-MIB::ciscoBfdSessDiag')) ?: 'unknown';

        // Try to find the corresponding port in the system
        $port = null;
        if ($ifIndex) {
            $port = $device->ports()->where('ifIndex', $ifIndex)->first();
        }

        if (! $port) {
            // Log if the port is not found (useful for troubleshooting)
            Log::warning("Snmptrap ciscoBfdSessDown: Could not find port at ifIndex $ifIndex for device: " . $device->hostname);

            // log the Trap in the device's Eventlog (without associating a specific port)
            $trap->log("BFD Session Down (ifIndex: $ifIndex). Motivo: $diag", Severity::Error);

            return;
        }

        // Build the message for a known port
        $message = "Cisco BFD Down Trap: $port->ifDescr. Reason: $diag";

        // Log the Trap in the Eventlog directly associated with the interface (port_id)
        $trap->log($message, Severity::Error, 'interface', $port->port_id);
    }
}
