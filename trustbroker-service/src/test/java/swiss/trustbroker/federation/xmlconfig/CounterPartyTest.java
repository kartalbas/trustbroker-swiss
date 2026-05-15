/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.federation.xmlconfig;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class CounterPartyTest {

	@Test
	void isWsTrustEnabled() {
		// disabled:
		var cp = ClaimsParty.builder().id("cp1").build();
		assertFalse(cp.isWsTrustEnabled(true, null));
		// disabled with disabled base:
		var rp = ClaimsParty.builder().id("rp1").build();
		assertFalse(rp.isWsTrustEnabled(true, cp));
		// enabled:
		cp.setWsTrust(new WsTrust());
		assertTrue(cp.isWsTrustEnabled(true, null));
		// enabled base not default:
		assertFalse(rp.isWsTrustEnabled(true, cp));
		// globally disabled:
		assertFalse(cp.isWsTrustEnabled(false, null));
		// enabled base default:
		cp.getWsTrust().setCounterPartyDefault(true);
		assertTrue(rp.isWsTrustEnabled(true, cp));
		// globally disabled:
		assertFalse(rp.isWsTrustEnabled(false, cp));
		// override base:
		rp.setWsTrust(new WsTrust());
		rp.getWsTrust().setEnabled(false);
		assertFalse(rp.isWsTrustEnabled(true, cp));
	}

	@Test
	void isValidInboundBinding() {
		List<WsTrustBinding> all = List.of(WsTrustBinding.RENEW, WsTrustBinding.ISSUE);
		List<WsTrustBinding> renew = List.of(WsTrustBinding.RENEW);
		// disabled:
		var cp = ClaimsParty.builder().id("cp1").build();
		assertFalse(cp.isValidInboundBinding(WsTrustBinding.ISSUE, null, null));
		// disabled with default:
		assertFalse(cp.isValidInboundBinding(WsTrustBinding.ISSUE, renew, null));
		assertTrue(cp.isValidInboundBinding(WsTrustBinding.ISSUE, all, null));
		// disabled with disabled base:
		var rp = ClaimsParty.builder().id("rp1").build();
		assertFalse(rp.isValidInboundBinding(WsTrustBinding.ISSUE, null, cp));
		assertTrue(rp.isValidInboundBinding(WsTrustBinding.ISSUE, all, cp));
		// enabled:
		cp.setWsTrust(new WsTrust());
		cp.getWsTrust().setSupportedBindings(renew);
		assertFalse(cp.isValidInboundBinding(WsTrustBinding.ISSUE, null, null));
		cp.getWsTrust().setSupportedBindings(all);
		assertTrue(cp.isValidInboundBinding(WsTrustBinding.ISSUE, null, null));
		// enabled base not default:
		assertFalse(rp.isValidInboundBinding(WsTrustBinding.ISSUE, null, cp));
		// enabled base default:
		cp.getWsTrust().setCounterPartyDefault(true);
		assertTrue(rp.isValidInboundBinding(WsTrustBinding.ISSUE, null, cp));
		// override base:
		rp.setWsTrust(new WsTrust());
		rp.getWsTrust().setSupportedBindings(renew);
		assertFalse(rp.isValidInboundBinding(WsTrustBinding.ISSUE, null, cp));
	}
}
