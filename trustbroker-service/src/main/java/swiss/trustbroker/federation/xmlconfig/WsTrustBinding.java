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

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.EnumUtils;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;

/**
 * Bindings for WS-Trust
 *
 * @since 1.14.0
 * @see <a href="https://docs.oasis-open.org/ws-sx/ws-trust/v1.3/ws-trust.html">WS-Trust 1.3</a>
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum WsTrustBinding {
	/**
	 * WS-Trust RST ISSUE.
	 */
	ISSUE(WSTrustConstants.WSA_ACTION_RST_ISSUE),
	/**
	 * WS-Trust RST RENEW.
	 */
	RENEW(WSTrustConstants.WSA_ACTION_RST_RENEW),;

	private String action;

	// throws RequestDeniedException if not found
	public static WsTrustBinding of(String protocolBinding) {
		if (protocolBinding == null) {
			return null;
		}
		for (var binding : values()) {
			if (binding.action.equals(protocolBinding)) {
				return binding;
			}
		}
		throw new RequestDeniedException(String.format("Unsupported WsTrustBinding protocolBinding=%s", protocolBinding));
	}

	public static WsTrustBinding ofNameOrValue(String protocolBinding) {
		var binding = EnumUtils.getEnum(WsTrustBinding.class, protocolBinding);
		if (binding == null) {
			binding = of(protocolBinding);
		}
		return binding;
	}

}
