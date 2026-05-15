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

package swiss.trustbroker.saml.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.saml.dto.ResponseData;

@Slf4j
public class SamlValidationUtil {

	private SamlValidationUtil() {
	}

	public static void validateRelayState(ResponseData<?> responseData) {
		var relayState = responseData.getRelayState();
		if (StringUtils.isEmpty(relayState)) {
			var response = responseData.getResponse();
			throw new RequestDeniedException(String.format("Relay state '%s' of response id='%s' is null/empty",
					relayState, response != null ? response.getID() : null));
		}
	}

	public static void validateResponse(ResponseData<?> responseData) {
		if (responseData.getResponse() == null) {
			throw new RequestDeniedException(String.format("Missing response for relayState='%s'", responseData.getRelayState()));
		}
	}

	public static void validateProfileRequestId(String profileRequestId) {
		if (StringUtils.isEmpty(profileRequestId)) {
			throw new RequestDeniedException(String.format("ID of profile request is null/empty: '%s", profileRequestId));
		}
	}

	public static boolean validateProtocolRestrictions(CounterParty counterParty, SamlBinding actualBinding,
			HttpServletRequest httpRequest, TrustBrokerProperties trustBrokerProperties, boolean tryOnly) {
		if (RelyingPartySetupUtil.isPartyDisabled(counterParty, httpRequest, trustBrokerProperties.getNetwork())) {
			ExceptionUtil.logOrThrow(String.format("%s=%s disabled",
					counterParty.getClass().getSimpleName(), counterParty.getId()),
					tryOnly, TechnicalException::new);
			return false;
		}
		// SAML is also used internally for OIDC
		if (!counterParty.isSamlEnabled(trustBrokerProperties.getSaml().isEnabled())
				&& !counterParty.isOidcEnabled(trustBrokerProperties.getOidc().isEnabled())) {
			ExceptionUtil.logOrThrow(String.format("%s issuerId=%s does not allow SAML",
					counterParty.getClass().getSimpleName(), counterParty.getId()),
					tryOnly, RequestDeniedException::new);
			return false;

		}
		if (!counterParty.isValidInboundBinding(actualBinding, trustBrokerProperties.getSaml().getSamlBindings())) {
			ExceptionUtil.logOrThrow(String.format("%s issuerId=%s does not support inbound binding=%s",
					counterParty.getClass().getSimpleName(), counterParty.getId(), actualBinding),
					tryOnly, RequestDeniedException::new);
			return false;
		}
		return true;
	}
}
