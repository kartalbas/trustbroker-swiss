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

package swiss.trustbroker.oidc;

import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

@AllArgsConstructor
@Slf4j
public class CustomJwtClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final JwtDecoder jwtDecoder;

	@Override
	public JwtDecoder createDecoder(RegisteredClient registeredClient) {
		return jwtDecoderFactory(jwtDecoder).createDecoder(registeredClient);
	}

	private JwtDecoderFactory<RegisteredClient> jwtDecoderFactory(JwtDecoder jwtDecoder) {
		if (jwtDecoder instanceof NimbusJwtDecoder nimbusJwtDecoder) {
			return (RegisteredClient registeredClient) -> {
				nimbusJwtDecoder.setJwtValidator(jwtAssertionValidator(registeredClient));
				return nimbusJwtDecoder;
			};
		}
		log.warn("Unknown JwtDecoder type: {}", jwtDecoder);
		throw new TechnicalException("Unknown JwtDecoder type: " + jwtDecoder);
	}

	private OAuth2TokenValidator<Jwt> jwtAssertionValidator(RegisteredClient registeredClient) {
		String clientId = registeredClient.getClientId();
		var clientConfig = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
		if (clientConfig.isEmpty()) {
			throw new TechnicalException("Missing OIDC client configuration");
		}
		return new DelegatingOAuth2TokenValidator<>(
				new JwtClaimValidator<>(JwtClaimNames.ISS, clientId::equals),
				new JwtClaimValidator<>(JwtClaimNames.SUB, clientId::equals),
				new CustomJwtAudValidator(),
				new JwtClaimValidator<>(JwtClaimNames.EXP, Objects::nonNull),
				new CustomJwtTimestampValidator(clientConfig.get(), trustBrokerProperties));
	}
}
