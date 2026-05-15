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

import java.time.Instant;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.OidcClient;

@AllArgsConstructor
@Slf4j
public final class CustomJwtTimestampValidator implements OAuth2TokenValidator<Jwt> {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private final OidcClient oidcClient;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Assert.notNull(token, "token cannot be null");

		long now = Instant.now().toEpochMilli();
		var oidcSecurityPolicies = oidcClient.getOidcSecurityPolicies();
		var trustBrokerPropertiesSecurity = trustBrokerProperties.getSecurity();

		var tokenIat = token.getIssuedAt();
		var iat = tokenIat != null ? Date.from(tokenIat) : null;
		OidcValidator.validIat(oidcSecurityPolicies.getClientAssertionMaxAgeSec(), oidcClient.getId(), iat, now, ERROR_URI);

		var tokenExpirationTime = token.getExpiresAt();
		var expirationTime = tokenExpirationTime != null ? Date.from(tokenExpirationTime) : null;
		var clientAssertionNotOnOrAfterToleranceSec = oidcSecurityPolicies.getClientAssertionNotOnOrAfterToleranceSec();
		long notOnOrAfterToleranceSec = clientAssertionNotOnOrAfterToleranceSec != null ? clientAssertionNotOnOrAfterToleranceSec : trustBrokerPropertiesSecurity.getNotOnOrAfterToleranceSec();
		if (!OidcValidator.validNotOnOrAfter(expirationTime, now, notOnOrAfterToleranceSec) ||
		!OidcValidator.validExpirationLifeTime(expirationTime, now, oidcSecurityPolicies.getClientAssertionExpirationLifeTimeSec())) {
			OAuth2Error oAuth2Error = createOAuth2Error(String.format("Jwt expired at %s", token.getExpiresAt()));
			return OAuth2TokenValidatorResult.failure(oAuth2Error);
		}

		var tokenNotBefore = token.getNotBefore();
		var notBefore = tokenNotBefore != null ? Date.from(tokenNotBefore) : null;
		Integer clientAssertionNotBeforeToleranceSec = oidcSecurityPolicies.getClientAssertionNotBeforeToleranceSec();
		long notBeforeToleranceSec = clientAssertionNotBeforeToleranceSec != null ? clientAssertionNotBeforeToleranceSec : trustBrokerPropertiesSecurity.getNotBeforeToleranceSec();
		if (!OidcValidator.validNotBefore(notBefore, now, notBeforeToleranceSec)) {
			OAuth2Error oAuth2Error = createOAuth2Error(String.format("Jwt used before %s", token.getNotBefore()));
			return OAuth2TokenValidatorResult.failure(oAuth2Error);
		}
		return OAuth2TokenValidatorResult.success();
	}

	private OAuth2Error createOAuth2Error(String reason) {
		log.debug(reason);
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason, "https://tools.ietf.org/html/rfc6750#section-3.1");
	}
}
