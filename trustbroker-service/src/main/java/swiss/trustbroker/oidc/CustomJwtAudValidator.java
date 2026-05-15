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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.util.OidcUtil;

@Slf4j
public final class CustomJwtAudValidator implements OAuth2TokenValidator<Jwt> {

	private final OAuth2Error error;

	public CustomJwtAudValidator() {
		this.error = new OAuth2Error("invalid_token", "The " + OidcUtil.OIDC_AUDIENCE + " claim is not valid", "https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Assert.notNull(token, "token cannot be null");
		List<String> audiences= token.getAudience();
		if (containsAudience(audiences)) {
			return OAuth2TokenValidatorResult.success();
		}
		else {
			log.error("Invalid audience={} in client_assertion in token with sub={}", audiences, token.getSubject());
			return OAuth2TokenValidatorResult.failure(this.error);
		}
	}

	private static boolean containsAudience(List<String> audienceClaim) {
		if (audienceClaim == null || CollectionUtils.isEmpty(audienceClaim)) {
			return false;
		}
		List<String> validAudienceList = getAudience();
		for (String audience : audienceClaim) {
			if (validAudienceList.contains(audience)) {
				return true;
			}
		}
		log.debug("Invalid audience={} expected={}", audienceClaim, validAudienceList);
		return false;
	}

	private static List<String> getAudience() {
		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		if (!StringUtils.hasText(authorizationServerContext.getIssuer())) {
			return Collections.emptyList();
		}
		List<String> audience = new ArrayList<>();
		audience.add(authorizationServerContext.getIssuer());

		return audience;
	}
}
