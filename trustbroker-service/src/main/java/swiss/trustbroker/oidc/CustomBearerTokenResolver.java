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

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;

@Slf4j
@AllArgsConstructor
public class CustomBearerTokenResolver implements BearerTokenResolver {

    private final DefaultBearerTokenResolver defaultBearerTokenResolver;

    private final RelyingPartyDefinitions relyingPartyDefinitions;

    private final TrustBrokerProperties trustBrokerProperties;

    @Override
    public String resolve(HttpServletRequest request) {
        var tokenFromBody = request.getParameter(OAuth2ParameterNames.ACCESS_TOKEN);
        if (tokenFromBody == null) {
            return defaultBearerTokenResolver.resolve(request);
        }

        String clientId = OidcUtil.getClaimFromJwtToken(tokenFromBody, OidcUtil.OIDC_AUTHORIZED_PARTY);
        if (clientId == null) {
            clientId = OidcUtil.getClaimFromJwtToken(tokenFromBody, OidcUtil.OIDC_AUDIENCE);
        }

        if (clientId != null) {
            Optional<OidcClient> oidcClientConfigById = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
            if (oidcClientConfigById.isPresent()) {
                var allowFormBearerToken = oidcClientConfigById.get().getOidcSecurityPolicies().getAllowFormBearerToken();
                if (Boolean.TRUE.equals(allowFormBearerToken)) {
                    defaultBearerTokenResolver.setAllowFormEncodedBodyParameter(true);
                    return defaultBearerTokenResolver.resolve(request);
                }
            }
        }

        log.error("The requested token in form body in not allowed for client={}. " +
				"HINT: To enabled it, set Client.OidcSecurityPolicies.allowFormBearerToken", clientId);
        BearerTokenError error = BearerTokenErrors.invalidRequest("Invalid request");
        throw new OAuth2AuthenticationException(error);
    }
}
