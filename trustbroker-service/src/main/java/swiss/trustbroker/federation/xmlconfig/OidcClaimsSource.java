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

import jakarta.xml.bind.annotation.XmlEnumValue;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Source for OIDC CP claims.
 *
 * @since 1.10.0
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@Getter
public enum OidcClaimsSource {

	/**
	 * Use claims from ID token.
	 * <br/>
	 * Allows override of claims and subject of other sources by default.
	 */
	@XmlEnumValue("id_token")
	ID_TOKEN(false, true, true),

	/**
	 * Use claims from userinfo endpoint.
	 * <br/>
	 * Allows override of claims <strong>other than subject</strong> of other sources by default.
	 */
	@XmlEnumValue("userinfo")
	USERINFO(true, false, false),

	/**
	 * Use claims from userinfo endpoint, accepting signed JWT token responses only.
	 * <br/>
	 * Allows override of claims and subject of other sources by default.
	 *
	 * @since 1.13.0
	 */
	@XmlEnumValue("userinfo_jwt")
	USERINFO_JWT(true, true, true);

	private final boolean claimsFromUserinfo;

	private final boolean allowClaimsOverride;

	private final boolean allowSubjectOverride;
}
