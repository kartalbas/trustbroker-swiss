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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TrustBrokerException;

class OidcTxRequestWrapperTest {

	private OidcTxRequestWrapper mapper;

	private MockHttpServletRequest request;

	@BeforeEach
	void setUp() {
		request = new MockHttpServletRequest();
		mapper = new OidcTxRequestWrapper(request);
	}

	@ParameterizedTest
	@MethodSource
	@SuppressWarnings("unchecked")
	void getServletPath(String path, Object mapped) {
		request.setServletPath(path);
		if (mapped instanceof Class<?> clazz) {
			var ex = assertThrows((Class<TrustBrokerException>) clazz, () -> {
				mapper.getServletPath();
			});
			assertThat(ex.getInternalMessage(), containsString("Invalid access to"));
		}
		else {
			assertThat(mapper.getServletPath(), is(mapped));
		}
	}

	static Object[][] getServletPath() {
		return new Object[][] {
				// not mapped
				{ null, null },
				{ "/", "/" },
				{ "/other/auth", "/other/auth" },
				{ "/realms/any", RequestDeniedException.class },
				{ "/any/realms", "/any/realms" },
				{ "/realms/any/token", "/oauth2/token" },
				{ "/realms/any/protocol/openid-connect/invalid", RequestDeniedException.class },
				{ "/.well-known/openid-configuration", "/.well-known/openid-configuration" },
				{ "/api/v1/openid-configuration", "/.well-known/openid-configuration" },
				{ "/oauth2/auth", RequestDeniedException.class },
				{ "/oauth2/authorize", "/oauth2/authorize" },
				{ "/oauth2/tokenX", RequestDeniedException.class },
				{ "/oauth2/token", "/oauth2/token" },
				// mapped
				{ "/realms/any/protocol/openid-connect/token", "/oauth2/token" },
				{ "/realms/any/protocol/openid-connect/token/introspect", "/oauth2/introspect" },
				{ "/realms/any/protocol/openid-connect/userinfo", "/userinfo" },
				{ "/realms/any/protocol/openid-connect/certs", "/oauth2/jwks" },
				{ "/realms/any/protocol/openid-connect/revoke", "/oauth2/revoke" },
				{ "/realms/any/protocol/openid-connect/logout", "/logout" },
				{ "/realms/any/.well-known", RequestDeniedException.class },
				{ "/realms/any/.well-known/openid-configuration", "/.well-known/openid-configuration" }
		};
	}

}
