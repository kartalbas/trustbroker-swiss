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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.net.MalformedURLException;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.saml.dto.SignatureContext;

class RedirectUrlBuilderTest {

	@Test
	void buildQueryStringTest() throws MalformedURLException {
		var context = SignatureContext.forRedirectBinding("/test"
				+"?RelayState=%7B%7c%7D%7e%7F"
				+"&SAMLRequest=abcde%2f"
				+"&Signature=any"
				+"&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256"
				+"&other=%aa");
		var expectedQueryString =
				"SAMLRequest=abcde%2f" // position 1, mandatory
				+"&RelayState=%7b%7c%7d%7e%7f" // position 2, optional (mixed hex not supported)
				+"&SigAlg=http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256"; // position 3, mandatory
		var builder = new RedirectUrlBuilder(context);
		assertThat(builder.buildQueryString(), is(expectedQueryString));
	}

}
