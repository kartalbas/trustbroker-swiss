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

import java.net.MalformedURLException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.net.URLBuilder;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.util.WebSupport;

@Slf4j
@Getter
public class RedirectUrlBuilder extends URLBuilder {

	private final SignatureContext signatureContext;

	private String signatureAlgorithm;

	public RedirectUrlBuilder(SignatureContext signatureContext) throws MalformedURLException {
		// URLBuilder expects a full URL, we only care about the query params here
		super("https://localhost" + signatureContext.getContext());
		this.signatureContext = signatureContext;
	}

	@Override
	public String buildQueryString() {
		// mandatory: SAMLRequest or SAMLResponse value
		var samlMessageName = SamlIoUtil.SAML_REQUEST_NAME;
		var samlMessage = WebSupport.getUniqueQueryParameter(this, samlMessageName);
		if (samlMessage == null) {
			samlMessageName = SamlIoUtil.SAML_RESPONSE_NAME;
			samlMessage = WebSupport.getUniqueQueryParameter(this, samlMessageName);
		}
		if (samlMessage == null) {
			throw new RequestDeniedException(String.format("Missing message in URL: %s", signatureContext.getContext()));
		}

		// optional: RelayState
		var relayState = WebSupport.getUniqueQueryParameter(this, SamlIoUtil.SAML_RELAY_STATE);

		// mandatory: SigAlg
		signatureAlgorithm = WebSupport.getUniqueQueryParameter(this, SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM);
		if (signatureAlgorithm == null) {
			throw new RequestDeniedException(String.format("%s missing in URL: %s",
					SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM, StringUtil.clean(signatureContext.getContext())));
		}

		// re-construct canonicalized query NOT honoring URL encoding used by client
		var queryParams = this.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<>(samlMessageName, samlMessage));
		if (StringUtils.isNotEmpty(relayState)) {
			queryParams.add(new Pair<>(SamlIoUtil.SAML_RELAY_STATE, relayState));
		}
		queryParams.add(new Pair<>(SamlIoUtil.SAML_REDIRECT_SIGNATURE_ALGORITHM, signatureAlgorithm));
		var queryString = super.buildQueryString();

		// check URL encoding used by client (not honoring uppercase hex codes
		if (queryString != null && requiresRecoding()) {
			queryString = recode(queryString);
		}
		return queryString;
	}

	private boolean requiresRecoding() {
		return signatureContext.getContext().contains("%3a%2f%2f"); // SigAlg always has URL encoded characters
	}

	private String recode(String queryString) {
		var reEncoded = queryString.toCharArray();
		for (int i = 0; i < reEncoded.length; i++) {
			if (reEncoded[i] == '%') {
				reEncoded[i+1] = toLower(reEncoded[i+1]);
				reEncoded[i+2] = toLower(reEncoded[i+2]);
			}
		}
		log.debug("Reverted RFC3986 Case Normalization fromQuery='{}' toQuery='{}'", queryString, reEncoded);
		return new String(reEncoded);
	}

	private char toLower(char ch) {
		return ch >= 'A' && ch <= 'F' ? Character.toLowerCase(ch) : ch;
	}

}
