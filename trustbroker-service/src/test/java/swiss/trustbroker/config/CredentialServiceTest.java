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

package swiss.trustbroker.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class CredentialServiceTest {

	@Test
	void checkAndLoadAbsoluteCert() {
		var signerConfig = dummySIgnerKeystore();
		var service = new CredentialService(null);
		var result = service.checkAndLoadCert(signerConfig, "", "");
		assertThat(	result, notNullValue());
	}

	@Test
	void checkAndLoadRelativeCert() {
		var signerConfig = dummySIgnerKeystore();
		signerConfig.setCertPath(Path.of(signerConfig.getCertPath()).getFileName().toString());
		var config = new TrustBrokerProperties();
		config.setConfigurationPath("/e/t/c");
		var service = new CredentialService(config);
		var exception = assertThrows(TechnicalException.class, () -> {
			service.checkAndLoadCert(signerConfig, "", "testing");
		});
		assertThat(exception.getInternalMessage(), containsString(
				"Failed to load cert='test-keystore.p12' from path='/e/t/c/latest/keystore/' or subPath='testing'"));
	}

	private SignerKeystore dummySIgnerKeystore() {
		var p12Keystore = SamlTestBase.fileFromClassPath(SamlTestBase.X509_RSAENC_P12);
		return SignerKeystore.builder()
								   .certPath(p12Keystore.getAbsolutePath())
								   .password(SamlTestBase.X509_RSAENC_PW)
								   .alias(SamlTestBase.X509_RSAENC_ALIAS)
								   .build();
	}

}
