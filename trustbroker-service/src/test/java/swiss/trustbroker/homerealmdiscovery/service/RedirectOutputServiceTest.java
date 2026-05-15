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

package swiss.trustbroker.homerealmdiscovery.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

@SpringBootTest
@ContextConfiguration(classes = { RedirectOutputService.class })
class RedirectOutputServiceTest {

	private static final String ORIGIN = "https://trustbroker.swiss";

	private static final String CROSS_ORIGIN = "https://localhost:443/path";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private VelocityEngine velocityEngine;

	@Autowired
	private RedirectOutputService redirectOutputService;

	@Test
	void handleRedirectCrossOrigin() {
		mockProperties();
		var request = new MockHttpServletRequest();
		request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_MODE, WebUtil.SEC_FETCH_MODE_CORS);
		var response = new MockHttpServletResponse();

		var result = redirectOutputService.handleRedirect(request, response, CROSS_ORIGIN);
		assertThat(result, is(nullValue()));
		verify(velocityEngine).mergeTemplate(eq(VelocityUtil.VELOCITY_REDIRECT_TEMPLATE_ID), any(), any(), any());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,true",
			"://,null,true", // invalid
			"/api/v1/test,null,false", // relative
			CROSS_ORIGIN + "/api/v1/test,navigate,false", // cross-origin, fetch mode navigate
			CROSS_ORIGIN + "/api/v1/test,null,false", // cross-origin, no fetch mode
			ORIGIN + "/api/v1/test,cors,false" // same origin, absolute, fetch mode cors
	}, nullValues = "null")
	void handleRedirectDirectly(String url, String secFetchMode, boolean expectNull) {
		mockProperties();
		var request = new MockHttpServletRequest();
		if (secFetchMode != null) {
			request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_MODE, secFetchMode);
		}
		var response = new MockHttpServletResponse();
		var expected = expectNull ? null : url;

		var result = redirectOutputService.handleRedirect(request, response, url);
		assertThat(result, is(expected));
		verify(velocityEngine, never()).mergeTemplate(any(), any(), any(), any());
	}

	private void mockProperties() {
		when(trustBrokerProperties.getPerimeterUrl()).thenReturn(ORIGIN + "/api/v1/entry");
	}
}
