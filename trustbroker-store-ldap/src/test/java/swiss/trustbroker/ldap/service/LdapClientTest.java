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

package swiss.trustbroker.ldap.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.naming.directory.SearchControls;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.saml.dto.CpResponse;

@SpringBootTest(classes = { LdapClient.class })
class LdapClientTest {

	private static final String SUBJECT_NAME_ID = "subjectNameId";

	@MockitoBean
	LdapTemplate ldapTemplate;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@Autowired
	LdapClient ldapClient;

	@Test
	void getLdapAttributesTest() {
		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		var idmRequests = givemIdmLookup(base);

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		var ldapResult = ldapClient.search(rpConfig, cpResponse, idmRequests, unprocessedAttributes);
		assertEquals(2, ldapResult.size());
	}

	private static IdmQuery givemIdmLookup(String base) {
		return IdmQuery.builder().store("LDAP").name("LDAP").appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build();
	}

	private static List<Map<String, List<String>>> givenLdapAttributes() {
		List<Map<String, List<String>>> ldapAttributes = new ArrayList<>();
		Map<String, List<String>> attribute1 = new HashMap<>();
		attribute1.put("uid", List.of("uid1"));
		attribute1.put("mail", List.of("mail1"));
		ldapAttributes.add(attribute1);
		Map<String, List<String>> attribute2 = new HashMap<>();
		attribute2.put("uid", List.of("uid2"));
		attribute2.put("mail", List.of("mail2"));
		ldapAttributes.add(attribute2);
		return ldapAttributes;
	}

	@Test
	void getQueryBaseTest() {
		var rpConfig = RelyingParty.builder().id("relyingPartyId").build();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapClient.getQueryBase(null, rpConfig));
		assertThat(ex.getInternalMessage(), containsString("Missing subResource"));

		assertEquals("subresource", ldapClient.getQueryBase("subresource", rpConfig));
	}

	@Test
	void queryFilterFormatterTest() {
		var cpResponse = givenCpResponse();
		var ldapConfig = new LdapStoreConfig(true, "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapClient.queryFilterFormatter(null, cpResponse, "RP_ID", unprocessedAttributes));
		assertThat(ex.getInternalMessage(), containsString("AppFilter is null or empty"));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))", cpResponse, "RP_ID", unprocessedAttributes));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute})))", cpResponse, "RP_ID", unprocessedAttributes));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(id=UNDEF)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:uid})(id=${unknownAttr})))", cpResponse, "RP_ID", unprocessedAttributes));

		assertEquals("(&amp;(app=app1)(|(uid=user\\5c123)(attribute=\\2a)(value=\\29\\28test=\\2a)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:escape})(attribute=${wildcard})"
						+ "(value=${injection})))", cpResponse, "RP_ID", unprocessedAttributes));
	}

	@Test
	void isChainedQueryTest() {
		assertTrue(ldapClient.isChainedQuery("IDM:uid"));
		assertFalse(ldapClient.isChainedQuery("uid"));
	}

	@Test
	void getPlaceholderValueTest() {
		var cpResponse = givenCpResponse();
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		assertEquals(List.of("NAME_ID"), ldapClient.getPlaceholderValues(SUBJECT_NAME_ID, cpResponse, unprocessedAttributes));
		assertEquals(List.of("uid"), ldapClient.getPlaceholderValues("IDM:uid", cpResponse, unprocessedAttributes));
		assertEquals(List.of("attribute"), ldapClient.getPlaceholderValues("attribute", cpResponse, unprocessedAttributes));
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(new Definition("uid"), List.of("uid"));
		attributeValueMap.put(new Definition("attribute"), List.of("attribute"));
		attributeValueMap.put(new Definition("wildcard"), List.of("*"));
		attributeValueMap.put(new Definition("escape"), List.of("user\\123"));
		attributeValueMap.put(new Definition("injection"), List.of(")(test=*"));
		return CpResponse.builder()
						 .userDetails(attributeValueMap)
						 .attributes(attributeValueMap)
						 .nameId("NAME_ID")
						 .build();
	}
}
