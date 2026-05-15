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

import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.profileselection.service.LdapIdentitySelectionService;
import swiss.trustbroker.util.IdmAttributeUtil;

@Service
@Slf4j
@Order(LOWEST_PRECEDENCE)
@AllArgsConstructor
public class LdapService implements IdmQueryService {

	public static final String PROFILE_SEPARATOR = LdapIdentitySelectionService.PROFILE_SEPARATOR;

	private final LdapClient ldapClient;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public Optional<IdmResult> getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback) {
		final var requestedStore = ExternalStores.LDAP.name();
		var ldapStoreConfig = trustBrokerProperties.getLdap();
		if (!ldapStoreConfig.isEnabled() || !hasQueryOfStore(requestedStore, idmRequests, null)) {
			log.trace("Skipping idmService={} for idmRequests={}", ExternalStores.LDAP, idmRequests);
			return Optional.empty();
		}
		var result = getLdapAttributes(relyingPartyConfig, cpResponse, idmRequests);
		log.info("LDAP result: attributeCount={} propertyCount={}", result.getUserDetails().size(), result.getProperties().size());
		return Optional.of(result);
	}

	public IdmResult getLdapAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests) {
		var result = new IdmResult();
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		var attributeCount = 0;
		var querySuccessCount = 0;

		// iterate over all queries skipping all not addressed to store LDAP
		final var requestedStore = ExternalStores.LDAP.name();
		for (var idmQuery : idmRequests.getQueryList()) {
			if (!isQueryOfStore(requestedStore, idmQuery, idmRequests.getStore())) {
				log.trace("Skipping idmService={} for idmQuery={}", ExternalStores.LDAP, idmQuery);
				continue;
			}
			result.getQueriedStores().add(requestedStore);

			var attrs = ldapClient.search(relyingPartyConfig, cpResponse, idmQuery, unprocessedAttributes);

			if (!attrs.isEmpty()) {
				querySuccessCount += 1;
				unprocessedAttributes.addAll(attrs);
			}
		}

		final var profileSelectionProperties = ((RelyingParty) relyingPartyConfig).getProfileSelection();
		List<Map<String, List<String>>> prefixedProfiles = new ArrayList<>();
		if (profileSelectionProperties != null && profileSelectionProperties.isProfileSelectionEnabled() &&
				!ProfileSelectionMode.SILENT.name().equals(profileSelectionProperties.getProfileSelectionMode())) {
			prefixedProfiles = prefixProfileAttributes(relyingPartyConfig, profileSelectionProperties, unprocessedAttributes);
		}
		final var attributes = aggregateAndFindAttributes(prefixedProfiles, relyingPartyConfig);
		result.getUserDetails().putAll(attributes);
		attributeCount += attributes.size();

		if (log.isInfoEnabled()) {
			log.info("IDM result ({}): Called directory with issuer={} nameID={} resultCount={} successCount={}",
					ExternalStores.LDAP.name(), cpResponse.getIssuerId(), cpResponse.getNameId(), attributeCount, querySuccessCount);
		}

		result.setOriginalUserDetailsCount(attributeCount);
		return result;
	}

	List<Map<String, List<String>>> prefixProfileAttributes(RelyingPartyConfig relyingPartyConfig, ProfileSelection profileSelectionProperties, List<Map<String, List<String>>> attrs) {
		final var profileSelector = getProfileSelector(profileSelectionProperties.getProfileSelector(), relyingPartyConfig.getId());
		if (profileSelector == null) {
			throw new TechnicalException(String.format(
					"LDAP ProfileSelection.profileSelector cannot be null or empty for rp=%s. HINT: set RelyingParty.ProfileSelection.profileSelector",  relyingPartyConfig.getId()));
		}
		final var orgSelector = getProfileSelector(profileSelectionProperties.getOrganizationSelector(), relyingPartyConfig.getId());
		final var organizationSelector = profileSelectionProperties.getOrganizationSelector();
		if (!userWithMultiProfiles(attrs, profileSelector) && !userWithMultiProfiles(attrs, orgSelector)) {
			log.debug("No multiprofile found with profileSelector={} and orgSelector={}", profileSelector, orgSelector);
			applySingleProfileN2K(profileSelectionProperties, attrs, profileSelector, organizationSelector);
			return attrs;
		}

		List<Map<String, List<String>>> profiles = new ArrayList<>();
		List<Map<String, List<String>>> organizations = new ArrayList<>();
		getProfilesAndOrgs(attrs, organizationSelector, profileSelector, organizations, profiles);
		log.debug("Total number of profiles={} and organizations={}", profiles.size(), organizations.size());

		for (var profile : profiles) {
			// no such an attribute in LDAP result
			if (profile.get(profileSelector) == null) {
				throw new TechnicalException(String.format("ProfileSelection.profileSelector=%s attributes not found for rpId=%s",
						profileSelector, relyingPartyConfig.getId()));
			}
			String orgId = null;
			var profileSelectorValue = profile.get(profileSelector).getFirst();
			if (organizationSelector != null) {
				// Profiles were split by organization, the organizationSelector only has one element
				orgId = profile.get(organizationSelector).getFirst();
				profileSelectorValue = profileSelectorValue + PROFILE_SEPARATOR + orgId;
				Map<String, List<String>> orgEntry = getOrgEntryByOrgId(organizations, orgId, organizationSelector);
				if (!orgEntry.isEmpty()) {
					// Add addition organization information to the profile
					addAttributesToProfile(profile, orgEntry);
				}
			}
			applyN2K(profileSelectionProperties, profile, profileSelectorValue, orgId);
			prefixValuesWithProfileSelector(profileSelectorValue, profileSelector, profile);
		}

		return profiles;
	}

	private void applySingleProfileN2K(ProfileSelection profileSelectionProperties, List<Map<String, List<String>>> profiles, String profileSelector, String organizationSelector) {
		if (profiles.isEmpty()) {
			return;
		}
		var profileSelectorValue = profiles.getFirst().get(profileSelector) != null ? profiles.getFirst().get(profileSelector).getFirst() : null;
		var orgSelectorValue = profiles.getFirst().get(organizationSelector) != null ? profiles.getFirst().get(organizationSelector).getFirst() : null;
		applyN2K(profileSelectionProperties, profiles.getFirst(), profileSelectorValue, orgSelectorValue);
	}

	private void applyN2K(ProfileSelection profileSelectionProperties, Map<String, List<String>> profile, String profileSelectorValue, String orgId) {
		if (!profileSelectionProperties.isN2kEnabled()) {
			return;
		}
		var n2kSeparator = trustBrokerProperties.getLdap().getN2kSeparator();
		profile.replaceAll((key, values) -> {
			if (values == null) {
				return null;
			}
			return values.stream().map(value -> {
				boolean containsSeparator = value.contains(n2kSeparator);
				boolean containsOrg = orgId != null && value.contains(orgId);
				boolean containsProfile = profileSelectorValue != null && value.contains(profileSelectorValue);
				if (containsSeparator && (containsOrg || containsProfile)) {
					String[] split = value.split(n2kSeparator);
					if (split.length == 2) {
						return split[1];
					}
				}
				return value;
			}).toList();
		});
	}

	private static void getProfilesAndOrgs(List<Map<String, List<String>>> attrs, String organizationSelector, String profileSelector, List<Map<String, List<String>>> organizations, List<Map<String, List<String>>> profiles) {
		if (organizationSelector != null) {
			for (var profile : attrs) {
				if (profile.get(profileSelector) == null) {
					organizations.add(profile);
					continue;
				}
				List<String> orgProfiles = profile.get(organizationSelector);
				if (orgProfiles == null || orgProfiles.isEmpty()) {
					log.warn("Invalid profile. Missing organization entry for profile={}", profile);
				} else {
					log.debug("Splitting profile={} by organizationSelector={}", profile, organizationSelector);
					splitProfileByOrgs(organizationSelector, profiles, profile, orgProfiles);
				}
			}
		}
		else {
			profiles.addAll(attrs);
		}
	}

	private static void splitProfileByOrgs(String organizationSelector, List<Map<String, List<String>>> profiles, Map<String, List<String>> profile, List<String> orgProfiles) {
		for (String orgProfile : orgProfiles) {
			List<String> organizationAttr = new ArrayList<>();
			organizationAttr.add(orgProfile);
			List<String> unselectedOrgs = orgProfiles.stream().filter(org -> !org.equals(orgProfile)).toList();
			Map<String, List<String>> newProfile = profile.entrySet()
														  .stream()
														  .collect(Collectors.toMap(Map.Entry::getKey,
																  e -> e.getValue()
																		.stream()
																		// If data contains orgId -> drop data from different organization
																		.filter(v -> unselectedOrgs.stream().noneMatch(v::contains))
																		.toList()
														  ));
			newProfile.put(organizationSelector, organizationAttr);
			profiles.add(newProfile);
		}
	}

	private void addAttributesToProfile(Map<String, List<String>> profile, Map<String, List<String>> orgEntry) {
		for (var entry : orgEntry.entrySet()) {
			if (!profile.containsKey(entry.getKey())) {
				profile.put(entry.getKey(), entry.getValue());
			}
		}
	}

	private Map<String, List<String>> getOrgEntryByOrgId(List<Map<String, List<String>>> organizations, String orgId, String organizationSelector) {
		List<Map<String, List<String>>> collect = organizations.stream()
															  .filter(orgEntry -> orgEntry.get(organizationSelector) != null && orgEntry.get(organizationSelector).contains(orgId))
															  .toList();
		return collect.isEmpty() ? Collections.emptyMap() : collect.getFirst();
	}

	boolean userWithMultiProfiles(List<Map<String, List<String>>> attrs, String profileSelector) {
		if (profileSelector == null) {
			return false;
		}

		// profileSelector must be a unique attribute in LDAP
		var userProfiles = attrs.stream().filter(attr -> attr.containsKey(profileSelector))
								.flatMap(attr -> attr.get(profileSelector).stream()).collect(Collectors.toSet());
		return userProfiles.size() > 1;
	}

	String getProfileSelector(String profileSelector, String rpId) {
		if (profileSelector != null && !profileSelector.isEmpty()) {
			log.debug("LDAP Profile Selection for rp={}: using profileSelector={}", rpId, profileSelector);
			return profileSelector;
		}
		return null;
	}

	void prefixValuesWithProfileSelector(String profileSelectorValue, String profileSelector, Map<String, List<String>> profile) {
		if (profileSelectorValue == null) {
			log.warn("Profile Selection of LDAP wrongly configured. Missing ProfileSelection.profileSelector={}. HINT: set RelyingParty.ProfileSelection.profileSelector", profileSelector);
			return;
		}

		profile.replaceAll((key, values) -> {
			if (values == null) {
				return null;
			}
			boolean isProfileSelector = key.equals(profileSelector);
			return values.stream().map(value -> isProfileSelector ? profileSelectorValue : profileSelectorValue + PROFILE_SEPARATOR + value).toList();
		});
	}

	private Map<AttributeName, List<String>> aggregateAndFindAttributes(List<Map<String, List<String>>> attrs,
																		RelyingPartyConfig relyingPartyConfig) {
		Map<String, List<String>> aggregatedAttributes = new HashMap<>();

		for (var attrMap : attrs) {
			for (Map.Entry<String, List<String>> entry : attrMap.entrySet()) {
				aggregatedAttributes
						.computeIfAbsent(entry.getKey(), k -> new ArrayList<>())
						.addAll(entry.getValue());
			}
		}

		// a wrong LDAP filter can lead to duplicated attributes in the attributes
		for (Map.Entry<String, List<String>> entry : aggregatedAttributes.entrySet()) {
			var deduplicated = new ArrayList<>(new HashSet<>(entry.getValue()));
			entry.setValue(deduplicated);
		}

		IdmQuery idmQuery = IdmQuery.builder().name(ExternalStores.LDAP.name()).build();
		var attributeSelection = IdmAttributeUtil.getIdmAttributeSelection(relyingPartyConfig, idmQuery);
		return IdmAttributeUtil.getAttributesForQueryResponse(aggregatedAttributes, idmQuery.getName(), attributeSelection);
	}
}
