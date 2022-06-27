package ca.uhn.fhir.jpa.starter.interceptors;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.Validate;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.util.StringUtil;

@SuppressWarnings("WeakerAccess")
class TokenVerifier {

	/**
	 * Creates a new instance using the RS256 algorithm and issuer and audience
	 * specified in environment
	 *
	 * @throws UnsupportedEncodingException if the current environment doesn't
	 *                                      support UTF-8 encoding.
	 */
	public TokenVerifier() throws UnsupportedEncodingException {
	}

	private JWT decodeToken(String idToken) throws ParseException {
		JWT jwt = JWTParser.parse(idToken);
		return jwt;
	}

	/**
	 * Verify the token and retrieve the authorizations claim, if any, from the JWT.
	 * The key for the
	 * authorizations claim must be specified in environment as 'JWT_AUTHZ_CLAIM'
	 *
	 * @param idToken the id token
	 * @return the authorizations map contained in the token
	 * @throws ParseException
	 * @throws JwkException             if the Public Key Certificate couldn't be
	 *                                  obtained
	 * @throws JWTVerificationException if the Id Token signature was invalid
	 */
	public Map<String, Object> getAuthorizations(String idToken) throws ParseException {
		Validate.notNull(idToken);

		// Decode the JWT
		JWT jwt = decodeToken(idToken);
		// Get the JWT authority details
		String authzClaim = System.getenv("JWT_AUTHZ_CLAIM");
		if (!StringUtils.hasText(authzClaim)) {
			authzClaim = "patient_id";
		}
		Validate.notNull(authzClaim, "JWT_AUTHZ_CLAIM must be set in environment");

		try {
			// Ensure authorizations are included in the JWT
			if (jwt.getJWTClaimsSet() != null) {
				// Get authorizations
				Map<String, Object> authorizations = new HashMap<String, Object>();

				String assignedPatientIds = jwt.getJWTClaimsSet().getClaim(authzClaim) != null
						? jwt.getJWTClaimsSet().getClaim(authzClaim).toString()
						: "";
				ArrayList<String> groups = new ArrayList<>();
				ArrayList<String> patientIds = new ArrayList<>();

				if (jwt.getJWTClaimsSet().getClaim("group") instanceof JSONArray) {
					JSONArray assignedGroups = (JSONArray) jwt.getJWTClaimsSet().getClaim("group");
					for (Object group : assignedGroups.toArray()) {
						groups.add(group.toString());
					}
				}

				if (assignedPatientIds.indexOf(" ") > 0) {
					for (String patientId : assignedPatientIds.split(" ")) {
						patientIds.add(patientId.trim());
					}
				} else {
					patientIds.add(assignedPatientIds);
				}

				authorizations.put("groups", groups);
				authorizations.put("patients", patientIds);

				// Get the JWT admin group
				return authorizations;
			}
		}

		catch (Exception e) {
			System.out.println("JWT Authorization error:" + e);
		}

		return null;
	}

	/**
	 * Verify the token and retrieve the authorizations claim, if any, from the JWT.
	 * The key for the
	 * authorizations claim must be specified in environment as 'JWT_AUTHZ_CLAIM'.
	 * Checks the authorizations
	 * map for membership in the admin group specified in environment as
	 * 'JWT_ADMIN_GROUP'.
	 *
	 * @param idToken the id token
	 * @return whether the token's authorizations includes membership in the admin
	 *         group or not
	 * @throws ParseException
	 * @throws JwkException             if the Public Key Certificate couldn't be
	 *                                  obtained
	 * @throws JWTVerificationException if the Id Token signature was invalid
	 */
	public boolean isAdmin(String idToken) throws ParseException {
		Validate.notNull(idToken);

		String adminGroup = System.getenv("JWT_ADMIN_GROUP");
		if (!StringUtils.hasText(adminGroup)) {
			adminGroup = "fhirAdmin";
		}
		Validate.notNull(adminGroup, "JWT_ADMIN_GROUP must be set in environment");

		// Get the authorizations claim
		Map<String, Object> authorizations = getAuthorizations(idToken);
		if (authorizations != null) {
			try {
				// Ensure groups are added
				if (authorizations.get("groups") != null && authorizations.get("groups") instanceof List) {

					// Get groups and check for the admin group
					ArrayList<String> groups = (ArrayList<String>) authorizations.get("groups");

					return groups.contains(adminGroup);
				}

			} catch (Exception e) {
				System.out.println("JWT Authorization error:" + e);
			}
		}

		return false;
	}

	public static String getTokenFromHeader(String header) {
		Validate.notNull(header, "Authorization header is null");

		// Get the auth header prefix to use
		String prefix = System.getenv("JWT_HEADER_PREFIX");
		if (!StringUtils.hasText(prefix)) {
			prefix = "Bearer";
		}
		Validate.notNull(prefix, "JWT_HEADER_PREFIX must be set in environment");

		// Ensure it ends with a space
		if (!prefix.endsWith(" ")) {
			prefix = prefix + " ";
		}

		// Ensure the token is in the string
		if (header.length() < prefix.length()) {
			throw new AuthenticationException("JWT header is invalid");
		}

		// Get the token from the header.
		return header.substring(prefix.length(), header.length());
	}
}