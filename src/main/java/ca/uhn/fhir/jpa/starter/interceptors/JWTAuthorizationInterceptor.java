package ca.uhn.fhir.jpa.starter.interceptors;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.hl7.fhir.r4.model.IdType;

import ca.uhn.fhir.model.dstu2.resource.Flag;
import ca.uhn.fhir.model.dstu2.resource.Patient;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;

@SuppressWarnings("ConstantConditions")
public class JWTAuthorizationInterceptor extends AuthorizationInterceptor {

	public JWTAuthorizationInterceptor() {
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) throws AuthenticationException {

		// Check for authorization
		String authHeader = theRequestDetails.getHeader("Authorization");
		if (authHeader != null) {
			try {
				// Get the token
				String token = TokenVerifier.getTokenFromHeader(authHeader);

				// Verify it
				TokenVerifier verifier = new TokenVerifier();

				// Determine if the user is an admin
				if (verifier.isAdmin(token)) {

					// Allow anything
					return new RuleBuilder()
							.allowAll().build();

				} else {

					List<String> patientIds = new ArrayList<>();
					Map<String, Object> authorizations = verifier.getAuthorizations(token);

					if (authorizations.get("patients") != null && authorizations.get("patients") instanceof List) {
						for (Object item : (List<Object>) authorizations.get("patients")) {
							patientIds.add(item.toString());
						}
					}

					if (patientIds.size() > 0) {
						// Collect rules for each Patient
						ArrayList<IAuthRule> rules = new ArrayList<>();
						for (int i = 0; i < patientIds.size(); i++) {
							IdType patientId = new IdType("Patient", patientIds.get(i));
							// Add the rules
							rules.addAll(
									new RuleBuilder()
											.allow("Allow user read " + patientId.toString()).read()
											.allResources().inCompartment("Patient", patientId).andThen()
											.allow("Allow user write " + patientId.toString()).write()
											.allResources().inCompartment("Patient", patientId).andThen()
											.build());
						}

						// Deny everything else but metadata
						rules.addAll(new RuleBuilder().allow("Allow user metadata").metadata().andThen()
								.denyAll("Deny user access").build());

						// Allow them to update themselves and any attached component
						return rules;
					} else {
						// Patient does not exist, allow creation of Patient and Flag
						return new RuleBuilder()
								.allow("Allow user create Patient").write().resourcesOfType(Patient.class).withAnyId().andThen()
								.allow("Allow user create Flag").write().resourcesOfType(Flag.class).withAnyId().andThen()
								.allow("Allow user metadata").metadata().andThen()
								.denyAll("Deny user access")
								.build();
					}
				}

			} catch (Exception e) {
				System.out.println("JWT Exception: " + e);
			}
		}

		// User has not tried to authenticate, set rules
		return new RuleBuilder()
				.allow("Only allow anonymous metadata").metadata().build();
	}
}