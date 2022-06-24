package ca.uhn.fhir.jpa.starter.interceptors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.InterceptorAdapter;

public class JWTAuthenticationInterceptor extends InterceptorAdapter {

	@Override
	public boolean incomingRequestPostProcessed(RequestDetails theRequestDetails, HttpServletRequest theRequest,
			HttpServletResponse theResponse) throws AuthenticationException {

		// Don't worry about metadata requests
		if (theRequestDetails.getRestOperationType().equals(RestOperationTypeEnum.METADATA)) {
			return true;
		}

		// Create the auth
		String authHeader = theRequestDetails.getHeader("Authorization");
		if (authHeader != null) {
			try {

				String token = TokenVerifier.getTokenFromHeader(authHeader);
				return !token.trim().equals("");

			} catch (Exception e) {
				System.out.println("JWT Exception: " + e);
				throw new AuthenticationException("Invalid JWT");
			}
		}

		throw new AuthenticationException("Missing JWT");
	}
}