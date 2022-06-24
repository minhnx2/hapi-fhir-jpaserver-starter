package ca.uhn.fhir.jpa.starter;

import org.springframework.beans.factory.annotation.Autowire;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import ca.uhn.fhir.jpa.config.r4.JpaR4Config;
import ca.uhn.fhir.jpa.starter.annotations.OnR4Condition;
import ca.uhn.fhir.jpa.starter.cql.StarterCqlR4Config;
import ca.uhn.fhir.jpa.starter.interceptors.JWTAuthenticationInterceptor;
import ca.uhn.fhir.jpa.starter.interceptors.JWTAuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.IServerInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IRuleApplier;

@Configuration
@Conditional(OnR4Condition.class)
@Import({
		StarterJpaConfig.class,
		JpaR4Config.class,
		StarterCqlR4Config.class,
		ElasticsearchConfig.class
})
public class FhirServerConfigR4 {

	@Bean(autowire = Autowire.BY_TYPE)
	@ConditionalOnProperty(name = "smart.jwt_auth_enabled", havingValue = "true")
	public IServerInterceptor authenticationInterceptor() {
		System.out.println("------------------- JWT AuthN Enabled -------------------");
		JWTAuthenticationInterceptor retVal = new JWTAuthenticationInterceptor();
		return retVal;
	}

	@Bean(autowire = Autowire.BY_TYPE)
	@ConditionalOnProperty(name = "smart.jwt_auth_enabled", havingValue = "true")
	public IRuleApplier authorizationInterceptor() {
		System.out.println("------------------- JWT AuthZ Enabled -------------------");
		JWTAuthorizationInterceptor retVal = new JWTAuthorizationInterceptor();
		return retVal;
	}
}
