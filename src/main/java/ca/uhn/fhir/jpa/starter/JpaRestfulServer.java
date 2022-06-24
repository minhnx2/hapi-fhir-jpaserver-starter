package ca.uhn.fhir.jpa.starter;

import java.util.Collection;

import javax.servlet.ServletException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.WebApplicationContext;

import ca.uhn.fhir.rest.server.interceptor.IServerInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;

@Import(AppProperties.class)
public class JpaRestfulServer extends BaseJpaRestfulServer {

  @Autowired
  AppProperties appProperties;

  private static final long serialVersionUID = 1L;

  public JpaRestfulServer() {
    super();
  }

  @Override
  protected void initialize() throws ServletException {
    super.initialize();

    Collection<IServerInterceptor> interceptorBeans = myApplicationContext.getBeansOfType(IServerInterceptor.class)
        .values();
    for (IServerInterceptor interceptor : interceptorBeans) {
      this.registerInterceptor(interceptor);
    }

    Collection<AuthorizationInterceptor> authInterceptorBeans = myApplicationContext
        .getBeansOfType(AuthorizationInterceptor.class).values();
    for (AuthorizationInterceptor interceptor : authInterceptorBeans) {
      this.registerInterceptor(interceptor);
    }
  }
}
