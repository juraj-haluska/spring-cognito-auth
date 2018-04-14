package hello.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "auth")
public class JwtAuthFilter extends OncePerRequestFilter {

    private String AUTH_HEADER_STRING = "Authorization";
    private String ISSUER = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_sFKzVGbR9";
    private String KEY_STORE_PATH = "/.well-known/jwks.json";

    // should cache keys
    RemoteJWKSet remoteJWKSet;

    public JwtAuthFilter() throws MalformedURLException {
        this.remoteJWKSet = new RemoteJWKSet(new URL(ISSUER + KEY_STORE_PATH));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest req,
            HttpServletResponse res,
            FilterChain chain) throws IOException, ServletException {

        String header = req.getHeader(AUTH_HEADER_STRING).replace("Bearer ","");

        logger.info(header);

        try {
            JWT jwt = JWTParser.parse(header);

            String iss = jwt.getJWTClaimsSet().getIssuer();
            logger.info(iss);

            // check if issues is our user pool
            if (ISSUER.equals(jwt.getJWTClaimsSet().getIssuer())) {

                JWSKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, remoteJWKSet);

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(keySelector);

                // check token
                JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);

                // process roles (gropus in cognito)
                List<String> groups = (List<String>) claimsSet.getClaim("cognito:groups");

                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("student"));

                groups.forEach(s -> {
                    logger.info(s);
                    switch (s) {
                        case "instructor": {
                            authorities.add(new SimpleGrantedAuthority("ROLE_INSTRUCTOR"));
                        } break;
                        case "student": {
                            authorities.add(new SimpleGrantedAuthority("ROLE_STUDENT"));
                        }
                    }
                });

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        claimsSet,
                        null,
                        authorities
                );

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }

        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (BadJOSEException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            // in case that header is null
            e.printStackTrace();
        }

        chain.doFilter(req, res);
    }
}
