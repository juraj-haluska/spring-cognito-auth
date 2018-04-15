package hello;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@RestController
public class ProtectedController {

    @RequestMapping("/instructor")
    @PreAuthorize("hasRole('ROLE_INSTRUCTOR')")
    public String helloInstructor(Authentication authentication) {

        JWTClaimsSet claims = (JWTClaimsSet) authentication.getPrincipal();
        String email = (String) claims.getClaim("email");

        return "Hello instructor " + email + "!";
    }

    @RequestMapping("/student")
    @PreAuthorize("hasAnyRole('ROLE_STUDENT', 'ROLE_INSTRUCTOR')")
    public String helloStudent(Authentication authentication) {

        JWTClaimsSet claims = (JWTClaimsSet) authentication.getPrincipal();
        List<String> groups = (List<String>) claims.getClaim("cognito:groups");

        return "Hello " + groups.get(0) + "!";
    }

    @RequestMapping("/any")
    public String helloWorld() {
        return "Hello world!";
    }
}