package hello;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
public class ProtectedController {

    @RequestMapping("/instructor")
    @PreAuthorize("hasRole('ROLE_INSTRUCTOR')")
    public String helloInstructor() {
        return "Hello instructor!";
    }

    @RequestMapping("/student")
    @PreAuthorize("hasRole('ROLE_STUDENT')")
    public String helloStudent() {
        return "Hello student!";
    }

    @RequestMapping("/any")
    public String helloWorld() {
        return "Hello world!";
    }
}