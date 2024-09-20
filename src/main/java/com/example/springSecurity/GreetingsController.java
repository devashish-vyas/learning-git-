package com.example.springSecurity;



import com.example.springSecurity.jwt.JwtUtils;
import com.example.springSecurity.jwt.LoginRequest;
import com.example.springSecurity.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
@RestController
public class GreetingsController {

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String greet(){
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String user(){
        return "User";
    }

    @GetMapping("/admin")
    public String admin(){
        return "Admin";
    }

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/signIn")
    public ResponseEntity<Object> authenticateUser(@RequestBody LoginRequest loginRequest){

        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword()));
        } catch (AuthenticationException ex) {
            Map<String, Object> mp = new HashMap<>();
            mp.put("message", "Bad Crediantial");
            mp.put("status", false);
            return new ResponseEntity<Object>(mp, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername(), roles);

        return ResponseEntity.ok(response);

    }
}
