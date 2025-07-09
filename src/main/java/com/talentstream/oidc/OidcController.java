package com.talentstream.oidc;

import com.talentstream.service.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.*;

@RestController
@RequestMapping("/oidc")
public class OidcController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthCodeService authCodeService;

    // 1. Moodle starts login here
    @GetMapping("/authorize")
    public void authorize(
            @RequestParam String client_id,
            @RequestParam String redirect_uri,
            @RequestParam String response_type,
            @RequestParam(required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        String token = extractJwtFromHeaderOrCookie(request);
        String email = null;

        if (token != null) {
            try {
                email = jwtUtil.extractUsername(token);
            } catch (Exception e) {
            	System.out.println("Inavlid token");
                // Invalid token
            }
        }

        if (email == null) {
            // Redirect to login (your frontend login page or API)
            String loginRedirect = "d1sq67t1c2pewz.cloudfront.net/candidate" + URLEncoder.encode(request.getRequestURL().toString(), "UTF-8");
            response.sendRedirect(loginRedirect);
            return;
        }

        // Generate code and redirect back to Moodle
        String code = authCodeService.generateAuthCode(email);
        String redirect = redirect_uri + "?code=" + code;
        if (state != null) redirect += "&state=" + URLEncoder.encode(state, "UTF-8");

        response.sendRedirect(redirect);
    }

    // 2. Moodle calls this to exchange code for JWT
    @PostMapping("/token")
    public ResponseEntity<?> token(
            @RequestParam String grant_type,
            @RequestParam String code,
            @RequestParam String client_id,
            @RequestParam String redirect_uri
    ) {
        if (!"authorization_code".equals(grant_type)) {
            return ResponseEntity.badRequest().body("Unsupported grant_type");
        }

        String email = authCodeService.consumeAuthCode(code);
        if (email == null) {
            return ResponseEntity.badRequest().body("Invalid or expired code");
        }

        User user = new User(email, "", new ArrayList<>()); // No roles needed here
        String jwt = jwtUtil.generateToken(user);

        Map<String, Object> res = new HashMap<>();
        res.put("access_token", jwt);
        res.put("token_type", "Bearer");
        res.put("expires_in", 36000);

        return ResponseEntity.ok(res);
    }

    // 3. Moodle calls this to get user details
    @GetMapping("/userinfo")
    public ResponseEntity<?> userinfo(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String email;

        try {
            email = jwtUtil.extractUsername(token);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> user = new HashMap<>();
        user.put("email", email);
        user.put("preferred_username", email.split("@")[0]);
        user.put("name", email.split("@")[0]);

        return ResponseEntity.ok(user);
    }

    // 4. Moodle reads this config during setup
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<?> wellKnown(HttpServletRequest request) {
        String baseUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/oidc";

        Map<String, Object> config = new HashMap<>();
        config.put("issuer", baseUrl);
        config.put("authorization_endpoint", baseUrl + "/authorize");
        config.put("token_endpoint", baseUrl + "/token");
        config.put("userinfo_endpoint", baseUrl + "/userinfo");

        return ResponseEntity.ok(config);
    }

    private String extractJwtFromHeaderOrCookie(HttpServletRequest request) {
        // Check Authorization header
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }

        // Optional: Check cookies
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}