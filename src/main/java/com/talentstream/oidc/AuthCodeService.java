package com.talentstream.oidc;


import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthCodeService {

    private final Map<String, String> codeStore = new ConcurrentHashMap<>();

    public String generateAuthCode(String email) {
        String code = UUID.randomUUID().toString();
        codeStore.put(code, email);
        return code;
    }

    public String consumeAuthCode(String code) {
        return codeStore.remove(code); // One-time use
    }
}
