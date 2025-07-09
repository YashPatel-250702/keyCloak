package com.talentstream.controller;

import com.talentstream.entity.GeminiRequest;
import com.talentstream.service.GeminiService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/gemini")
public class GeminiController {

    private static final Logger logger = LoggerFactory.getLogger(GeminiController.class);

    private final GeminiService geminiService;

    @Autowired
    public GeminiController(GeminiService geminiService) {
        this.geminiService = geminiService;
        logger.info("GeminiController initialized successfully");
    }

    @PostMapping("/chat")
    public ResponseEntity<String> chatWithGemini(@RequestBody GeminiRequest request) {
        logger.info("Received POST request at /api/gemini/chat");
        logger.debug("Request body: {}", request);

        try {
            ResponseEntity<String> response = geminiService.chatWithGemini(request);
            logger.info("Successfully processed request and received response");
            return response;
        } catch (Exception e) {
            logger.error("Exception occurred while processing /chat request: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error");
        }
    }
}
