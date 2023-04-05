package cn.sakka.jwe.application.controller;

import cn.sakka.jwe.security.JweSecurityEntity;
import lombok.Data;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JWEController {

    @PostMapping("/jwe/json")
    public JweData jweJson(@RequestBody JweData encrypt) throws Exception {
        return encrypt;
    }

    @Data
    @JweSecurityEntity
    public static class JweData {
        private String p1;
        private int p2;
    }

}
