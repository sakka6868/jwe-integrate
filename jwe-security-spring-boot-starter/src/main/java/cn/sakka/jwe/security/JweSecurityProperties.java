package cn.sakka.jwe.security;

import lombok.Data;

import java.util.List;

@Data
public class JweSecurityProperties {
    private boolean enabled;
    private String serverPrivateKey;
    private List<ClientPublicKey> clientPublicKeys;


    @Data
    public static class ClientPublicKey {
        private String clientId;
        private String clientKey;
    }

}
