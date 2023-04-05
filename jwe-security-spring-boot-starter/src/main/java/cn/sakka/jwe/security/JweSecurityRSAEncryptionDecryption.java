package cn.sakka.jwe.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author sakka
 * @version 1.0
 * @description: jwe加解密器
 * @date 2023/3/30
 */
public class JweSecurityRSAEncryptionDecryption {

    public static String encrypt(byte[] payload, PublicKey publicKey) throws Exception {
        // 创建加密器
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        JWEEncrypter jweEncrypter = new RSAEncrypter((RSAPublicKey) publicKey);
        // 加密JSON数据
        Payload jwePayload = new Payload(payload);
        JWEObject jweObject = new JWEObject(header, jwePayload);
        jweObject.encrypt(jweEncrypter);
        // 将JWE对象转换为JWE字符串
        return jweObject.serialize();
    }

    public static byte[] decrypt(String jwe, PrivateKey privateKey) throws Exception {
        // 创建解密器
        JWEDecrypter jweDecrypter = new RSADecrypter(privateKey);
        // 解密JWE字符串
        JWEObject jweObject = JWEObject.parse(jwe);
        jweObject.decrypt(jweDecrypter);
        // 将解密后的JSON数据转换为JSONObject对象
        Payload payload = jweObject.getPayload();
        return payload.toBytes();
    }

}
