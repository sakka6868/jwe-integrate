package cn.sakka.jwe.application;

import cn.hutool.core.codec.Base64;
import cn.sakka.jwe.application.controller.JWEController;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;


public class JweRSAEncryptionDecryptionTest {

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

    public static void main(String[] args) throws Exception {
/*        // 创建一个JSON对象
        JSONObject payload = new JSONObject();
        payload.put("name", "Alice");
        payload.put("age", 30);
        String jsonString = payload.toJSONString();
        // 生成RSA密钥对*/

        // 生成RSA密钥对
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        System.out.println("Base64.encode(publicKey.getEncoded()) = " + Base64.encode(publicKey.getEncoded()));
//        System.out.println("Base64.encode(privateKey.getEncoded()) = " + Base64.encode(privateKey.getEncoded()));


/*        // 加密JSON对象
        String jwe = encrypt(jsonString, publicKey);
        System.out.println("JWE: " + jwe);
        // 解密JWE字符串
        String decryptedPayload = decrypt(jwe, privateKey);
        System.out.println("Decrypted payload: " + decryptedPayload);*/

        String publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqBTYOqBU5rdpdRX9/owxi0nHsxsyGr/8PWQZ8GtPQilXfNuQEFWO01o0ZU8Agn+wzatpGCOwIgSaEF4p6uI4tyhC8BlnkQZN/GcjbryljzIrRlu8NKsLu40SQO3CYa+p7DA36pdX/nMQ9QceSeGW9e7E5YWuiMhUDgqWVEdmRxX+bxfoNYpBtNlvyxeL0MKEIUVlikYKe+UxKhiPRcwjBIiHKfsY2PszP4h485UjcIWveyJjBu8nEpUgHUqUHdA1nm32WmUMcOhTU41tX6ZoYK6qUBeNX4xnfOG7jnE76Vz2QcsVTnnTqTQ/93nxEIrZsSfQ/vdzi8LryY2xS0EmQIDAQAB";
        PublicKey publicKey = getPublicKey(publicKeyStr);
        //playload 可以是json串，也可以是普通字符串
        JWEController.JweData jweData = new JWEController.JweData();

        String encrypt = encrypt("{\"p1\":\"hello server\",\"p2\":1}".getBytes(StandardCharsets.UTF_8), publicKey);
        System.out.println(encrypt);


//        String privateKeyBase64 = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCyoFNg6oFTmt2l1Ff3+jDGLScezGzIav/w9ZBnwa09CKVd825AQVY7TWjRlTwCCf7DNq2kYI7AiBJoQXinq4ji3KELwGWeRBk38ZyNuvKWPMitGW7w0qwu7jRJA7cJhr6nsMDfql1f+cxD1Bx5J4Zb17sTlha6IyFQOCpZUR2ZHFf5vF+g1ikG02W/LF4vQwoQhRWWKRgp75TEqGI9FzCMEiIcp+xjY+zM/iHjzlSNwha97ImMG7ycSlSAdSpQd0DWebfZaZQxw6FNTjW1fpmhgrqpQF41fjGd84buOcTvpXPZByxVOedOpND/3efEQitmxJ9D+93OLwuvJjbFLQSZAgMBAAECggEAJHg4XcazPeMWEufuR/pkX+nTHWYmZar283bnk0+HM7lirfJoFaVhWj09Q+EgvdfVlHzC6hcuvh9qBrArVqxeh9b86H3RIYWM0o+5Y3SCV+s0G6dgL7oLno9SzH9+LOs+XNVpI6FQbCp/qm+RmqjXtUOv9dlEbZ+DizHUb6TwkpRPMo3BHPUKGpajmP0pgSkQz8x4MWJ0a6SVST+/E7ZbwF8PobzOQCxND2yZQah/TY1EvCCyOM6chGm0loCyC4HGTBmDm/0LcWRqgiI8GiglEijGu2Iha6UR11JaEStHoc1Sy38Orj377bhndm2l19HNOQIslp9m0VP4WUSG3GJDKwKBgQC55+HY29F0H2jy7p94+snPCKVG0uJHu0IKhFN09fChP/1q0PLJuz3Vj07YUjGneSL3RHM1D+HbMYAGnZ+7GFmwIi8FLKBVZDx4L7ENhcPMUM2q0rsBphZuHfD14Hf9I0xUiNrpyTLuVPJfK3kzx2NYQmRGo6tY+INDuI5L2HEELwKBgQD1+c4ilEQtTRvoIa+BfZ/oOBeFaYsQGlLL+8yVbsPsfH+0MMoiIY++my5rDhT//8QXNhnOI1cs7CFKELA/99Mk7y9G/4o+cMb1kAyZJU6zNoSe9Eitdyo0qQQ20NVAW+YWX0zAuAm5bttk1RvVGz/wiuOotVw6oCSR0uUYUWCptwKBgB2psy6f/G6z6FIC4y0xjuva7Ew9r99UMLhu3sYly+xewne9uU+Y8cfWovT/QG8BdCPSJzPLQfVwk4X6tpbqzry855XCxh557PAcY/rNYi2Cox5jm3Uq5B9T5bPFyj9412ARqiRtdxPyN+4ZiLBLWz2k8k0XJmr+1CsFEqdldLr/AoGAEjyqLuAlSeKMriJJO+WPhI0cGVUg7Vm2R89sdKvYtODqKvbvFaa9XJlu0JsjrXNOG5Z0RVdTcE41jaM9HhEGw5dEPxRVMJn19mDuvjAI7LqfDJX6CXprU6owWMwU84ecwI3iR+udNPVmKMywGpXBoNj7VhfUNbiH3ZPwTmRCMXMCgYBi5I1KJ7kyaHKTilJEAhiYv6XBwsJScJkdAXWuA/SdG3aWQAEc4SOrRwqmqbHWYOm827tb20kG09rHnVS+tVSShvCkv4OcAr2X0L04IX9OfvUqI5pPWiQd/VzCQrTPcelixgkUkG4Sc2dRr6gvvFOKFAAVTQrePh9clk8kd3bg+g==";
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyBase64));
//        KeyFactory keyFactory;
//        keyFactory = KeyFactory.getInstance("RSA");
//        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

    }

    /**
     * String转公钥PublicKey
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

}
