package cn.sakka.jwe.security;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.text.CharSequenceUtil;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.util.StreamUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.WebRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @author sakka
 * @version 1.0
 * @description: //TODO
 * @date 2023/3/30
 */
public class JweSecurityMappingJackson2HttpMessageConverter extends AbstractJackson2HttpMessageConverter {
    public static final String X_JWE_CLIENT = "X-JWE-CLIENT";
    /**
     * 配置文件
     */
    private final JweSecurityProperties jweSecurityProperties;
    /**
     * 客户端公钥
     */
    private final Map<String, PublicKey> clientPublicKeys;
    /**
     * 服务器私钥
     */
    private PrivateKey serverPrivateKey;


    public JweSecurityMappingJackson2HttpMessageConverter(JweSecurityProperties jweSecurityProperties) {
        this(jweSecurityProperties, Jackson2ObjectMapperBuilder.json().build());
    }

    public JweSecurityMappingJackson2HttpMessageConverter(JweSecurityProperties jweSecurityProperties, ObjectMapper objectMapper) {
        super(objectMapper, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
        this.jweSecurityProperties = jweSecurityProperties;
        clientPublicKeys = new HashMap<>();
        init();
    }

    private void init() {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(jweSecurityProperties.getServerPrivateKey()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            serverPrivateKey = keyFactory.generatePrivate(keySpec);
            for (JweSecurityProperties.ClientPublicKey clientPublicKey : jweSecurityProperties.getClientPublicKeys()) {
                String clientId = clientPublicKey.getClientId();
                PublicKey publicKey = getPublicKey(clientPublicKey.getClientKey());
                clientPublicKeys.put(clientId, publicKey);
            }
        } catch (Exception e) {
            throw new JweSecurityException(e);
        }
    }

    /**
     * String转公钥PublicKey
     *
     * @param key base64
     * @return 公钥
     * @throws Exception 异常
     */
    protected PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes = Base64.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }


    @Override
    public boolean canRead(Type type, Class<?> contextClass, MediaType mediaType) {
        return super.canRead(type, contextClass, mediaType) && isJweEntity(type, contextClass);
    }

    @Override
    public boolean canWrite(Type type, Class<?> contextClass, MediaType mediaType) {
        return super.canWrite(type, contextClass, mediaType) && isJweEntity(type, contextClass);
    }

    protected boolean isJweEntity(Type type, Class<?> contextClass) {
        JavaType javaType = getJavaType(type, contextClass);
        return javaType.getRawClass().getDeclaredAnnotation(JweSecurityEntity.class) != null;
    }

    @Override
    public Object read(Type type, Class<?> contextClass, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        HttpHeaders headers = inputMessage.getHeaders();
        String clientId = headers.getFirst(X_JWE_CLIENT);
        if (CharSequenceUtil.isNotEmpty(clientId)) {
            RequestContextHolder.currentRequestAttributes().setAttribute(X_JWE_CLIENT, clientId, WebRequest.SCOPE_REQUEST);
        }
        MediaType contentType = headers.getContentType();
        Charset charset = getCharset(contentType);
        InputStream inputStream = StreamUtils.nonClosing(inputMessage.getBody());
        String jwe = IoUtil.read(inputStream, charset);
        if (CharSequenceUtil.isEmpty(jwe)) {
            throw new HttpMessageNotReadableException("I/O error while reading input message", inputMessage);
        }
        try {
            byte[] decrypt = JweSecurityRSAEncryptionDecryption.decrypt(jwe, serverPrivateKey);
            return super.read(type, contextClass, new HttpInputMessage() {
                @Override
                public InputStream getBody() {
                    return new ByteArrayInputStream(decrypt);
                }

                @Override
                public HttpHeaders getHeaders() {
                    return headers;
                }
            });
        } catch (Exception e) {
            throw new JweSecurityException(e);
        }
    }

    @Override
    protected void writeInternal(Object object, Type type, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        //读取请求头
        String clientId = (String) RequestContextHolder.currentRequestAttributes().getAttribute(X_JWE_CLIENT, WebRequest.SCOPE_REQUEST);
        if (CharSequenceUtil.isNotEmpty(clientId)) {
            HttpHeaders headers = outputMessage.getHeaders();
            MediaType contentType = headers.getContentType();
            Charset charset = getCharset(contentType);
            PublicKey publicKey = clientPublicKeys.get(clientId);
            //如果公钥为空，直接抛出异常
            if (publicKey == null) {
                throw new JweSecurityException(CharSequenceUtil.format("Not found {} client publicKey"));
            }
            //找到对应的公钥，就加密数据并返回
            OutputStream outputStream = StreamUtils.nonClosing(outputMessage.getBody());
            try {
                String encrypt = JweSecurityRSAEncryptionDecryption.encrypt(getObjectMapper().writeValueAsString(object).getBytes(charset), publicKey);
                outputStream.write(encrypt.getBytes(charset));
            } catch (Exception e) {
                throw new JweSecurityException(e);
            }
        } else {
            //如果没有带上请求头，就走原来的路
            super.writeInternal(object, type, outputMessage);
        }
    }
}
